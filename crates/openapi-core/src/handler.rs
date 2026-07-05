use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use openapi_platform::AttestationPlatform;
use rand::RngCore;
use serde_json::Value;

use crate::auth::{AuthContext, Authenticator};
use crate::config::Config;
use crate::error::ApiError;
use crate::limits::{Limits, RateLimiter};
use crate::models::{
    default_models, AttestationChallengeRequest, ChatCompletionRequest, ModelsListResponse,
};
use crate::usage::{UsageReport, UsageSigner};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Other,
}

impl HttpMethod {
    pub fn parse(method: &str) -> Self {
        match method {
            "GET" => Self::Get,
            "POST" => Self::Post,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone)]
pub enum AppResponse {
    Json(Value),
    JsonWithUsage {
        body: Value,
        usage: UsageReport,
    },
    SseStream {
        upstream_body: Vec<u8>,
        usage: UsageReport,
    },
}

pub trait UpstreamForwarder: Send + Sync {
    fn forward_chat(
        &self,
        request_json: &Value,
        stream: bool,
    ) -> Result<UpstreamResponse, ApiError>;

    fn list_models(&self) -> Result<ModelsListResponse, ApiError> {
        Ok(default_models())
    }
}

#[derive(Debug, Clone)]
pub enum UpstreamResponse {
    Json(Value),
    Raw { bytes: Vec<u8>, content_type: String },
}

pub struct App<U, P>
where
    U: UpstreamForwarder,
    P: AttestationPlatform,
{
    config: Config,
    limits: Limits,
    authenticator: Authenticator,
    upstream: U,
    platform: P,
    usage_signer: UsageSigner,
    rate_limiter: Arc<RateLimiter>,
}

impl<U, P> App<U, P>
where
    U: UpstreamForwarder,
    P: AttestationPlatform,
{
    pub fn new(
        config: Config,
        limits: Limits,
        authenticator: Authenticator,
        upstream: U,
        platform: P,
        usage_signer: UsageSigner,
    ) -> Self {
        let rate_limiter = limits.rate_limiter();
        Self {
            config,
            limits,
            authenticator,
            upstream,
            platform,
            usage_signer,
            rate_limiter,
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn handle(
        &self,
        method: HttpMethod,
        path: &str,
        authorization: Option<&str>,
        body: &[u8],
        now_ms: u64,
    ) -> Result<AppResponse, ApiError> {
        match (method, path) {
            (HttpMethod::Get, "/healthz") => Ok(AppResponse::Json(serde_json::json!({
                "status": "ok",
                "region": self.config.region,
            }))),
            (HttpMethod::Get, "/v1/models") => {
                let auth = self.authenticator.authenticate_bearer(authorization)?;
                self.enforce_rate_limit(&auth)?;
                let models = self.upstream.list_models()?;
                Ok(AppResponse::Json(serde_json::to_value(models).unwrap()))
            }
            (HttpMethod::Post, "/v1/chat/completions") => {
                let auth = self.authenticator.authenticate_bearer(authorization)?;
                self.enforce_rate_limit(&auth)?;
                self.limits.validate_body_size(body.len())?;
                self.handle_chat(auth, body, now_ms)
            }
            (HttpMethod::Post, "/v1/attestation/challenge") => {
                self.handle_attestation(body)
            }
            (_, "/v1/chat/completions" | "/v1/attestation/challenge") => {
                Err(ApiError::MethodNotAllowed)
            }
            (_, _) if path.starts_with("/v1/") => Err(ApiError::NotFound),
            (_, _) => Err(ApiError::NotFound),
        }
    }

    fn enforce_rate_limit(&self, auth: &AuthContext) -> Result<(), ApiError> {
        self.rate_limiter.check(&auth.key_id)
    }

    fn handle_chat(
        &self,
        auth: AuthContext,
        body: &[u8],
        now_ms: u64,
    ) -> Result<AppResponse, ApiError> {
        let req: ChatCompletionRequest = serde_json::from_slice(body)
            .map_err(|e| ApiError::BadRequest(format!("invalid chat request: {e}")))?;

        if req.messages.is_empty() {
            return Err(ApiError::BadRequest("messages must not be empty".into()));
        }

        let request_value: Value = serde_json::from_slice(body)
            .map_err(|e| ApiError::BadRequest(format!("invalid json: {e}")))?;

        let upstream = self
            .upstream
            .forward_chat(&request_value, req.stream)?;

        let (prompt_tokens, completion_tokens) = extract_token_counts(&upstream, req.stream);

        let usage = self.usage_signer.sign_report(
            &auth.key_id,
            &req.model,
            prompt_tokens,
            completion_tokens,
            now_ms,
        )?;

        match upstream {
            UpstreamResponse::Json(body) if !req.stream => Ok(AppResponse::JsonWithUsage {
                body,
                usage,
            }),
            UpstreamResponse::Json(body) if req.stream => {
                // Upstream returned JSON while client asked for stream — pass through as SSE-ish raw.
                Ok(AppResponse::SseStream {
                    upstream_body: serde_json::to_vec(&body).unwrap(),
                    usage,
                })
            }
            UpstreamResponse::Raw { bytes, content_type } if req.stream && content_type.contains("text/event-stream") => {
                Ok(AppResponse::SseStream {
                    upstream_body: bytes,
                    usage,
                })
            }
            UpstreamResponse::Raw { bytes, .. } if req.stream => Ok(AppResponse::SseStream {
                upstream_body: bytes,
                usage,
            }),
            UpstreamResponse::Json(body) => Ok(AppResponse::JsonWithUsage { body, usage }),
            UpstreamResponse::Raw { bytes, .. } => {
                let body: Value = serde_json::from_slice(&bytes)
                    .map_err(|e| ApiError::Upstream(format!("invalid upstream json: {e}")))?;
                Ok(AppResponse::JsonWithUsage { body, usage })
            }
        }
    }

    fn handle_attestation(&self, body: &[u8]) -> Result<AppResponse, ApiError> {
        self.limits.validate_body_size(body.len())?;
        let req: AttestationChallengeRequest = if body.is_empty() {
            AttestationChallengeRequest {
                nonce_b64: String::new(),
            }
        } else {
            serde_json::from_slice(body)
                .map_err(|e| ApiError::BadRequest(format!("invalid challenge request: {e}")))?
        };

        let nonce = if req.nonce_b64.is_empty() {
            let mut buf = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut buf);
            buf.to_vec()
        } else {
            URL_SAFE_NO_PAD
                .decode(&req.nonce_b64)
                .map_err(|e| ApiError::BadRequest(format!("invalid nonce: {e}")))?
        };

        if nonce.len() < 16 {
            return Err(ApiError::BadRequest("nonce must be at least 16 bytes".into()));
        }

        let attestation = self
            .platform
            .challenge(&nonce)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        Ok(AppResponse::Json(serde_json::to_value(attestation).unwrap()))
    }
}

fn extract_token_counts(upstream: &UpstreamResponse, stream: bool) -> (u64, u64) {
    if stream {
        return (0, 0);
    }
    match upstream {
        UpstreamResponse::Json(v) => {
            let usage = v.get("usage");
            let prompt = usage
                .and_then(|u| u.get("prompt_tokens"))
                .and_then(|t| t.as_u64())
                .unwrap_or(0);
            let completion = usage
                .and_then(|u| u.get("completion_tokens"))
                .and_then(|t| t.as_u64())
                .unwrap_or(0);
            (prompt, completion)
        }
        UpstreamResponse::Raw { bytes, .. } => serde_json::from_slice::<Value>(bytes)
            .ok()
            .and_then(|v| {
                let usage = v.get("usage")?;
                Some((
                    usage.get("prompt_tokens")?.as_u64()?,
                    usage.get("completion_tokens")?.as_u64()?,
                ))
            })
            .unwrap_or((0, 0)),
    }
}

pub use openapi_platform::AttestationChallengeResponse as ChallengeResponse;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{hash_api_key, sign_test_catalog, KeyCatalog, KeyRecord};
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use openapi_platform::{
        AttestationChallengeResponse, EdgeIdentity, Measurement, PlatformError, UsageSigningKey,
    };
    use rand::rngs::OsRng;

    struct MockUpstream {
        response: UpstreamResponse,
    }

    impl UpstreamForwarder for MockUpstream {
        fn forward_chat(
            &self,
            _request_json: &Value,
            _stream: bool,
        ) -> Result<UpstreamResponse, ApiError> {
            Ok(self.response.clone())
        }
    }

    struct TestPlatform;

    impl AttestationPlatform for TestPlatform {
        fn identity(&self) -> &EdgeIdentity {
            panic!("not used in tests")
        }

        fn challenge(&self, nonce: &[u8]) -> Result<AttestationChallengeResponse, PlatformError> {
            Ok(AttestationChallengeResponse {
                edge: EdgeIdentity {
                    build_version: "0.1.0".into(),
                    code_hash: "abc".into(),
                    measurement: Measurement::LaunchDigest {
                        launch_digest: "ld".into(),
                        image_digest: "id".into(),
                    },
                    tls_cert_spki_sha256: "spki".into(),
                },
                challenge_nonce_b64: URL_SAFE_NO_PAD.encode(nonce),
                quote_b64: None,
            })
        }
    }

    fn build_test_app(upstream: MockUpstream) -> App<MockUpstream, TestPlatform> {
        let api_key = "sk-teechat-test";
        let mut csprng = OsRng;
        let catalog_signing = SigningKey::generate(&mut csprng);
        let catalog_verify = catalog_signing.verifying_key();
        let record = KeyRecord {
            key_id: "k-test".into(),
            key_hash_hex: hash_api_key(api_key),
            revoked: false,
        };
        let signed = sign_test_catalog(vec![record], &catalog_signing);
        let catalog = KeyCatalog::from_signed(signed, catalog_verify).unwrap();
        let usage_signer = UsageSigner::from_seed([1u8; 32]);

        App::new(
            Config::default(),
            Limits::default(),
            Authenticator::new(catalog),
            upstream,
            TestPlatform,
            usage_signer,
        )
    }

    const AUTH: &str = "Bearer sk-teechat-test";

    #[test]
    fn healthz_no_auth() {
        let app = build_test_app(MockUpstream {
            response: UpstreamResponse::Json(serde_json::json!({})),
        });
        let resp = app
            .handle(HttpMethod::Get, "/healthz", None, b"", 1)
            .unwrap();
        match resp {
            AppResponse::Json(v) => assert_eq!(v["status"], "ok"),
            _ => panic!("expected json"),
        }
    }

    #[test]
    fn chat_completions_requires_auth() {
        let app = build_test_app(MockUpstream {
            response: UpstreamResponse::Json(serde_json::json!({
                "choices": [],
                "usage": {"prompt_tokens": 3, "completion_tokens": 5}
            })),
        });
        assert!(app
            .handle(HttpMethod::Post, "/v1/chat/completions", None, b"{}", 1)
            .is_err());
    }

    #[test]
    fn chat_completions_success_with_usage() {
        let app = build_test_app(MockUpstream {
            response: UpstreamResponse::Json(serde_json::json!({
                "id": "cmpl-1",
                "choices": [{"message": {"role":"assistant","content":"hi"}}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 5}
            })),
        });
        let body = br#"{"model":"teechat-default","messages":[{"role":"user","content":"hi"}]}"#;
        let resp = app
            .handle(HttpMethod::Post, "/v1/chat/completions", Some(AUTH), body, 100)
            .unwrap();
        match resp {
            AppResponse::JsonWithUsage { body, usage } => {
                assert_eq!(body["id"], "cmpl-1");
                assert_eq!(usage.prompt_tokens, 3);
                assert_eq!(usage.completion_tokens, 5);
                assert_eq!(usage.key_id, "k-test");
                let vk = VerifyingKey::from_bytes(&app.usage_signer.public_key_bytes()).unwrap();
                UsageSigner::verify_report(&usage, &vk).unwrap();
            }
            _ => panic!("expected json with usage"),
        }
    }

    #[test]
    fn attestation_challenge() {
        let app = build_test_app(MockUpstream {
            response: UpstreamResponse::Json(serde_json::json!({})),
        });
        let nonce = URL_SAFE_NO_PAD.encode([0u8; 32]);
        let body = format!(r#"{{"nonce_b64":"{nonce}"}}"#).into_bytes();
        let resp = app
            .handle(HttpMethod::Post, "/v1/attestation/challenge", None, &body, 1)
            .unwrap();
        match resp {
            AppResponse::Json(v) => {
                assert_eq!(v["edge"]["build_version"], "0.1.0");
                assert!(v.get("challenge_nonce_b64").is_some());
            }
            _ => panic!("expected json"),
        }
    }

    #[test]
    fn unknown_route_404() {
        let app = build_test_app(MockUpstream {
            response: UpstreamResponse::Json(serde_json::json!({})),
        });
        assert!(matches!(
            app.handle(HttpMethod::Get, "/v1/unknown", Some(AUTH), b"", 1),
            Err(ApiError::NotFound)
        ));
    }
}
