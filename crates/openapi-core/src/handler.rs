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
use crate::routes::{classify, RouteAction};
use crate::upstream::{body_wants_stream, model_from_body};
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
    fn forward_v1(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&[u8]>,
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
        match classify(method.clone(), path) {
            RouteAction::Health => Ok(AppResponse::Json(serde_json::json!({
                "status": "ok",
                "region": self.config.region,
            }))),
            RouteAction::Attestation => self.handle_attestation(body),
            RouteAction::ModelsList => {
                let auth = self.authenticator.authenticate_bearer(authorization)?;
                self.enforce_rate_limit(&auth)?;
                let models = self.upstream.list_models()?;
                Ok(AppResponse::Json(serde_json::to_value(models).unwrap()))
            }
            RouteAction::InferencePost => {
                let auth = self.authenticator.authenticate_bearer(authorization)?;
                self.enforce_rate_limit(&auth)?;
                self.limits.validate_body_size(body.len())?;
                if path == "/v1/chat/completions" {
                    self.handle_chat_completions(auth, body, now_ms)
                } else {
                    self.handle_inference_post(auth, path, body, now_ms)
                }
            }
            RouteAction::ProxyGet | RouteAction::ProxyPost => {
                let auth = self.authenticator.authenticate_bearer(authorization)?;
                self.enforce_rate_limit(&auth)?;
                if !body.is_empty() {
                    self.limits.validate_body_size(body.len())?;
                }
                let upstream = self.upstream.forward_v1(
                    method,
                    path,
                    if body.is_empty() { None } else { Some(body) },
                )?;
                Ok(upstream_to_json_response(upstream))
            }
            RouteAction::NotImplemented(reason) => {
                let _ = self.authenticator.authenticate_bearer(authorization)?;
                Err(ApiError::NotImplemented(reason.into()))
            }
            RouteAction::MethodNotAllowed => Err(ApiError::MethodNotAllowed),
            RouteAction::NotFound => Err(ApiError::NotFound),
        }
    }

    fn enforce_rate_limit(&self, auth: &AuthContext) -> Result<(), ApiError> {
        self.rate_limiter.check(&auth.key_id)
    }

    fn handle_chat_completions(
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

        self.handle_inference_post(auth, "/v1/chat/completions", body, now_ms)
    }

    fn handle_inference_post(
        &self,
        auth: AuthContext,
        path: &str,
        body: &[u8],
        now_ms: u64,
    ) -> Result<AppResponse, ApiError> {
        let stream = body_wants_stream(body);
        let model = model_from_body(body);
        let upstream = self
            .upstream
            .forward_v1(HttpMethod::Post, path, Some(body))?;

        let (prompt_tokens, completion_tokens) = extract_token_counts(&upstream, stream);

        let usage = self.usage_signer.sign_report(
            &auth.key_id,
            &model,
            prompt_tokens,
            completion_tokens,
            now_ms,
        )?;

        inference_to_app_response(upstream, stream, usage)
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

fn upstream_to_json_response(upstream: UpstreamResponse) -> AppResponse {
    match upstream {
        UpstreamResponse::Json(body) => AppResponse::Json(body),
        UpstreamResponse::Raw { bytes, .. } => {
            match serde_json::from_slice::<Value>(&bytes) {
                Ok(body) => AppResponse::Json(body),
                Err(_) => AppResponse::Json(serde_json::json!({
                    "object": "binary",
                    "data": URL_SAFE_NO_PAD.encode(bytes),
                })),
            }
        }
    }
}

fn inference_to_app_response(
    upstream: UpstreamResponse,
    stream: bool,
    usage: UsageReport,
) -> Result<AppResponse, ApiError> {
    match upstream {
        UpstreamResponse::Json(body) if !stream => Ok(AppResponse::JsonWithUsage { body, usage }),
        UpstreamResponse::Json(body) if stream => Ok(AppResponse::SseStream {
            upstream_body: serde_json::to_vec(&body).unwrap(),
            usage,
        }),
        UpstreamResponse::Raw { bytes, content_type: _ } if stream => Ok(AppResponse::SseStream {
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

fn extract_token_counts(upstream: &UpstreamResponse, stream: bool) -> (u64, u64) {
    if stream {
        return (0, 0);
    }
    match upstream {
        UpstreamResponse::Json(v) => usage_from_json(v),
        UpstreamResponse::Raw { bytes, .. } => serde_json::from_slice::<Value>(bytes)
            .ok()
            .map(|v| usage_from_json(&v))
            .unwrap_or((0, 0)),
    }
}

fn usage_from_json(v: &Value) -> (u64, u64) {
    let usage = match v.get("usage") {
        Some(u) => u,
        None => return (0, 0),
    };
    let prompt = usage
        .get("prompt_tokens")
        .or_else(|| usage.get("input_tokens"))
        .and_then(|t| t.as_u64())
        .unwrap_or(0);
    let completion = usage
        .get("completion_tokens")
        .or_else(|| usage.get("output_tokens"))
        .and_then(|t| t.as_u64())
        .unwrap_or(0);
    (prompt, completion)
}

pub use openapi_platform::AttestationChallengeResponse as ChallengeResponse;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{hash_api_key, sign_test_catalog, KeyCatalog, KeyRecord};
    use ed25519_dalek::SigningKey;
    use openapi_platform::{
        AttestationChallengeResponse, EdgeIdentity, Measurement, PlatformError,
    };
    use rand::rngs::OsRng;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MockUpstream {
        responses: Mutex<HashMap<String, UpstreamResponse>>,
    }

    impl MockUpstream {
        fn with(self, path: &str, resp: UpstreamResponse) -> Self {
            self.responses
                .lock()
                .unwrap()
                .insert(path.to_string(), resp);
            self
        }
    }

    impl UpstreamForwarder for MockUpstream {
    fn forward_v1(
        &self,
        _method: HttpMethod,
        path: &str,
        _body: Option<&[u8]>,
    ) -> Result<UpstreamResponse, ApiError> {
        self.responses
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .ok_or(ApiError::Upstream("no mock".into()))
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

        App::new(
            Config::default(),
            Limits::default(),
            Authenticator::new(catalog),
            upstream,
            TestPlatform,
            UsageSigner::from_seed([1u8; 32]),
        )
    }

    const AUTH: &str = "Bearer sk-teechat-test";

    #[test]
    fn healthz_no_auth() {
        let app = build_test_app(MockUpstream::default());
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
        let app = build_test_app(MockUpstream::default());
        assert!(app
            .handle(HttpMethod::Post, "/v1/chat/completions", None, b"{}", 1)
            .is_err());
    }

    #[test]
    fn chat_completions_success_with_usage() {
        let app = build_test_app(
            MockUpstream::default().with(
                "/v1/chat/completions",
                UpstreamResponse::Json(serde_json::json!({
                    "id": "cmpl-1",
                    "choices": [{"message": {"role":"assistant","content":"hi"}}],
                    "usage": {"prompt_tokens": 3, "completion_tokens": 5}
                })),
            ),
        );
        let body = br#"{"model":"teechat-default","messages":[{"role":"user","content":"hi"}]}"#;
        let resp = app
            .handle(HttpMethod::Post, "/v1/chat/completions", Some(AUTH), body, 100)
            .unwrap();
        match resp {
            AppResponse::JsonWithUsage { body, usage } => {
                assert_eq!(body["id"], "cmpl-1");
                assert_eq!(usage.prompt_tokens, 3);
                assert_eq!(usage.completion_tokens, 5);
            }
            _ => panic!("expected json with usage"),
        }
    }

    #[test]
    fn embeddings_forwarded_with_usage() {
        let app = build_test_app(
            MockUpstream::default().with(
                "/v1/embeddings",
                UpstreamResponse::Json(serde_json::json!({
                    "object": "list",
                    "usage": {"prompt_tokens": 7, "total_tokens": 7}
                })),
            ),
        );
        let body = br#"{"model":"m","input":"hello"}"#;
        let resp = app
            .handle(HttpMethod::Post, "/v1/embeddings", Some(AUTH), body, 1)
            .unwrap();
        match resp {
            AppResponse::JsonWithUsage { usage, .. } => assert_eq!(usage.prompt_tokens, 7),
            _ => panic!("expected usage"),
        }
    }

    #[test]
    fn files_returns_not_implemented() {
        let app = build_test_app(MockUpstream::default());
        assert!(matches!(
            app.handle(HttpMethod::Post, "/v1/files", Some(AUTH), b"{}", 1),
            Err(ApiError::NotImplemented(_))
        ));
    }

    #[test]
    fn proxy_get_unknown_route() {
        let app = build_test_app(
            MockUpstream::default().with(
                "/v1/models/custom",
                UpstreamResponse::Json(serde_json::json!({"id": "custom"})),
            ),
        );
        let resp = app
            .handle(HttpMethod::Get, "/v1/models/custom", Some(AUTH), b"", 1)
            .unwrap();
        match resp {
            AppResponse::Json(v) => assert_eq!(v["id"], "custom"),
            _ => panic!("expected json"),
        }
    }

    #[test]
    fn attestation_challenge() {
        let app = build_test_app(MockUpstream::default());
        let nonce = URL_SAFE_NO_PAD.encode([0u8; 32]);
        let body = format!(r#"{{"nonce_b64":"{nonce}"}}"#).into_bytes();
        let resp = app
            .handle(HttpMethod::Post, "/v1/attestation/challenge", None, &body, 1)
            .unwrap();
        match resp {
            AppResponse::Json(v) => {
                assert_eq!(v["edge"]["build_version"], "0.1.0");
            }
            _ => panic!("expected json"),
        }
    }

    #[test]
    fn unknown_non_v1_404() {
        let app = build_test_app(MockUpstream::default());
        assert!(matches!(
            app.handle(HttpMethod::Get, "/v2/foo", Some(AUTH), b"", 1),
            Err(ApiError::NotFound)
        ));
    }
}
