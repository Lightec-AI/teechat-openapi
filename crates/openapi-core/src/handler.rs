use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use openapi_platform::AttestationPlatform;
use serde_json::Value;

use crate::auth::AuthContext;
use crate::remote_auth::EdgeAuthenticator;
use crate::config::Config;
use crate::error::ApiError;
use crate::limits::{InflightGate, IpConnPermit, IpConnTracker, Limits, RateLimiter};
use crate::models::{
    AttestationChallengeRequest, ChatCompletionRequest, ModelsListResponse,
};
use crate::quota::enforce_token_quota;
use crate::routes::{classify, normalize_path, RouteAction};
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
    /// Buffered SSE (non-streaming upstream fallback / tests).
    SseStream {
        upstream_body: Vec<u8>,
        usage: UsageReport,
    },
    /// Incremental SSE passthrough: HTTP layer pipes upstream body to the client,
    /// accumulates SSE `usage`, then signs the final report (METER-001).
    SsePassthrough {
        method: HttpMethod,
        path: String,
        body: Vec<u8>,
        key_id: String,
        key_set: String,
        model: String,
        now_ms: u64,
    },
}

pub trait UpstreamForwarder: Send + Sync {
    fn forward_v1(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<UpstreamResponse, ApiError>;

    /// Context-aware forward (key_id / key_set for OPE dispatch + metering).
    fn forward_v1_ctx(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&[u8]>,
        _ctx: &UpstreamRequestContext,
    ) -> Result<UpstreamResponse, ApiError> {
        self.forward_v1(method, path, body)
    }

    /// Stream upstream response body to `out` on HTTP 2xx. Non-2xx responses are
    /// read fully and returned as `ApiError::Upstream` without writing to `out`.
    fn forward_v1_stream(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&[u8]>,
        out: &mut dyn std::io::Write,
    ) -> Result<StreamForwardResult, ApiError> {
        let resp = self.forward_v1(method, path, body)?;
        let (bytes, content_type) = match resp {
            UpstreamResponse::Json(v) => (
                serde_json::to_vec(&v).map_err(|e| ApiError::Internal(e.to_string()))?,
                "application/json".into(),
            ),
            UpstreamResponse::Raw { bytes, content_type } => (bytes, content_type),
        };
        out.write_all(&bytes)
            .map_err(|e| ApiError::Upstream(e.to_string()))?;
        Ok(StreamForwardResult {
            status: 200,
            content_type,
            bytes_written: bytes.len() as u64,
        })
    }

    fn forward_v1_stream_ctx(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&[u8]>,
        _ctx: &UpstreamRequestContext,
        out: &mut dyn std::io::Write,
    ) -> Result<StreamForwardResult, ApiError> {
        self.forward_v1_stream(method, path, body, out)
    }

    fn list_models(&self) -> Result<ModelsListResponse, ApiError> {
        match self.forward_v1(HttpMethod::Get, "/v1/models", None)? {
            UpstreamResponse::Json(v) => crate::models::parse_models_json(v),
            UpstreamResponse::Raw { bytes, .. } => crate::models::parse_models_bytes(&bytes),
        }
    }

    fn list_models_for_key(
        &self,
        _ctx: &UpstreamRequestContext,
        policy: &crate::authz::OpenApiKeyPolicy,
    ) -> Result<ModelsListResponse, ApiError> {
        let mut models = self.list_models()?;
        models.data.retain(|m| policy.allows_model(&m.id));
        Ok(models)
    }
}

/// Per-request identity for OPE upstream (METER-002 + key_set matrix).
#[derive(Debug, Clone)]
pub struct UpstreamRequestContext {
    pub key_id: String,
    pub key_set: String,
}

impl Default for UpstreamRequestContext {
    fn default() -> Self {
        Self {
            key_id: String::new(),
            key_set: "api".into(),
        }
    }
}

impl UpstreamRequestContext {
    pub fn from_auth(key_id: &str, key_set: &str) -> Self {
        Self {
            key_id: key_id.to_string(),
            key_set: if key_set.trim().is_empty() {
                "api".into()
            } else {
                key_set.trim().to_string()
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamForwardResult {
    pub status: u16,
    pub content_type: String,
    pub bytes_written: u64,
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
    authenticator: EdgeAuthenticator,
    upstream: U,
    platform: P,
    usage_signer: UsageSigner,
    rate_limiter: Arc<RateLimiter>,
    challenge_rate_limiter: Arc<RateLimiter>,
    challenge_inflight: Arc<InflightGate>,
    ip_conn_tracker: Arc<IpConnTracker>,
    ip_rate_limiter: Arc<RateLimiter>,
}

impl<U, P> App<U, P>
where
    U: UpstreamForwarder,
    P: AttestationPlatform,
{
    pub fn new(
        config: Config,
        limits: Limits,
        authenticator: EdgeAuthenticator,
        upstream: U,
        platform: P,
        usage_signer: UsageSigner,
    ) -> Self {
        let rate_limiter = limits.rate_limiter();
        let challenge_rate_limiter = limits.challenge_rate_limiter();
        let challenge_inflight = limits.challenge_inflight_gate();
        let ip_conn_tracker = limits.ip_conn_tracker();
        let ip_rate_limiter = limits.ip_rate_limiter();
        Self {
            config,
            limits,
            authenticator,
            upstream,
            platform,
            usage_signer,
            rate_limiter,
            challenge_rate_limiter,
            challenge_inflight,
            ip_conn_tracker,
            ip_rate_limiter,
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Acquire a per-IP connection slot for the TCP/TLS session lifetime.
    pub fn try_acquire_ip_conn(&self, client_ip: Option<&str>) -> Result<IpConnPermit<'_>, ApiError> {
        self.ip_conn_tracker
            .try_acquire(client_ip.unwrap_or("unknown"))
    }

    pub fn handle(
        &self,
        method: HttpMethod,
        path: &str,
        authorization: Option<&str>,
        body: &[u8],
        now_ms: u64,
    ) -> Result<AppResponse, ApiError> {
        self.handle_from(method, path, authorization, body, now_ms, None)
    }

    /// Like [`Self::handle`], with optional client IP for public challenge rate limits.
    pub fn handle_from(
        &self,
        method: HttpMethod,
        path: &str,
        authorization: Option<&str>,
        body: &[u8],
        now_ms: u64,
        client_ip: Option<&str>,
    ) -> Result<AppResponse, ApiError> {
        self.handle_from_ex(method, path, authorization, body, now_ms, client_ip, None)
    }

    /// Full request context including optional challenge bench bypass token.
    pub fn handle_from_ex(
        &self,
        method: HttpMethod,
        path: &str,
        authorization: Option<&str>,
        body: &[u8],
        now_ms: u64,
        client_ip: Option<&str>,
        challenge_bench_header: Option<&str>,
    ) -> Result<AppResponse, ApiError> {
        let path = match normalize_path(path) {
            Ok(p) => p,
            Err(RouteAction::NotFound) => return Err(ApiError::NotFound),
            Err(_) => return Err(ApiError::NotFound),
        };
        match classify(method.clone(), &path, self.config.proxy_mode) {
            RouteAction::Health => Ok(AppResponse::Json(serde_json::json!({
                "status": "ok",
                "region": self.config.region,
            }))),
            RouteAction::Attestation => {
                self.handle_attestation(body, client_ip, challenge_bench_header)
            }
            RouteAction::ModelsList => {
                self.enforce_ip_api_limit(client_ip)?;
                let auth = self.authenticator.authenticate_bearer(authorization)?;
                self.enforce_rate_limit(&auth)?;
                let ctx = UpstreamRequestContext::from_auth(&auth.key_id, &auth.policy.key_set);
                let models = self.upstream.list_models_for_key(&ctx, &auth.policy)?;
                Ok(AppResponse::Json(serde_json::to_value(models).unwrap()))
            }
            RouteAction::InferencePost => {
                self.enforce_ip_api_limit(client_ip)?;
                let auth = self.authenticator.authenticate_bearer(authorization)?;
                self.enforce_rate_limit(&auth)?;
                self.limits.validate_body_size(body.len())?;
                self.enforce_model_policy(&auth, body)?;
                enforce_token_quota(&auth.policy, body)?;
                if path == "/v1/chat/completions" {
                    self.handle_chat_completions(auth, body, now_ms)
                } else {
                    self.handle_inference_post(auth, &path, body, now_ms)
                }
            }
            RouteAction::ProxyGet | RouteAction::ProxyPost => {
                self.enforce_ip_api_limit(client_ip)?;
                let auth = self.authenticator.authenticate_bearer(authorization)?;
                self.enforce_rate_limit(&auth)?;
                if !body.is_empty() {
                    self.limits.validate_body_size(body.len())?;
                }
                if method == HttpMethod::Post && !body.is_empty() {
                    self.enforce_model_policy(&auth, body)?;
                    enforce_token_quota(&auth.policy, body)?;
                }
                let ctx = UpstreamRequestContext::from_auth(&auth.key_id, &auth.policy.key_set);
                if method == HttpMethod::Post && body_wants_stream(body) {
                    let model = model_from_body(body);
                    return Ok(AppResponse::SsePassthrough {
                        method,
                        path: path.clone(),
                        body: body.to_vec(),
                        key_id: auth.key_id.clone(),
                        key_set: auth.policy.key_set.clone(),
                        model,
                        now_ms,
                    });
                }
                let upstream = self.upstream.forward_v1_ctx(
                    method,
                    &path,
                    if body.is_empty() { None } else { Some(body) },
                    &ctx,
                )?;
                Ok(upstream_to_json_response(upstream))
            }
            RouteAction::NotImplemented(reason) => {
                self.enforce_ip_api_limit(client_ip)?;
                let _ = self.authenticator.authenticate_bearer(authorization)?;
                Err(ApiError::NotImplemented(reason.into()))
            }
            RouteAction::MethodNotAllowed => Err(ApiError::MethodNotAllowed),
            RouteAction::NotFound => Err(ApiError::NotFound),
        }
    }

    fn enforce_rate_limit(&self, auth: &AuthContext) -> Result<(), ApiError> {
        let rpm = auth
            .policy
            .effective_rpm(self.limits.requests_per_minute);
        self.rate_limiter.check_with_rpm(&auth.key_id, rpm)
    }

    fn enforce_ip_api_limit(&self, client_ip: Option<&str>) -> Result<(), ApiError> {
        let rpm = self.limits.ip_requests_per_minute;
        if rpm == 0 {
            return Ok(());
        }
        let ip = client_ip.unwrap_or("unknown");
        self.ip_rate_limiter.check_with_rpm(ip, rpm)
    }

    fn enforce_model_policy(&self, auth: &AuthContext, body: &[u8]) -> Result<(), ApiError> {
        let model = model_from_body(body);
        if auth.policy.allows_model(&model) {
            return Ok(());
        }
        Err(ApiError::Forbidden(format!(
            "model `{model}` is not allowed for this API key"
        )))
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
        let ctx = UpstreamRequestContext::from_auth(&auth.key_id, &auth.policy.key_set);

        if stream {
            return Ok(AppResponse::SsePassthrough {
                method: HttpMethod::Post,
                path: path.to_string(),
                body: body.to_vec(),
                key_id: auth.key_id.clone(),
                key_set: auth.policy.key_set.clone(),
                model,
                now_ms,
            });
        }

        let upstream = self
            .upstream
            .forward_v1_ctx(HttpMethod::Post, path, Some(body), &ctx)?;

        let (prompt_tokens, completion_tokens) = extract_token_counts(&upstream, false);

        let usage = self.usage_signer.sign_report(
            &auth.key_id,
            &model,
            prompt_tokens,
            completion_tokens,
            now_ms,
        )?;

        inference_to_app_response(upstream, false, usage)
    }

    /// Pipe a prepared SSE passthrough request to the client writer.
    pub fn execute_sse_passthrough(
        &self,
        method: HttpMethod,
        path: &str,
        body: &[u8],
        out: &mut dyn std::io::Write,
    ) -> Result<StreamForwardResult, ApiError> {
        // key_set defaults to api when SSE path does not re-auth; METER-002 key_id is in AppResponse.
        let ctx = UpstreamRequestContext {
            key_id: String::new(),
            key_set: "api".into(),
        };
        self.upstream
            .forward_v1_stream_ctx(method, path, Some(body), &ctx, out)
    }

    /// SSE passthrough with explicit auth context (preferred for OPE cutover).
    pub fn execute_sse_passthrough_ctx(
        &self,
        method: HttpMethod,
        path: &str,
        body: &[u8],
        ctx: &UpstreamRequestContext,
        out: &mut dyn std::io::Write,
    ) -> Result<StreamForwardResult, ApiError> {
        self.upstream
            .forward_v1_stream_ctx(method, path, Some(body), ctx, out)
    }

    /// Sign a usage report after SSE accumulation (METER-001).
    pub fn sign_stream_usage(
        &self,
        key_id: &str,
        model: &str,
        prompt_tokens: u64,
        completion_tokens: u64,
        now_ms: u64,
    ) -> Result<UsageReport, ApiError> {
        self.usage_signer.sign_report(
            key_id,
            model,
            prompt_tokens,
            completion_tokens,
            now_ms,
        )
    }

    fn handle_attestation(
        &self,
        body: &[u8],
        client_ip: Option<&str>,
        challenge_bench_header: Option<&str>,
    ) -> Result<AppResponse, ApiError> {
        use openapi_platform::CHALLENGE_NONCE_LEN;

        // BENCH-001: never honor bench bypass when OPENAPI_PROFILE=prod (defense in depth;
        // load-time validate_tls_key_policy already refuses the env on prod units).
        let bench_bypass = if openapi_platform::load_edge_profile().is_prod() {
            false
        } else {
            match (
                self.limits.challenge_bench_token.as_deref(),
                challenge_bench_header,
            ) {
                (Some(expected), Some(got))
                    if !expected.is_empty()
                        && subtle_constant_time_eq(expected.as_bytes(), got.as_bytes()) =>
                {
                    true
                }
                _ => false,
            }
        };

        let _inflight = if bench_bypass {
            None
        } else {
            let ip_key = client_ip
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("unknown");
            self.challenge_rate_limiter.check(ip_key)?;
            Some(self.challenge_inflight.try_acquire()?)
        };

        self.limits.validate_body_size(body.len())?;
        if body.is_empty() {
            return Err(ApiError::BadRequest(
                "attestation challenge requires JSON body with nonce_b64".into(),
            ));
        }
        let req: AttestationChallengeRequest = serde_json::from_slice(body)
            .map_err(|e| ApiError::BadRequest(format!("invalid challenge request: {e}")))?;

        let nonce = URL_SAFE_NO_PAD
            .decode(req.nonce_b64.trim())
            .map_err(|e| ApiError::BadRequest(format!("invalid nonce_b64: {e}")))?;
        if nonce.len() != CHALLENGE_NONCE_LEN {
            return Err(ApiError::BadRequest(format!(
                "nonce must be exactly {CHALLENGE_NONCE_LEN} bytes"
            )));
        }

        let attestation = self
            .platform
            .challenge(&nonce)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        Ok(AppResponse::Json(serde_json::to_value(attestation).unwrap()))
    }
}

fn subtle_constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
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
    use crate::auth::Authenticator;
    use crate::catalog::{hash_api_key, sign_test_catalog, KeyCatalog, KeyRecord};
    use ed25519_dalek::SigningKey;
    use openapi_platform::{
        AttestationChallengeResponse, EdgeIdentity, Measurement, PlatformError, QuoteFormat,
        REPORT_DATA_LEN, SNP_REPORT_DATA_OFFSET,
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
            fn hex32(b: u8) -> String {
                hex::encode([b; 32])
            }
            let edge = EdgeIdentity {
                build_version: "0.1.0".into(),
                code_hash: hex32(0x11),
                measurement: Measurement::LaunchDigest {
                    launch_digest: hex32(0xcc),
                    image_digest: hex32(0xdd),
                },
                tls_cert_spki_sha256: hex32(0xbb),
            };
            let rd = openapi_platform::build_report_data_v1(nonce, &edge)?;
            let mut report = vec![0u8; SNP_REPORT_DATA_OFFSET + REPORT_DATA_LEN];
            report[SNP_REPORT_DATA_OFFSET..SNP_REPORT_DATA_OFFSET + 64].copy_from_slice(&rd);
            AttestationChallengeResponse::new(edge, nonce, QuoteFormat::SnpReport, &report)
                .map_err(Into::into)
        }
    }

    fn build_test_app<U: UpstreamForwarder>(upstream: U) -> App<U, TestPlatform> {
        build_test_app_with_config(Config::default(), upstream)
    }

    fn build_test_app_with_config<U: UpstreamForwarder>(
        config: Config,
        upstream: U,
    ) -> App<U, TestPlatform> {
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
            config,
            Limits::default(),
            EdgeAuthenticator::from_catalog(Authenticator::new(catalog)),
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
    fn allowlist_rejects_unknown_get_by_default() {
        let app = build_test_app(MockUpstream::default());
        assert!(matches!(
            app.handle(HttpMethod::Get, "/v1/models/custom", Some(AUTH), b"", 1),
            Err(ApiError::NotFound)
        ));
    }

    #[test]
    fn transparent_proxy_get_unknown_route() {
        let mut cfg = Config::default();
        cfg.proxy_mode = crate::routes::ProxyMode::Transparent;
        let app = build_test_app_with_config(
            cfg,
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
    fn chat_completions_with_query_still_inference() {
        let app = build_test_app(
            MockUpstream::default().with(
                "/v1/chat/completions",
                UpstreamResponse::Json(serde_json::json!({
                    "id": "cmpl-q",
                    "choices": [{"message": {"role":"assistant","content":"hi"}}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1}
                })),
            ),
        );
        let body = br#"{"model":"teechat-default","messages":[{"role":"user","content":"hi"}]}"#;
        let resp = app
            .handle(
                HttpMethod::Post,
                "/v1/chat/completions?foo=1",
                Some(AUTH),
                body,
                100,
            )
            .unwrap();
        assert!(matches!(resp, AppResponse::JsonWithUsage { .. }));
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
                assert_eq!(v["schema_version"], 1);
                assert_eq!(v["report_data_version"], 1);
                assert_eq!(v["quote_format"], "snp_report");
                assert!(v["quote_b64"].as_str().unwrap().len() > 8);
            }
            _ => panic!("expected json"),
        }
    }

    #[test]
    fn attestation_rejects_short_nonce() {
        let app = build_test_app(MockUpstream::default());
        let nonce = URL_SAFE_NO_PAD.encode([0u8; 16]);
        let body = format!(r#"{{"nonce_b64":"{nonce}"}}"#).into_bytes();
        let err = app
            .handle(HttpMethod::Post, "/v1/attestation/challenge", None, &body, 1)
            .unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn attestation_rejects_empty_body() {
        let app = build_test_app(MockUpstream::default());
        let err = app
            .handle(HttpMethod::Post, "/v1/attestation/challenge", None, b"", 1)
            .unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn attestation_challenge_rate_limited_per_ip() {
        let mut limits = Limits::default();
        limits.challenge_requests_per_minute = 2;
        let api_key = "sk-teechat-test";
        let catalog_signing = SigningKey::from_bytes(&[7u8; 32]);
        let signed = sign_test_catalog(
            vec![KeyRecord {
                key_id: "k".into(),
                key_hash_hex: hash_api_key(api_key),
                revoked: false,
            }],
            &catalog_signing,
        );
        let catalog = KeyCatalog::from_signed(signed, catalog_signing.verifying_key()).unwrap();
        let app = App::new(
            Config::default(),
            limits,
            EdgeAuthenticator::from_catalog(Authenticator::new(catalog)),
            MockUpstream::default(),
            TestPlatform,
            UsageSigner::from_seed([9u8; 32]),
        );
        let nonce = URL_SAFE_NO_PAD.encode([1u8; 32]);
        let body = format!(r#"{{"nonce_b64":"{nonce}"}}"#).into_bytes();
        app.handle_from(
            HttpMethod::Post,
            "/v1/attestation/challenge",
            None,
            &body,
            1,
            Some("203.0.113.10"),
        )
        .unwrap();
        app.handle_from(
            HttpMethod::Post,
            "/v1/attestation/challenge",
            None,
            &body,
            2,
            Some("203.0.113.10"),
        )
        .unwrap();
        let err = app
            .handle_from(
                HttpMethod::Post,
                "/v1/attestation/challenge",
                None,
                &body,
                3,
                Some("203.0.113.10"),
            )
            .unwrap_err();
        assert!(matches!(err, ApiError::RateLimited));
        app.handle_from(
            HttpMethod::Post,
            "/v1/attestation/challenge",
            None,
            &body,
            4,
            Some("203.0.113.11"),
        )
        .unwrap();
    }

    /// Serialize tests that mutate `OPENAPI_PROFILE` (process-global).
    static PROFILE_ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn challenge_bench_token_bypasses_limits_in_dev() {
        let _g = PROFILE_ENV_LOCK.lock().unwrap();
        std::env::remove_var("OPENAPI_PROFILE");
        let mut limits = Limits::default();
        limits.challenge_requests_per_minute = 1;
        limits.challenge_bench_token = Some("lab-token".into());
        let app = App::new(
            Config::default(),
            limits,
            EdgeAuthenticator::from_catalog(Authenticator::new({
                let sk = SigningKey::from_bytes(&[7u8; 32]);
                KeyCatalog::from_signed(sign_test_catalog(vec![], &sk), sk.verifying_key()).unwrap()
            })),
            MockUpstream::default(),
            TestPlatform,
            UsageSigner::from_seed([9u8; 32]),
        );
        let nonce = URL_SAFE_NO_PAD.encode([2u8; 32]);
        let body = format!(r#"{{"nonce_b64":"{nonce}"}}"#).into_bytes();
        for i in 0..3 {
            app.handle_from_ex(
                HttpMethod::Post,
                "/v1/attestation/challenge",
                None,
                &body,
                i,
                Some("198.51.100.50"),
                Some("lab-token"),
            )
            .unwrap();
        }
    }

    #[test]
    fn challenge_bench_token_ignored_when_profile_prod() {
        let _g = PROFILE_ENV_LOCK.lock().unwrap();
        std::env::set_var("OPENAPI_PROFILE", "prod");
        let mut limits = Limits::default();
        limits.challenge_requests_per_minute = 1;
        limits.challenge_bench_token = Some("lab-token".into());
        let app = App::new(
            Config::default(),
            limits,
            EdgeAuthenticator::from_catalog(Authenticator::new({
                let sk = SigningKey::from_bytes(&[7u8; 32]);
                KeyCatalog::from_signed(sign_test_catalog(vec![], &sk), sk.verifying_key()).unwrap()
            })),
            MockUpstream::default(),
            TestPlatform,
            UsageSigner::from_seed([9u8; 32]),
        );
        let nonce = URL_SAFE_NO_PAD.encode([3u8; 32]);
        let body = format!(r#"{{"nonce_b64":"{nonce}"}}"#).into_bytes();
        app.handle_from_ex(
            HttpMethod::Post,
            "/v1/attestation/challenge",
            None,
            &body,
            1,
            Some("198.51.100.51"),
            Some("lab-token"),
        )
        .unwrap();
        let err = app
            .handle_from_ex(
                HttpMethod::Post,
                "/v1/attestation/challenge",
                None,
                &body,
                2,
                Some("198.51.100.51"),
                Some("lab-token"),
            )
            .unwrap_err();
        std::env::remove_var("OPENAPI_PROFILE");
        assert!(matches!(err, ApiError::RateLimited));
    }

    #[test]
    fn chat_completions_stream_returns_passthrough() {
        let app = build_test_app(MockUpstream::default());
        let body = br#"{"model":"m","messages":[{"role":"user","content":"hi"}],"stream":true}"#;
        let resp = app
            .handle(HttpMethod::Post, "/v1/chat/completions", Some(AUTH), body, 1)
            .unwrap();
        match resp {
            AppResponse::SsePassthrough {
                path,
                body,
                key_id,
                model,
                ..
            } => {
                assert_eq!(path, "/v1/chat/completions");
                assert!(body_wants_stream(&body));
                assert_eq!(key_id, "k-test");
                assert_eq!(model, "m");
            }
            _ => panic!("expected sse passthrough"),
        }
    }

    #[test]
    fn api_rate_limited_per_ip_before_key_rpm() {
        let mut limits = Limits::default();
        limits.ip_requests_per_minute = 2;
        limits.requests_per_minute = 1000;
        let api_key = "sk-teechat-test";
        let catalog_signing = SigningKey::from_bytes(&[7u8; 32]);
        let signed = sign_test_catalog(
            vec![KeyRecord {
                key_id: "k".into(),
                key_hash_hex: hash_api_key(api_key),
                revoked: false,
            }],
            &catalog_signing,
        );
        let catalog = KeyCatalog::from_signed(signed, catalog_signing.verifying_key()).unwrap();
        let auth = format!("Bearer {api_key}");
        let upstream = MockUpstream::default().with(
            "/v1/models",
            UpstreamResponse::Json(serde_json::json!({
                "object": "list",
                "data": []
            })),
        );
        let app = App::new(
            Config::default(),
            limits,
            EdgeAuthenticator::from_catalog(Authenticator::new(catalog)),
            upstream,
            TestPlatform,
            UsageSigner::from_seed([9u8; 32]),
        );
        app.handle_from(
            HttpMethod::Get,
            "/v1/models",
            Some(&auth),
            b"",
            1,
            Some("198.51.100.7"),
        )
        .unwrap();
        app.handle_from(
            HttpMethod::Get,
            "/v1/models",
            Some(&auth),
            b"",
            2,
            Some("198.51.100.7"),
        )
        .unwrap();
        let err = app
            .handle_from(
                HttpMethod::Get,
                "/v1/models",
                Some(&auth),
                b"",
                3,
                Some("198.51.100.7"),
            )
            .unwrap_err();
        assert!(matches!(err, ApiError::RateLimited));
        // Different IP still OK.
        app.handle_from(
            HttpMethod::Get,
            "/v1/models",
            Some(&auth),
            b"",
            4,
            Some("198.51.100.8"),
        )
        .unwrap();
    }

    #[test]
    fn healthz_exempt_from_ip_api_rpm() {
        let mut limits = Limits::default();
        limits.ip_requests_per_minute = 1;
        let app = App::new(
            Config::default(),
            limits,
            EdgeAuthenticator::from_catalog(Authenticator::new({
                let sk = SigningKey::from_bytes(&[8u8; 32]);
                KeyCatalog::from_signed(
                    sign_test_catalog(vec![], &sk),
                    sk.verifying_key(),
                )
                .unwrap()
            })),
            MockUpstream::default(),
            TestPlatform,
            UsageSigner::from_seed([1u8; 32]),
        );
        for i in 0..5 {
            app.handle_from(HttpMethod::Get, "/healthz", None, b"", i, Some("198.51.100.9"))
                .unwrap();
        }
    }

    #[test]
    fn ip_api_rpm_zero_is_unlimited() {
        let mut limits = Limits::default();
        limits.ip_requests_per_minute = 0;
        limits.requests_per_minute = 10_000;
        let api_key = "sk-teechat-ip0";
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let signed = sign_test_catalog(
            vec![KeyRecord {
                key_id: "k".into(),
                key_hash_hex: hash_api_key(api_key),
                revoked: false,
            }],
            &sk,
        );
        let catalog = KeyCatalog::from_signed(signed, sk.verifying_key()).unwrap();
        let auth = format!("Bearer {api_key}");
        let upstream = MockUpstream::default().with(
            "/v1/models",
            UpstreamResponse::Json(serde_json::json!({"object":"list","data":[]})),
        );
        let app = App::new(
            Config::default(),
            limits,
            EdgeAuthenticator::from_catalog(Authenticator::new(catalog)),
            upstream,
            TestPlatform,
            UsageSigner::from_seed([2u8; 32]),
        );
        for i in 0..20 {
            app.handle_from(
                HttpMethod::Get,
                "/v1/models",
                Some(&auth),
                b"",
                i,
                Some("203.0.113.50"),
            )
            .unwrap();
        }
    }

    #[test]
    fn app_try_acquire_ip_conn_caps_and_releases() {
        let sk = SigningKey::from_bytes(&[4u8; 32]);
        let catalog = KeyCatalog::from_signed(sign_test_catalog(vec![], &sk), sk.verifying_key())
            .unwrap();
        let mut limits = Limits::default();
        limits.ip_max_connections = 1;
        let app = App::new(
            Config::default(),
            limits,
            EdgeAuthenticator::from_catalog(Authenticator::new(catalog)),
            MockUpstream::default(),
            TestPlatform,
            UsageSigner::from_seed([4u8; 32]),
        );
        let a = app.try_acquire_ip_conn(Some("198.51.100.1")).unwrap();
        match app.try_acquire_ip_conn(Some("198.51.100.1")) {
            Err(ApiError::RateLimited) => {}
            Ok(_) => panic!("expected RateLimited when ip_max_connections=1"),
            Err(e) => panic!("unexpected error: {e}"),
        }
        drop(a);
        app.try_acquire_ip_conn(Some("198.51.100.1")).unwrap();
    }

    #[test]
    fn list_models_proxies_upstream() {
        #[derive(Default)]
        struct ModelsUpstream;
        impl UpstreamForwarder for ModelsUpstream {
            fn forward_v1(
                &self,
                method: HttpMethod,
                path: &str,
                _body: Option<&[u8]>,
            ) -> Result<UpstreamResponse, ApiError> {
                assert_eq!(method, HttpMethod::Get);
                assert_eq!(path, "/v1/models");
                Ok(UpstreamResponse::Json(serde_json::json!({
                    "object": "list",
                    "data": [{"id":"engine-model","object":"model","created":1,"owned_by":"vllm"}]
                })))
            }
        }
        let app = build_test_app(ModelsUpstream);
        let resp = app
            .handle(HttpMethod::Get, "/v1/models", Some(AUTH), b"", 1)
            .unwrap();
        match resp {
            AppResponse::Json(v) => assert_eq!(v["data"][0]["id"], "engine-model"),
            _ => panic!("expected models json"),
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

    fn build_remote_app<U: UpstreamForwarder>(
        upstream: U,
        policy: crate::authz::OpenApiKeyPolicy,
        global_rpm: u32,
    ) -> (App<U, TestPlatform>, String) {
        use crate::authz::sign_test_authz_with_policy;
        use crate::remote_auth::{L0AuthorizeClient, RemoteAuthenticator};
        use std::sync::Arc;

        struct MockL0 {
            authz: crate::authz::SignedAuthz,
        }
        impl L0AuthorizeClient for MockL0 {
            fn authorize(
                &self,
                _key_id: &str,
                _key_hash_hex: &str,
            ) -> Result<crate::authz::SignedAuthz, ApiError> {
                Ok(self.authz.clone())
            }

            fn fetch_revocations(
                &self,
                _since_epoch: u64,
            ) -> Result<crate::remote_auth::RevocationDelta, ApiError> {
                Ok(crate::remote_auth::RevocationDelta {
                    epoch: self.authz.epoch,
                    revocations: vec![],
                })
            }
        }

        let secret = "D".repeat(32);
        let api_key = format!("sk-teechat-tcak_pl01ICY1.{secret}");
        let signing = SigningKey::generate(&mut OsRng);
        let hash = hash_api_key(&api_key);
        let authz = sign_test_authz_with_policy(
            "tcak_pl01ICY1",
            &hash,
            9_999_999_999_999,
            policy,
            1,
            &signing,
        );
        let remote = RemoteAuthenticator::new(
            signing.verifying_key(),
            Arc::new(MockL0 { authz }),
        );
        let mut limits = Limits::default();
        limits.requests_per_minute = global_rpm;
        let app = App::new(
            Config::default(),
            limits,
            EdgeAuthenticator::from_remote(remote),
            upstream,
            TestPlatform,
            UsageSigner::from_seed([3u8; 32]),
        );
        (app, format!("Bearer {api_key}"))
    }

    #[test]
    fn authz_policy_denies_disallowed_model() {
        let (app, auth) = build_remote_app(
            MockUpstream::default().with(
                "/v1/chat/completions",
                UpstreamResponse::Json(serde_json::json!({"id": "should-not-reach"})),
            ),
            crate::authz::OpenApiKeyPolicy {
                models: vec!["teechat-lite".into()],
                rpm: 120,
            key_set: "api".into(),
            remaining_tokens: None,
            },
            120,
        );
        let body = br#"{"model":"teechat-pro","messages":[{"role":"user","content":"hi"}]}"#;
        let err = app
            .handle(HttpMethod::Post, "/v1/chat/completions", Some(&auth), body, 1)
            .unwrap_err();
        match err {
            ApiError::Forbidden(msg) => assert!(msg.contains("teechat-pro")),
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }

    #[test]
    fn authz_policy_allows_listed_model() {
        let (app, auth) = build_remote_app(
            MockUpstream::default().with(
                "/v1/chat/completions",
                UpstreamResponse::Json(serde_json::json!({
                    "id": "ok",
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1}
                })),
            ),
            crate::authz::OpenApiKeyPolicy {
                models: vec!["teechat-lite".into()],
                rpm: 120,
            key_set: "api".into(),
            remaining_tokens: None,
            },
            120,
        );
        let body = br#"{"model":"teechat-lite","messages":[{"role":"user","content":"hi"}]}"#;
        let resp = app
            .handle(HttpMethod::Post, "/v1/chat/completions", Some(&auth), body, 1)
            .unwrap();
        assert!(matches!(resp, AppResponse::JsonWithUsage { .. }));
    }

    #[test]
    fn authz_policy_denies_model_on_streaming_chat() {
        let (app, auth) = build_remote_app(
            MockUpstream::default(),
            crate::authz::OpenApiKeyPolicy {
                models: vec!["teechat-lite".into()],
                rpm: 120,
            key_set: "api".into(),
            remaining_tokens: None,
            },
            120,
        );
        let body =
            br#"{"model":"teechat-pro","messages":[{"role":"user","content":"hi"}],"stream":true}"#;
        assert!(matches!(
            app.handle(HttpMethod::Post, "/v1/chat/completions", Some(&auth), body, 1),
            Err(ApiError::Forbidden(_))
        ));
    }

    #[test]
    fn authz_policy_rpm_caps_below_global() {
        let (app, auth) = build_remote_app(
            MockUpstream::default().with(
                "/v1/embeddings",
                UpstreamResponse::Json(serde_json::json!({
                    "object": "list",
                    "usage": {"prompt_tokens": 1, "total_tokens": 1}
                })),
            ),
            crate::authz::OpenApiKeyPolicy {
                models: vec!["*".into()],
                rpm: 2,
            key_set: "api".into(),
            remaining_tokens: None,
            },
            120,
        );
        let body = br#"{"model":"m","input":"x"}"#;
        app.handle(HttpMethod::Post, "/v1/embeddings", Some(&auth), body, 1)
            .unwrap();
        app.handle(HttpMethod::Post, "/v1/embeddings", Some(&auth), body, 2)
            .unwrap();
        assert!(matches!(
            app.handle(HttpMethod::Post, "/v1/embeddings", Some(&auth), body, 3),
            Err(ApiError::RateLimited)
        ));
    }

    #[test]
    fn authz_policy_global_rpm_caps_below_policy() {
        let (app, auth) = build_remote_app(
            MockUpstream::default().with(
                "/v1/embeddings",
                UpstreamResponse::Json(serde_json::json!({
                    "object": "list",
                    "usage": {"prompt_tokens": 1, "total_tokens": 1}
                })),
            ),
            crate::authz::OpenApiKeyPolicy {
                models: vec!["*".into()],
                rpm: 100,
            key_set: "api".into(),
            remaining_tokens: None,
            },
            1,
        );
        let body = br#"{"model":"m","input":"x"}"#;
        app.handle(HttpMethod::Post, "/v1/embeddings", Some(&auth), body, 1)
            .unwrap();
        assert!(matches!(
            app.handle(HttpMethod::Post, "/v1/embeddings", Some(&auth), body, 2),
            Err(ApiError::RateLimited)
        ));
    }

    #[test]
    fn catalog_auth_still_allows_any_model() {
        let app = build_test_app(
            MockUpstream::default().with(
                "/v1/chat/completions",
                UpstreamResponse::Json(serde_json::json!({
                    "id": "ok",
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1}
                })),
            ),
        );
        let body = br#"{"model":"whatever","messages":[{"role":"user","content":"hi"}]}"#;
        assert!(app
            .handle(HttpMethod::Post, "/v1/chat/completions", Some(AUTH), body, 1)
            .is_ok());
    }
}
