//! Dial client for TeeChat gateway **F′** privileged OPE API plane.
//!
//! Private listener routes (`GET /v1/ope/api/health`, `POST /v1/ope/dispatch`)
//! with `Authorization: Bearer` and optional pinned client mTLS (TLS 1.3).
//! Successful admit stamps gateway-authored `traffic_class=api`.

use std::io::{Cursor, Read};
use std::sync::Arc;
use std::time::Duration;

use openapi_platform::EdgeProfile;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::version::TLS13;
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};
use ureq::OrAnyStatus;

const HEALTH_PATH: &str = "/v1/ope/api/health";
const INVENTORY_PATH: &str = "/v1/ope/api/inventory";
const PREASSIGN_PATH: &str = "/v1/ope/api/preassign";
const DISPATCH_PATH: &str = "/v1/ope/dispatch";
const HEADER_ENGINE_ID: &str = "x-ope-engine-id";
const HEADER_CONVERSATION_ID: &str = "x-ope-conversation-id";
const HEADER_EPHEMERAL_EPOCH: &str = "x-ope-ephemeral-epoch";
const HEADER_ASSIGN_ID: &str = "x-ope-assign-id";
/// Binds API-key ledger debit on the gateway (METER-002). Must match gateway `HEADER_OPENAPI_KEY_ID`.
const HEADER_OPENAPI_KEY_ID: &str = "x-teechat-openapi-key-id";

/// Env configuration for the edge → gateway OPE API dialer.
#[derive(Debug, Clone)]
pub struct GatewayOpeApiConfig {
    /// Base URL, e.g. `https://10.0.0.2:8791` (no trailing slash required).
    pub base_url: String,
    /// Bearer dispatch token (optional during mTLS-only harden).
    pub token: Option<String>,
    /// Client certificate PEM (path or inline `-----BEGIN`).
    pub client_cert_pem: Option<String>,
    /// Client private key PEM (path or inline).
    pub client_key_pem: Option<String>,
    /// Optional CA PEM to verify the gateway server cert.
    pub ca_pem: Option<String>,
    /// Dev-only: skip server certificate verification.
    pub insecure_skip_verify: bool,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
}

impl GatewayOpeApiConfig {
    /// Load from `OPENAPI_GATEWAY_OPE_API_*`. Returns `Ok(None)` when URL is unset.
    pub fn from_env() -> Result<Option<Self>, GatewayOpeApiError> {
        let Some(base_url) = opt_env("OPENAPI_GATEWAY_OPE_API_URL") else {
            return Ok(None);
        };
        let cfg = Self::from_parts(
            base_url,
            opt_env("OPENAPI_GATEWAY_OPE_API_TOKEN"),
            opt_env("OPENAPI_GATEWAY_OPE_API_TLS_CLIENT_CERT_PEM"),
            opt_env("OPENAPI_GATEWAY_OPE_API_TLS_CLIENT_KEY_PEM"),
            opt_env("OPENAPI_GATEWAY_OPE_API_TLS_CA_PEM"),
            truthy_env("OPENAPI_GATEWAY_OPE_API_TLS_INSECURE_SKIP_VERIFY"),
        )?;
        cfg.validate_for_profile(openapi_platform::load_edge_profile())?;
        Ok(Some(cfg))
    }

    pub fn from_parts(
        base_url: impl Into<String>,
        token: Option<String>,
        client_cert_pem: Option<String>,
        client_key_pem: Option<String>,
        ca_pem: Option<String>,
        insecure_skip_verify: bool,
    ) -> Result<Self, GatewayOpeApiError> {
        // Shared audited PEM/path load + cert/key pairing (attested-mtls TCB).
        let loaded = attested_mtls::load_openapi_client_tls_from_parts(
            &base_url.into(),
            client_cert_pem.as_deref(),
            client_key_pem.as_deref(),
            ca_pem.as_deref(),
            insecure_skip_verify,
        )
        .map_err(|e| GatewayOpeApiError::Config(e.to_string()))?;
        Ok(Self {
            base_url: loaded.base_url,
            token: token.filter(|s| !s.is_empty()),
            client_cert_pem: loaded.client_cert_pem,
            client_key_pem: loaded.client_key_pem,
            ca_pem: loaded.ca_pem,
            insecure_skip_verify: loaded.insecure_skip_verify,
            connect_timeout: Duration::from_secs(10),
            // Match gateway TEECHAT_OPE_UPSTREAM_TIMEOUT_MS default (5m). Override via
            // OPENAPI_GATEWAY_OPE_API_READ_TIMEOUT_SECS. Short chats were fine at 120s;
            // long/tool runs hung up as client 502 when the ureq read deadline fired or a
            // half-closed keep-alive socket was reused (prod CLOSE-WAIT/FIN-WAIT-2).
            read_timeout: duration_secs_from_env("OPENAPI_GATEWAY_OPE_API_READ_TIMEOUT_SECS", 300),
        })
    }

    /// Reject `INSECURE_SKIP_VERIFY` and cleartext F′ URL under prod (OPE-006).
    pub fn validate_for_profile(&self, profile: EdgeProfile) -> Result<(), GatewayOpeApiError> {
        if self.insecure_skip_verify && profile.is_prod() {
            return Err(GatewayOpeApiError::Config(
                "OPENAPI_GATEWAY_OPE_API_TLS_INSECURE_SKIP_VERIFY forbidden when OPENAPI_PROFILE=prod"
                    .into(),
            ));
        }
        if profile.is_prod() && !self.base_url.starts_with("https://") {
            return Err(GatewayOpeApiError::Config(
                "OPENAPI_GATEWAY_OPE_API_URL must use https:// when OPENAPI_PROFILE=prod".into(),
            ));
        }
        Ok(())
    }
}

/// Dialer for gateway F′ OPE API.
///
/// Idle keep-alive is **disabled** (`max_idle_connections=0`): reusing half-closed
/// sockets after gateway VIP/TLS teardown surfaced as client `502 socket hang up`
/// with edge CLOSE-WAIT and gateway FIN-WAIT-2 on `:8791`/`:8792`.
#[derive(Debug, Clone)]
pub struct GatewayOpeApiClient {
    base_url: String,
    token: Option<String>,
    agent: ureq::Agent,
}

impl GatewayOpeApiClient {
    pub fn try_new(config: GatewayOpeApiConfig) -> Result<Self, GatewayOpeApiError> {
        let mut builder = ureq::AgentBuilder::new()
            .timeout_connect(config.connect_timeout)
            .timeout_read(config.read_timeout)
            .max_idle_connections(0)
            .max_idle_connections_per_host(0);

        if config.base_url.starts_with("https://") {
            let tls = build_client_tls_config(&config)?;
            builder = builder.tls_config(tls);
        }

        Ok(Self {
            base_url: config.base_url,
            token: config.token,
            agent: builder.build(),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    fn apply_auth(&self, req: ureq::Request) -> ureq::Request {
        match &self.token {
            Some(tok) => req.set("Authorization", &format!("Bearer {tok}")),
            None => req,
        }
    }

    /// `GET /v1/ope/api/health`
    pub fn health(&self) -> Result<HealthResponse, GatewayOpeApiError> {
        let url = self.url(HEALTH_PATH);
        let resp = self
            .apply_auth(self.agent.get(&url))
            .call()
            .or_any_status()
            .map_err(|e| GatewayOpeApiError::Transport(e.to_string()))?;
        let status = resp.status();
        let text = resp
            .into_string()
            .map_err(|e| GatewayOpeApiError::Transport(format!("read body: {e}")))?;
        if status != 200 {
            return Err(GatewayOpeApiError::Http {
                status,
                body: truncate_body(&text),
            });
        }
        serde_json::from_str(&text).map_err(|e| GatewayOpeApiError::Decode(e.to_string()))
    }

    /// `GET /v1/ope/api/inventory?key_set=`
    pub fn inventory(&self, key_set: &str) -> Result<InventoryResponse, GatewayOpeApiError> {
        let ks = key_set.trim();
        let mut url = self.url(INVENTORY_PATH);
        if !ks.is_empty() {
            url.push_str(&format!("?key_set={}", urlencoding_minimal(ks)));
        }
        let resp = self
            .apply_auth(self.agent.get(&url))
            .call()
            .or_any_status()
            .map_err(|e| GatewayOpeApiError::Transport(e.to_string()))?;
        let status = resp.status();
        let text = resp
            .into_string()
            .map_err(|e| GatewayOpeApiError::Transport(format!("read body: {e}")))?;
        if status != 200 {
            return Err(GatewayOpeApiError::Http {
                status,
                body: truncate_body(&text),
            });
        }
        serde_json::from_str(&text).map_err(|e| GatewayOpeApiError::Decode(e.to_string()))
    }

    /// `POST /v1/ope/api/preassign` — P1 epoch wrap material + assign_id.
    pub fn preassign(
        &self,
        req: &PreassignRequest,
    ) -> Result<PreassignResponse, GatewayOpeApiError> {
        if req.engine_id.trim().is_empty() {
            return Err(GatewayOpeApiError::Config(
                "preassign requires non-empty engine_id".into(),
            ));
        }
        let url = self.url(PREASSIGN_PATH);
        let body =
            serde_json::to_vec(req).map_err(|e| GatewayOpeApiError::Decode(e.to_string()))?;
        let resp = self
            .apply_auth(self.agent.post(&url))
            .set("Content-Type", "application/json")
            .send_bytes(&body)
            .or_any_status()
            .map_err(|e| GatewayOpeApiError::Transport(e.to_string()))?;
        let status = resp.status();
        let text = resp
            .into_string()
            .map_err(|e| GatewayOpeApiError::Transport(format!("read body: {e}")))?;
        if status != 200 {
            return Err(GatewayOpeApiError::Http {
                status,
                body: truncate_body(&text),
            });
        }
        serde_json::from_str(&text).map_err(|e| GatewayOpeApiError::Decode(e.to_string()))
    }

    /// `POST /v1/ope/dispatch` — returns status + headers + body bytes.
    pub fn dispatch(&self, req: &DispatchRequest) -> Result<DispatchResponse, GatewayOpeApiError> {
        let (status, headers, mut reader) = self.dispatch_reader(req)?;
        let mut body = Vec::new();
        reader
            .read_to_end(&mut body)
            .map_err(|e| GatewayOpeApiError::Transport(format!("read body: {e}")))?;
        Ok(DispatchResponse {
            status,
            headers,
            body,
        })
    }

    /// Streaming dispatch: caller consumes the response body reader.
    pub fn dispatch_reader(
        &self,
        req: &DispatchRequest,
    ) -> Result<(u16, Vec<(String, String)>, Box<dyn std::io::Read + Send>), GatewayOpeApiError>
    {
        if req.engine_id.trim().is_empty() {
            return Err(GatewayOpeApiError::Config(
                "dispatch requires non-empty engine_id".into(),
            ));
        }
        let url = self.url(DISPATCH_PATH);
        let mut ureq_req = self
            .apply_auth(self.agent.post(&url))
            .set("Content-Type", "application/json")
            .set(HEADER_ENGINE_ID, req.engine_id.trim());
        if let Some(cid) = req
            .conversation_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            ureq_req = ureq_req.set(HEADER_CONVERSATION_ID, cid);
        }
        if let Some(epoch) = req
            .ephemeral_epoch
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            ureq_req = ureq_req.set(HEADER_EPHEMERAL_EPOCH, epoch);
        } else {
            ureq_req = ureq_req.set(HEADER_EPHEMERAL_EPOCH, "0");
        }
        if let Some(key_id) = req
            .openapi_key_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            ureq_req = ureq_req.set(HEADER_OPENAPI_KEY_ID, key_id);
        }
        if let Some(assign_id) = req
            .assign_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            ureq_req = ureq_req.set(HEADER_ASSIGN_ID, assign_id);
        }

        let resp = ureq_req
            .send_bytes(&req.body)
            .or_any_status()
            .map_err(|e| GatewayOpeApiError::Transport(e.to_string()))?;
        let status = resp.status();
        let headers: Vec<(String, String)> = resp
            .headers_names()
            .into_iter()
            .filter_map(|name| resp.header(&name).map(|v| (name, v.to_string())))
            .collect();
        let reader = resp.into_reader();
        Ok((status, headers, Box::new(reader)))
    }
}

/// Gateway `GET /v1/ope/api/health` JSON body.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct HealthResponse {
    pub ok: bool,
    pub plane: String,
    pub traffic_class_author: String,
    #[serde(default)]
    pub auth: Option<String>,
    #[serde(default)]
    pub peer_pin: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct InventoryEngine {
    pub engine_id: String,
    #[serde(default = "default_engine_set")]
    pub engine_set: String,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default)]
    pub healthy: bool,
    #[serde(default)]
    pub ready_sessions: u32,
}

fn default_engine_set() -> String {
    "shared".into()
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct InventoryResponse {
    #[serde(default)]
    pub engines: Vec<InventoryEngine>,
    #[serde(default)]
    pub key_set: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreassignRequest {
    pub engine_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_set: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Bound at P1 for ledger debit (OPE-007 / METER-002).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub openapi_key_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PreassignTrustHybrid {
    #[serde(default)]
    pub kex: String,
    pub mlkem_encapsulation_key: String,
    pub x25519_public: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PreassignTrustIdentity {
    pub ed25519_public: String,
    #[serde(default)]
    pub identity_signature: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PreassignTrust {
    pub engine_id: String,
    pub epoch_id: String,
    #[serde(default)]
    pub not_before: Option<String>,
    #[serde(default)]
    pub not_after: Option<String>,
    pub hybrid: PreassignTrustHybrid,
    pub identity: PreassignTrustIdentity,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PreassignResponse {
    pub assign_id: String,
    pub engine_id: String,
    #[serde(default)]
    pub engine_set: Option<String>,
    #[serde(default)]
    pub key_set: Option<String>,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    #[serde(default)]
    pub ttl_ms: Option<u64>,
    pub trust: PreassignTrust,
}

/// Dispatch request for OPE envelope wiring.
#[derive(Debug, Clone)]
pub struct DispatchRequest {
    pub engine_id: String,
    pub conversation_id: Option<String>,
    pub ephemeral_epoch: Option<String>,
    /// When set, gateway ope-api plane debits `openapi_usage_events` for this key (METER-002).
    pub openapi_key_id: Option<String>,
    /// P1 assign id from preassign (required after hard cutover).
    pub assign_id: Option<String>,
    /// Raw OPE envelope JSON bytes.
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DispatchResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl DispatchResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Error)]
pub enum GatewayOpeApiError {
    #[error("config: {0}")]
    Config(String),
    #[error("tls: {0}")]
    Tls(String),
    #[error("transport: {0}")]
    Transport(String),
    #[error("http {status}: {body}")]
    Http { status: u16, body: String },
    #[error("decode: {0}")]
    Decode(String),
}

/// Optional startup probe: skip when URL unset; warn (fail-closed tone in prod) on failure.
pub fn probe_gateway_ope_api_at_startup(profile: EdgeProfile) {
    match GatewayOpeApiConfig::from_env() {
        Ok(None) => {
            info!("OPENAPI_GATEWAY_OPE_API_URL unset — skipping gateway OPE API health probe");
        }
        Ok(Some(cfg)) => {
            let url = cfg.base_url.clone();
            match GatewayOpeApiClient::try_new(cfg).and_then(|c| c.health()) {
                Ok(h) => {
                    info!(
                        url = %url,
                        plane = %h.plane,
                        traffic_class_author = %h.traffic_class_author,
                        auth = ?h.auth,
                        "gateway OPE API health ok"
                    );
                }
                Err(e) if profile.is_prod() => {
                    warn!(
                        url = %url,
                        error = %e,
                        "gateway OPE API health failed — fail-closed (OPE dispatch unavailable until plane is reachable)"
                    );
                }
                Err(e) => {
                    warn!(
                        url = %url,
                        error = %e,
                        "gateway OPE API health failed (non-fatal in dev)"
                    );
                }
            }
        }
        Err(e) if profile.is_prod() => {
            warn!(
                error = %e,
                "gateway OPE API config invalid — fail-closed (fix OPENAPI_GATEWAY_OPE_API_* )"
            );
        }
        Err(e) => {
            warn!(
                error = %e,
                "gateway OPE API config invalid (non-fatal in dev)"
            );
        }
    }
}

/// Fail closed in prod when F′ is unreachable (hard OPE cutover).
pub fn require_gateway_ope_api_healthy(profile: EdgeProfile) -> Result<(), GatewayOpeApiError> {
    let Some(cfg) = GatewayOpeApiConfig::from_env()? else {
        if profile.is_prod() {
            return Err(GatewayOpeApiError::Config(
                "OPENAPI_GATEWAY_OPE_API_URL required in prod (hard OPE cutover)".into(),
            ));
        }
        return Ok(());
    };
    let url = cfg.base_url.clone();
    let client = GatewayOpeApiClient::try_new(cfg)?;
    client.health().map(|_| ()).map_err(|e| {
        if profile.is_prod() {
            GatewayOpeApiError::Transport(format!("F′ health failed at {url}: {e}"))
        } else {
            e
        }
    })
}

fn urlencoding_minimal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn build_client_tls_config(
    config: &GatewayOpeApiConfig,
) -> Result<Arc<ClientConfig>, GatewayOpeApiError> {
    let builder = ClientConfig::builder_with_protocol_versions(&[&TLS13]);

    let builder = if config.insecure_skip_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerify))
    } else {
        let mut roots = RootCertStore::empty();
        if let Some(ca) = &config.ca_pem {
            let certs = load_certs_pem(ca.as_bytes())?;
            for cert in certs {
                roots
                    .add(cert)
                    .map_err(|e| GatewayOpeApiError::Tls(format!("add CA: {e}")))?;
            }
            if roots.is_empty() {
                return Err(GatewayOpeApiError::Tls(
                    "OPENAPI_GATEWAY_OPE_API_TLS_CA_PEM contained no certificates".into(),
                ));
            }
        } else {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        builder.with_root_certificates(roots)
    };

    let client_config = match (&config.client_cert_pem, &config.client_key_pem) {
        (Some(cert_pem), Some(key_pem)) => {
            let certs = load_certs_pem(cert_pem.as_bytes())?;
            let key = load_private_key_pem(key_pem.as_bytes())?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| GatewayOpeApiError::Tls(format!("client identity: {e}")))?
        }
        _ => builder.with_no_client_auth(),
    };

    Ok(Arc::new(client_config))
}

fn load_certs_pem(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, GatewayOpeApiError> {
    rustls_pemfile::certs(&mut Cursor::new(pem))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| GatewayOpeApiError::Tls(format!("parse cert PEM: {e}")))
}

fn load_private_key_pem(pem: &[u8]) -> Result<PrivateKeyDer<'static>, GatewayOpeApiError> {
    rustls_pemfile::private_key(&mut Cursor::new(pem))
        .map_err(|e| GatewayOpeApiError::Tls(format!("parse key PEM: {e}")))?
        .ok_or_else(|| GatewayOpeApiError::Tls("missing private key in PEM".into()))
}

fn opt_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.trim().is_empty())
}

fn duration_secs_from_env(name: &str, default_secs: u64) -> Duration {
    let secs = opt_env(name)
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default_secs);
    Duration::from_secs(secs)
}

fn truthy_env(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes"
        }
        Err(_) => false,
    }
}

fn truncate_body(s: &str) -> String {
    const MAX: usize = 256;
    if s.len() <= MAX {
        s.to_string()
    } else {
        format!("{}…", &s[..MAX])
    }
}

#[derive(Debug)]
struct SkipServerVerify;

impl ServerCertVerifier for SkipServerVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Mutex;
    use std::thread;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn ensure_crypto() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    fn clear_ope_env() {
        for k in [
            "OPENAPI_GATEWAY_OPE_API_URL",
            "OPENAPI_GATEWAY_OPE_API_TOKEN",
            "OPENAPI_GATEWAY_OPE_API_TLS_CLIENT_CERT_PEM",
            "OPENAPI_GATEWAY_OPE_API_TLS_CLIENT_KEY_PEM",
            "OPENAPI_GATEWAY_OPE_API_TLS_CA_PEM",
            "OPENAPI_GATEWAY_OPE_API_TLS_INSECURE_SKIP_VERIFY",
        ] {
            std::env::remove_var(k);
        }
    }

    fn serve_http_once(status_line: &'static str, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(
                req.contains("Authorization: Bearer test-token"),
                "missing bearer: {req}"
            );
            let resp = format!(
                "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        });
        format!("http://{addr}")
    }

    fn serve_dispatch_once() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let req = read_http_request(&mut stream);
            assert!(req.starts_with("POST /v1/ope/dispatch"));
            assert!(req.to_ascii_lowercase().contains("x-ope-engine-id: eng-1"));
            assert!(
                req.to_ascii_lowercase()
                    .contains("x-teechat-openapi-key-id: tcak_bill01"),
                "missing openapi key_id header: {req}"
            );
            assert!(
                req.to_ascii_lowercase()
                    .contains("x-ope-assign-id: assign-abc"),
                "missing assign_id header: {req}"
            );
            assert!(req.contains("Authorization: Bearer test-token"));
            let body = br#"{"ok":true}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-OPE-Traffic-Class: api\r\nX-OPE-Request-Id: req-1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                std::str::from_utf8(body).unwrap()
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        });
        format!("http://{addr}")
    }

    /// Read one HTTP/1.1 request including body (Content-Length).
    fn read_http_request(stream: &mut impl Read) -> String {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            let n = stream.read(&mut tmp).expect("read");
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(header_end) = find_header_end(&buf) {
                let headers = std::str::from_utf8(&buf[..header_end]).unwrap_or("");
                let content_len = headers
                    .lines()
                    .find_map(|l| {
                        let l = l.to_ascii_lowercase();
                        l.strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                if buf.len() >= header_end + content_len {
                    break;
                }
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    fn find_header_end(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
    }

    #[test]
    fn from_env_none_when_url_unset() {
        let _g = env_lock();
        clear_ope_env();
        assert!(GatewayOpeApiConfig::from_env().unwrap().is_none());
    }

    #[test]
    fn from_env_loads_bearer_config() {
        let _g = env_lock();
        clear_ope_env();
        std::env::set_var("OPENAPI_GATEWAY_OPE_API_URL", "https://10.0.0.2:8791/");
        std::env::set_var("OPENAPI_GATEWAY_OPE_API_TOKEN", "secret");
        let cfg = GatewayOpeApiConfig::from_env().unwrap().unwrap();
        assert_eq!(cfg.base_url, "https://10.0.0.2:8791");
        assert_eq!(cfg.token.as_deref(), Some("secret"));
        assert!(!cfg.insecure_skip_verify);
        clear_ope_env();
    }

    #[test]
    fn from_env_reads_pem_from_path() {
        let _g = env_lock();
        clear_ope_env();
        ensure_crypto();
        let dir = std::env::temp_dir().join(format!("ope-api-pem-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("client.crt");
        let key_path = dir.join("client.key");
        let (cert_pem, key_pem) = self_signed_client_pem();
        fs::write(&cert_path, &cert_pem).unwrap();
        fs::write(&key_path, &key_pem).unwrap();

        std::env::set_var("OPENAPI_GATEWAY_OPE_API_URL", "https://127.0.0.1:8791");
        std::env::set_var(
            "OPENAPI_GATEWAY_OPE_API_TLS_CLIENT_CERT_PEM",
            cert_path.to_str().unwrap(),
        );
        std::env::set_var(
            "OPENAPI_GATEWAY_OPE_API_TLS_CLIENT_KEY_PEM",
            key_path.to_str().unwrap(),
        );
        // Self-signed: pin the same cert as CA so we do not need skip-verify.
        std::env::set_var(
            "OPENAPI_GATEWAY_OPE_API_TLS_CA_PEM",
            cert_path.to_str().unwrap(),
        );

        let cfg = GatewayOpeApiConfig::from_env().unwrap().unwrap();
        assert!(cfg
            .client_cert_pem
            .as_ref()
            .unwrap()
            .contains("BEGIN CERTIFICATE"));
        assert!(cfg.client_key_pem.as_ref().unwrap().contains("BEGIN"));
        GatewayOpeApiClient::try_new(cfg).expect("client builds with path PEMs");

        clear_ope_env();
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn prod_rejects_insecure_skip_verify() {
        let cfg = GatewayOpeApiConfig::from_parts(
            "https://10.0.0.2:8791",
            Some("tok".into()),
            None,
            None,
            None,
            true,
        )
        .unwrap();
        let err = cfg
            .validate_for_profile(EdgeProfile::Prod)
            .expect_err("must reject");
        assert!(matches!(err, GatewayOpeApiError::Config(_)));
        assert!(cfg.validate_for_profile(EdgeProfile::Dev).is_ok());
    }

    #[test]
    fn prod_rejects_http_f_prime_url() {
        let cfg = GatewayOpeApiConfig::from_parts(
            "http://10.0.0.2:8791",
            Some("tok".into()),
            None,
            None,
            None,
            false,
        )
        .unwrap();
        let err = cfg
            .validate_for_profile(EdgeProfile::Prod)
            .expect_err("must reject http in prod");
        assert!(matches!(err, GatewayOpeApiError::Config(_)));
        let msg = err.to_string();
        assert!(msg.contains("https://"), "{msg}");
        assert!(cfg.validate_for_profile(EdgeProfile::Dev).is_ok());
    }

    #[test]
    fn cert_without_key_rejected() {
        let err = GatewayOpeApiConfig::from_parts(
            "https://10.0.0.2:8791",
            None,
            Some("-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----".into()),
            None,
            None,
            false,
        )
        .expect_err("must reject");
        assert!(matches!(err, GatewayOpeApiError::Config(_)));
    }

    #[test]
    fn health_parses_gateway_shape() {
        ensure_crypto();
        let base = serve_http_once(
            "200 OK",
            r#"{"ok":true,"plane":"ope_api","traffic_class_author":"api","auth":"bearer"}"#,
        );
        let cfg = GatewayOpeApiConfig::from_parts(
            base,
            Some("test-token".into()),
            None,
            None,
            None,
            false,
        )
        .unwrap();
        let client = GatewayOpeApiClient::try_new(cfg).unwrap();
        let h = client.health().unwrap();
        assert!(h.ok);
        assert_eq!(h.plane, "ope_api");
        assert_eq!(h.traffic_class_author, "api");
        assert_eq!(h.auth.as_deref(), Some("bearer"));
    }

    #[test]
    fn health_maps_unauthorized() {
        ensure_crypto();
        let base = serve_http_once(
            "401 Unauthorized",
            r#"{"error":{"message":"Unauthorized","code":"missing_bearer"}}"#,
        );
        let cfg = GatewayOpeApiConfig::from_parts(
            base,
            Some("test-token".into()),
            None,
            None,
            None,
            false,
        )
        .unwrap();
        let client = GatewayOpeApiClient::try_new(cfg).unwrap();
        let err = client.health().expect_err("must fail");
        assert!(matches!(err, GatewayOpeApiError::Http { status: 401, .. }));
    }

    #[test]
    fn dispatch_returns_status_headers_body() {
        ensure_crypto();
        let base = serve_dispatch_once();
        let cfg = GatewayOpeApiConfig::from_parts(
            base,
            Some("test-token".into()),
            None,
            None,
            None,
            false,
        )
        .unwrap();
        let client = GatewayOpeApiClient::try_new(cfg).unwrap();
        let resp = client
            .dispatch(&DispatchRequest {
                engine_id: "eng-1".into(),
                conversation_id: Some("c1".into()),
                ephemeral_epoch: None,
                openapi_key_id: Some("tcak_bill01".into()),
                assign_id: Some("assign-abc".into()),
                body: br#"{"version":1,"ciphertext":"x"}"#.to_vec(),
            })
            .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.header("X-OPE-Traffic-Class"), Some("api"));
        assert_eq!(resp.header("X-OPE-Request-Id"), Some("req-1"));
        assert_eq!(resp.body, br#"{"ok":true}"#);
    }

    #[test]
    fn inventory_and_preassign_roundtrip() {
        ensure_crypto();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let req = read_http_request(&mut stream);
                let (status_line, body): (&str, &str) = if req
                    .starts_with("GET /v1/ope/api/inventory")
                {
                    assert!(req.contains("key_set=api"));
                    assert!(req.contains("Authorization: Bearer test-token"));
                    (
                        "200 OK",
                        r#"{"matrix_default":"*-*","key_set":"api","engines":[{"engine_id":"eng-1","engine_set":"shared","models":["m1"],"healthy":true,"ready_sessions":2}]}"#,
                    )
                } else if req.starts_with("POST /v1/ope/api/preassign") {
                    assert!(req.contains("Authorization: Bearer test-token"));
                    assert!(req.contains("eng-1"));
                    (
                        "200 OK",
                        r#"{"assign_id":"a1","engine_id":"eng-1","engine_set":"shared","key_set":"api","trust":{"engine_id":"eng-1","epoch_id":"ep1","hybrid":{"kex":"X25519MLKEM768","mlkem_encapsulation_key":"aa","x25519_public":"bb"},"identity":{"ed25519_public":"cc"}}}"#,
                    )
                } else {
                    panic!("unexpected req: {req}");
                };
                let resp = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        let base = format!("http://{addr}");
        let cfg = GatewayOpeApiConfig::from_parts(
            base,
            Some("test-token".into()),
            None,
            None,
            None,
            false,
        )
        .unwrap();
        let client = GatewayOpeApiClient::try_new(cfg).unwrap();
        let inv = client.inventory("api").unwrap();
        assert_eq!(inv.engines.len(), 1);
        assert_eq!(inv.engines[0].engine_id, "eng-1");
        assert_eq!(inv.engines[0].ready_sessions, 2);
        let pre = client
            .preassign(&PreassignRequest {
                engine_id: "eng-1".into(),
                key_set: Some("api".into()),
                model: Some("m1".into()),
                openapi_key_id: Some("tcak_test".into()),
            })
            .unwrap();
        assert_eq!(pre.assign_id, "a1");
        assert_eq!(pre.trust.epoch_id, "ep1");
    }

    #[test]
    fn tls_client_config_with_self_signed_pair() {
        ensure_crypto();
        let (cert_pem, key_pem) = self_signed_client_pem();
        let ca_pem = cert_pem.clone(); // self-signed: use same as trust anchor for smoke build
        let cfg = GatewayOpeApiConfig::from_parts(
            "https://127.0.0.1:8791",
            Some("tok".into()),
            Some(cert_pem),
            Some(key_pem),
            Some(ca_pem),
            false,
        )
        .unwrap();
        let tls = build_client_tls_config(&cfg).expect("tls config");
        assert!(Arc::strong_count(&tls) >= 1);
    }

    #[test]
    fn tls_insecure_skip_verify_builds() {
        ensure_crypto();
        let (cert_pem, key_pem) = self_signed_client_pem();
        let cfg = GatewayOpeApiConfig::from_parts(
            "https://127.0.0.1:8791",
            None,
            Some(cert_pem),
            Some(key_pem),
            None,
            true,
        )
        .unwrap();
        build_client_tls_config(&cfg).expect("skip-verify tls");
    }

    #[test]
    fn mtls_health_against_local_rustls_server() {
        ensure_crypto();
        let fixtures = MtlsFixtures::generate();
        let base = fixtures.spawn_health_server();
        let cfg = GatewayOpeApiConfig::from_parts(
            base,
            Some("test-token".into()),
            Some(fixtures.client_cert_pem.clone()),
            Some(fixtures.client_key_pem.clone()),
            Some(fixtures.ca_pem.clone()),
            false,
        )
        .unwrap();
        let client = GatewayOpeApiClient::try_new(cfg).unwrap();
        let h = client.health().unwrap();
        assert!(h.ok);
        assert_eq!(h.plane, "ope_api");
        assert_eq!(h.traffic_class_author, "api");
    }

    fn self_signed_client_pem() -> (String, String) {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["edge-client".into()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.pem(), key_pair.serialize_pem())
    }

    struct MtlsFixtures {
        ca_pem: String,
        client_cert_pem: String,
        client_key_pem: String,
        server_cert_pem: String,
        server_key_pem: String,
        client_ca_der: CertificateDer<'static>,
    }

    impl MtlsFixtures {
        fn generate() -> Self {
            use rcgen::{BasicConstraints, IsCa, KeyUsagePurpose, SanType};
            use std::net::{IpAddr, Ipv4Addr};

            let ca_key = rcgen::KeyPair::generate().unwrap();
            let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let ca_cert = ca_params.self_signed(&ca_key).unwrap();
            let ca_pem = ca_cert.pem();

            let server_key = rcgen::KeyPair::generate().unwrap();
            let mut server_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            server_params.subject_alt_names = vec![
                SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                SanType::DnsName("localhost".try_into().unwrap()),
            ];
            server_params
                .key_usages
                .push(KeyUsagePurpose::DigitalSignature);
            server_params
                .extended_key_usages
                .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
            let server_cert = server_params
                .signed_by(&server_key, &ca_cert, &ca_key)
                .unwrap();

            let client_key = rcgen::KeyPair::generate().unwrap();
            let mut client_params =
                rcgen::CertificateParams::new(vec!["edge-client".into()]).unwrap();
            client_params
                .key_usages
                .push(KeyUsagePurpose::DigitalSignature);
            client_params
                .extended_key_usages
                .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
            let client_cert = client_params
                .signed_by(&client_key, &ca_cert, &ca_key)
                .unwrap();

            Self {
                ca_pem,
                client_cert_pem: client_cert.pem(),
                client_key_pem: client_key.serialize_pem(),
                server_cert_pem: server_cert.pem(),
                server_key_pem: server_key.serialize_pem(),
                client_ca_der: CertificateDer::from(ca_cert.der().to_vec()),
            }
        }

        fn spawn_health_server(&self) -> String {
            let server_certs = load_certs_pem(self.server_cert_pem.as_bytes()).unwrap();
            let server_key = load_private_key_pem(self.server_key_pem.as_bytes()).unwrap();
            let mut root = RootCertStore::empty();
            root.add(self.client_ca_der.clone()).unwrap();
            let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root))
                .build()
                .expect("client verifier");
            let server_config = rustls::ServerConfig::builder_with_protocol_versions(&[&TLS13])
                .with_client_cert_verifier(client_verifier)
                .with_single_cert(server_certs, server_key)
                .expect("server config");
            let server_config = Arc::new(server_config);

            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let addr = listener.local_addr().expect("addr");
            thread::spawn(move || {
                let (tcp, _) = listener.accept().expect("accept");
                tcp.set_read_timeout(Some(Duration::from_secs(5))).ok();
                tcp.set_write_timeout(Some(Duration::from_secs(5))).ok();
                let conn = rustls::ServerConnection::new(server_config).expect("conn");
                let mut tls = rustls::StreamOwned::new(conn, tcp);
                let mut buf = [0u8; 8192];
                let n = tls.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                assert!(req.contains("GET /v1/ope/api/health"));
                assert!(req.contains("Authorization: Bearer test-token"));
                let body = r#"{"ok":true,"plane":"ope_api","traffic_class_author":"api","auth":"mtls+bearer"}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(resp.as_bytes());
                let _ = tls.flush();
            });
            format!("https://{addr}")
        }
    }
}
