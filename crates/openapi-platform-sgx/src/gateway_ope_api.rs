//! Dial client for TeeChat gateway **F′** privileged OPE API plane — Fortanix SGX EDP.
//!
//! Private listener routes (`GET /v1/ope/api/health`, `GET /v1/ope/api/inventory`,
//! `POST /v1/ope/api/preassign`, `POST /v1/ope/dispatch`) with `Authorization: Bearer`
//! and optional pinned client mTLS (TLS 1.3). Same wire contract as
//! `openapi-platform-cvm::gateway_ope_api`, but dialed with a raw `TcpStream` +
//! `rustls` (SGX target: `rustls-rustcrypto` provider) instead of `ureq` — `ureq`'s
//! TLS backends (`aws-lc-rs` / `ring`) hit `#UD` inside the Fortanix enclave.
//!
//! **SGX constraints baked in here:**
//! - `OPENAPI_GATEWAY_OPE_API_URL` must be `https://IP:port` — no DNS resolver in the
//!   enclave, and no clear-text fallback for the F′ plane itself (unlike CVM's dev-only
//!   plain-http option). Use `OPENAPI_UPSTREAM_CLEAR_HTTP=1` to bypass OPE entirely
//!   (see `edge_upstream::EdgeUpstream`) instead of trying to run F′ over http.
//! - mTLS client cert/key/CA must be **inline PEM** (`-----BEGIN ...-----`). Path-based
//!   PEM is rejected up front: `std::fs` is unsupported on Fortanix EDP, so a path would
//!   otherwise fail confusingly deep inside `attested_mtls::read_pem_maybe`.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use openapi_core::http1_body::{read_response_headers, BodyFraming};
use openapi_platform::{EdgeProfile, EngineIdentityPins, EngineRecipientPolicy};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::version::TLS13;
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error as RustlsError, RootCertStore,
    SignatureScheme, StreamOwned,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};

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
    /// Base URL — `https://IP:port` (SGX: literal IP, no DNS; no trailing slash required).
    pub base_url: String,
    /// Bearer dispatch token (optional during mTLS-only harden).
    pub token: Option<String>,
    /// Client certificate PEM — **inline only** on SGX (`-----BEGIN ...`).
    pub client_cert_pem: Option<String>,
    /// Client private key PEM — **inline only** on SGX.
    pub client_key_pem: Option<String>,
    /// Optional CA PEM to verify the gateway server cert — **inline only** on SGX.
    pub ca_pem: Option<String>,
    /// Dev-only: skip server certificate verification.
    pub insecure_skip_verify: bool,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub engine_identity_pins: EngineIdentityPins,
    pub epoch_clock_skew: Duration,
    /// Which engine keys customer plaintext may be encrypted to (RB-46/47).
    ///
    /// The lab enclave verifies the epoch binding and the launch-digest pin but
    /// not the AMD chain: `openapi-attest` does not link under Fortanix EDP.
    pub recipient_policy: EngineRecipientPolicy,
}

impl GatewayOpeApiConfig {
    /// Load from `OPENAPI_GATEWAY_OPE_API_*`. Returns `Ok(None)` when URL is unset.
    pub fn from_env() -> Result<Option<Self>, GatewayOpeApiError> {
        let Some(base_url) = opt_env("OPENAPI_GATEWAY_OPE_API_URL") else {
            return Ok(None);
        };
        let mut cfg = Self::from_parts(
            base_url,
            opt_env("OPENAPI_GATEWAY_OPE_API_TOKEN"),
            opt_env("OPENAPI_GATEWAY_OPE_API_TLS_CLIENT_CERT_PEM"),
            opt_env("OPENAPI_GATEWAY_OPE_API_TLS_CLIENT_KEY_PEM"),
            opt_env("OPENAPI_GATEWAY_OPE_API_TLS_CA_PEM"),
            truthy_env("OPENAPI_GATEWAY_OPE_API_TLS_INSECURE_SKIP_VERIFY"),
        )?;
        let require_epoch_evidence = truthy_env("OPENAPI_OPE_REQUIRE_EPOCH_EVIDENCE");
        match opt_env("OPENAPI_ENGINE_IDENTITY_PINS_JSON") {
            Some(pins_json) => {
                cfg.engine_identity_pins = EngineIdentityPins::parse_json(&pins_json)
                    .map_err(|e| GatewayOpeApiError::Config(e.to_string()))?;
                if cfg.engine_identity_pins.is_empty() && !require_epoch_evidence {
                    return Err(GatewayOpeApiError::Config(
                        "OPENAPI_ENGINE_IDENTITY_PINS_JSON must contain at least one engine".into(),
                    ));
                }
            }
            None if require_epoch_evidence => {}
            None => {
                return Err(GatewayOpeApiError::Config(
                    "OPENAPI_ENGINE_IDENTITY_PINS_JSON required unless OPENAPI_OPE_REQUIRE_EPOCH_EVIDENCE=1"
                        .into(),
                ));
            }
        }
        cfg.epoch_clock_skew = duration_secs_from_env("OPENAPI_OPE_EPOCH_CLOCK_SKEW_SEC", 300);
        cfg.recipient_policy = EngineRecipientPolicy {
            identity_pins: cfg.engine_identity_pins.clone(),
            launch_digest_allowlist: EngineRecipientPolicy::parse_launch_digest_allowlist(
                &opt_env("OPENAPI_ENGINE_LAUNCH_DIGEST_ALLOWLIST").unwrap_or_default(),
            ),
            require_epoch_evidence,
            require_launch_digest: truthy_env("OPENAPI_OPE_REQUIRE_ENGINE_LAUNCH_DIGEST"),
            epoch_clock_skew_ms: u64::try_from(cfg.epoch_clock_skew.as_millis())
                .unwrap_or(u64::MAX),
        };
        let profile = openapi_platform::load_edge_profile()
            .map_err(|e| GatewayOpeApiError::Config(e.to_string()))?;
        cfg.validate_for_profile(profile)?;
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
        // Shared audited PEM/path load + cert/key pairing (attested-mtls TCB). On SGX we
        // additionally reject path-based PEM below (std::fs is unsupported on Fortanix EDP).
        let loaded = attested_mtls::load_openapi_client_tls_from_parts(
            &base_url.into(),
            client_cert_pem.as_deref(),
            client_key_pem.as_deref(),
            ca_pem.as_deref(),
            insecure_skip_verify,
        )
        .map_err(|e| GatewayOpeApiError::Config(e.to_string()))?;

        require_ip_https_base_url(&loaded.base_url)?;
        for (name, raw, loaded_pem) in [
            (
                "OPENAPI_GATEWAY_OPE_API_TLS_CLIENT_CERT_PEM",
                client_cert_pem.as_deref(),
                loaded.client_cert_pem.as_deref(),
            ),
            (
                "OPENAPI_GATEWAY_OPE_API_TLS_CLIENT_KEY_PEM",
                client_key_pem.as_deref(),
                loaded.client_key_pem.as_deref(),
            ),
            (
                "OPENAPI_GATEWAY_OPE_API_TLS_CA_PEM",
                ca_pem.as_deref(),
                loaded.ca_pem.as_deref(),
            ),
        ] {
            if loaded_pem.is_some() && !raw.unwrap_or_default().trim().contains("-----BEGIN") {
                return Err(GatewayOpeApiError::Config(format!(
                    "{name} must be inline PEM (-----BEGIN...) on SGX; path-based PEM is \
                     unsupported (std::fs disabled on Fortanix EDP)"
                )));
            }
        }

        Ok(Self {
            base_url: loaded.base_url,
            token: token.filter(|s| !s.is_empty()),
            client_cert_pem: loaded.client_cert_pem,
            client_key_pem: loaded.client_key_pem,
            ca_pem: loaded.ca_pem,
            insecure_skip_verify: loaded.insecure_skip_verify,
            connect_timeout: Duration::from_secs(10),
            // Match gateway TEECHAT_OPE_UPSTREAM_TIMEOUT_MS default (5m). Override via
            // OPENAPI_GATEWAY_OPE_API_READ_TIMEOUT_SECS.
            read_timeout: duration_secs_from_env("OPENAPI_GATEWAY_OPE_API_READ_TIMEOUT_SECS", 300),
            engine_identity_pins: EngineIdentityPins::default(),
            epoch_clock_skew: Duration::from_secs(300),
            recipient_policy: EngineRecipientPolicy {
                epoch_clock_skew_ms: 300_000,
                ..Default::default()
            },
        })
    }

    /// Reject `INSECURE_SKIP_VERIFY` in prod (OPE-006) and enforce `https://IP:port` always
    /// (SGX has no clear-text F′ path; use `OPENAPI_UPSTREAM_CLEAR_HTTP` to bypass OPE instead).
    pub fn validate_for_profile(&self, profile: EdgeProfile) -> Result<(), GatewayOpeApiError> {
        if self.insecure_skip_verify && profile.is_prod() {
            return Err(GatewayOpeApiError::Config(
                "OPENAPI_GATEWAY_OPE_API_TLS_INSECURE_SKIP_VERIFY forbidden when OPENAPI_PROFILE=prod"
                    .into(),
            ));
        }
        if profile.is_prod()
            && self.engine_identity_pins.is_empty()
            && !self.recipient_policy.require_epoch_evidence
        {
            return Err(GatewayOpeApiError::Config(
                "OPENAPI_ENGINE_IDENTITY_PINS_JSON required in prod unless OPENAPI_OPE_REQUIRE_EPOCH_EVIDENCE=1"
                    .into(),
            ));
        }
        if self.recipient_policy.require_launch_digest
            && self.recipient_policy.launch_digest_allowlist.is_empty()
        {
            return Err(GatewayOpeApiError::Config(
                "OPENAPI_ENGINE_LAUNCH_DIGEST_ALLOWLIST required when OPENAPI_OPE_REQUIRE_ENGINE_LAUNCH_DIGEST=1"
                    .into(),
            ));
        }
        require_ip_https_base_url(&self.base_url)?;
        Ok(())
    }
}

/// Enforce `https://IP:port` — no DNS resolver in the enclave, no clear-text F′ dial.
fn require_ip_https_base_url(base_url: &str) -> Result<(), GatewayOpeApiError> {
    parse_https_ip_endpoint(base_url).map(|_| ())
}

fn parse_https_ip_endpoint(base_url: &str) -> Result<(String, u16), GatewayOpeApiError> {
    let url = base_url.trim().trim_end_matches('/');
    let rest = url.strip_prefix("https://").ok_or_else(|| {
        GatewayOpeApiError::Config(
            "OPENAPI_GATEWAY_OPE_API_URL must be https://IP:port (SGX: no DNS in enclave, \
             no clear-text F' dial)"
                .into(),
        )
    })?;
    let (host, port_str) = rest.rsplit_once(':').ok_or_else(|| {
        GatewayOpeApiError::Config(
            "OPENAPI_GATEWAY_OPE_API_URL must include an explicit port".into(),
        )
    })?;
    let port: u16 = port_str.parse().map_err(|_| {
        GatewayOpeApiError::Config(format!(
            "invalid port in OPENAPI_GATEWAY_OPE_API_URL: {port_str}"
        ))
    })?;
    host.parse::<IpAddr>().map_err(|_| {
        GatewayOpeApiError::Config(format!(
            "OPENAPI_GATEWAY_OPE_API_URL host `{host}` must be a literal IP address (no DNS in SGX enclave)"
        ))
    })?;
    if host.is_empty() {
        return Err(GatewayOpeApiError::Config(
            "OPENAPI_GATEWAY_OPE_API_URL host is empty".into(),
        ));
    }
    Ok((host.to_string(), port))
}

/// Dialer for gateway F′ OPE API — raw `TcpStream` + rustls (no ureq, no aws-lc/ring on SGX).
///
/// Every call opens a fresh connection with `Connection: close` (no idle pooling): matches
/// CVM's `max_idle_connections(0)` intent — half-closed sockets after gateway VIP/TLS teardown
/// otherwise surface as client `502 socket hang up`.
#[derive(Clone)]
pub struct GatewayOpeApiClient {
    host: String,
    port: u16,
    token: Option<String>,
    tls_config: Arc<ClientConfig>,
    connect_timeout: Duration,
    read_timeout: Duration,
}

impl GatewayOpeApiClient {
    pub fn try_new(config: GatewayOpeApiConfig) -> Result<Self, GatewayOpeApiError> {
        let (host, port) = parse_https_ip_endpoint(&config.base_url)?;
        let tls_config = build_client_tls_config(&config)?;
        Ok(Self {
            host,
            port,
            token: config.token,
            tls_config,
            connect_timeout: config.connect_timeout,
            read_timeout: config.read_timeout,
        })
    }

    fn connect(&self) -> Result<StreamOwned<ClientConnection, TcpStream>, GatewayOpeApiError> {
        let ip: IpAddr = self
            .host
            .parse()
            .map_err(|_| GatewayOpeApiError::Config(format!("invalid host `{}`", self.host)))?;
        let addr = SocketAddr::new(ip, self.port);
        let tcp = TcpStream::connect_timeout(&addr, self.connect_timeout)
            .map_err(|e| GatewayOpeApiError::Transport(format!("connect {addr}: {e}")))?;
        let _ = tcp.set_read_timeout(Some(self.read_timeout));
        let _ = tcp.set_write_timeout(Some(self.connect_timeout));
        let _ = tcp.set_nodelay(true);
        let server_name = ServerName::try_from(self.host.as_str())
            .map_err(|e| GatewayOpeApiError::Tls(format!("server name: {e}")))?
            .to_owned();
        let conn = ClientConnection::new(self.tls_config.clone(), server_name)
            .map_err(|e| GatewayOpeApiError::Tls(e.to_string()))?;
        Ok(StreamOwned::new(conn, tcp))
    }

    fn auth_headers(&self) -> Vec<(String, String)> {
        match &self.token {
            Some(tok) => vec![("Authorization".into(), format!("Bearer {tok}"))],
            None => Vec::new(),
        }
    }

    fn exec(
        &self,
        method: &str,
        path: &str,
        headers: Vec<(String, String)>,
        body: Option<&[u8]>,
    ) -> Result<
        (
            u16,
            Vec<(String, String)>,
            FramedBodyReader<StreamOwned<ClientConnection, TcpStream>>,
        ),
        GatewayOpeApiError,
    > {
        let mut stream = self.connect()?;
        write_request(&mut stream, &self.host, method, path, &headers, body)?;
        let (status, headers_text, framing) = read_response_headers(&mut stream)
            .map_err(|e| GatewayOpeApiError::Transport(e.to_string()))?;
        let header_pairs = parse_header_pairs(&headers_text);
        Ok((status, header_pairs, FramedBodyReader::new(stream, framing)))
    }

    fn exec_buffered(
        &self,
        method: &str,
        path: &str,
        headers: Vec<(String, String)>,
        body: Option<&[u8]>,
    ) -> Result<(u16, String), GatewayOpeApiError> {
        let (status, _headers, mut reader) = self.exec(method, path, headers, body)?;
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .map_err(|e| GatewayOpeApiError::Transport(format!("read body: {e}")))?;
        Ok((status, String::from_utf8_lossy(&buf).into_owned()))
    }

    /// `GET /v1/ope/api/health`
    pub fn health(&self) -> Result<HealthResponse, GatewayOpeApiError> {
        let (status, text) = self.exec_buffered("GET", HEALTH_PATH, self.auth_headers(), None)?;
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
        let mut path = INVENTORY_PATH.to_string();
        if !ks.is_empty() {
            path.push_str(&format!("?key_set={}", urlencoding_minimal(ks)));
        }
        let (status, text) = self.exec_buffered("GET", &path, self.auth_headers(), None)?;
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
        let body =
            serde_json::to_vec(req).map_err(|e| GatewayOpeApiError::Decode(e.to_string()))?;
        let mut headers = self.auth_headers();
        headers.push(("Content-Type".into(), "application/json".into()));
        let (status, text) = self.exec_buffered("POST", PREASSIGN_PATH, headers, Some(&body))?;
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
        let mut headers = self.auth_headers();
        headers.push(("Content-Type".into(), "application/json".into()));
        headers.push((HEADER_ENGINE_ID.into(), req.engine_id.trim().to_string()));
        if let Some(cid) = req
            .conversation_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            headers.push((HEADER_CONVERSATION_ID.into(), cid.to_string()));
        }
        if let Some(epoch) = req
            .ephemeral_epoch
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            headers.push((HEADER_EPHEMERAL_EPOCH.into(), epoch.to_string()));
        } else {
            headers.push((HEADER_EPHEMERAL_EPOCH.into(), "0".into()));
        }
        if let Some(key_id) = req
            .openapi_key_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            headers.push((HEADER_OPENAPI_KEY_ID.into(), key_id.to_string()));
        }
        if let Some(assign_id) = req
            .assign_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            headers.push((HEADER_ASSIGN_ID.into(), assign_id.to_string()));
        }

        let (status, headers_out, reader) =
            self.exec("POST", DISPATCH_PATH, headers, Some(&req.body))?;
        Ok((status, headers_out, Box::new(reader)))
    }
}

fn write_request(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Result<(), GatewayOpeApiError> {
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
    for (k, v) in headers {
        req.push_str(k);
        req.push_str(": ");
        req.push_str(v);
        req.push_str("\r\n");
    }
    if let Some(b) = body {
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("Connection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| GatewayOpeApiError::Transport(e.to_string()))?;
    if let Some(b) = body {
        stream
            .write_all(b)
            .map_err(|e| GatewayOpeApiError::Transport(e.to_string()))?;
    }
    stream
        .flush()
        .map_err(|e| GatewayOpeApiError::Transport(e.to_string()))
}

fn parse_header_pairs(headers_text: &str) -> Vec<(String, String)> {
    headers_text
        .lines()
        .skip(1) // status line
        .filter_map(|l| {
            let l = l.trim_end_matches('\r');
            let (k, v) = l.split_once(':')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

/// Incremental HTTP/1.1 body reader honoring `BodyFraming` over an arbitrary `Read`
/// (self-contained: `openapi_core::http1_body`'s chunked/content-length copiers are
/// one-shot `copy_body` helpers, not a streaming `Read` impl — this crate needs the
/// latter for `dispatch_reader`'s SSE/ndjson bridging).
struct FramedBodyReader<R: Read> {
    inner: R,
    state: FramedState,
}

enum FramedState {
    ContentLength(usize),
    UntilClose,
    Chunked { remaining: usize, done: bool },
}

impl<R: Read> FramedBodyReader<R> {
    fn new(inner: R, framing: BodyFraming) -> Self {
        let state = match framing {
            BodyFraming::ContentLength(n) => FramedState::ContentLength(n),
            BodyFraming::UntilClose => FramedState::UntilClose,
            BodyFraming::Chunked => FramedState::Chunked {
                remaining: 0,
                done: false,
            },
        };
        Self { inner, state }
    }
}

impl<R: Read> Read for FramedBodyReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        match &mut self.state {
            FramedState::ContentLength(remaining) => {
                if *remaining == 0 {
                    return Ok(0);
                }
                let cap = buf.len().min(*remaining);
                let n = self.inner.read(&mut buf[..cap])?;
                *remaining -= n;
                Ok(n)
            }
            FramedState::UntilClose => self.inner.read(buf),
            FramedState::Chunked { remaining, done } => {
                if *done {
                    return Ok(0);
                }
                if *remaining == 0 {
                    let size = read_chunk_size(&mut self.inner)?;
                    if size == 0 {
                        consume_line(&mut self.inner)?; // trailing CRLF after "0"
                        *done = true;
                        return Ok(0);
                    }
                    *remaining = size;
                }
                let cap = buf.len().min(*remaining);
                let n = self.inner.read(&mut buf[..cap])?;
                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "upstream closed mid-chunk",
                    ));
                }
                *remaining -= n;
                if *remaining == 0 {
                    consume_line(&mut self.inner)?; // CRLF terminating this chunk's data
                }
                Ok(n)
            }
        }
    }
}

fn read_line_bytes<R: Read>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = r.read(&mut byte)?;
        if n == 0 {
            break;
        }
        line.push(byte[0]);
        if line.len() >= 2 && line[line.len() - 2..] == *b"\r\n" {
            line.truncate(line.len() - 2);
            break;
        }
        if line.len() > 8192 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "chunk header line too long",
            ));
        }
    }
    Ok(line)
}

fn read_chunk_size<R: Read>(r: &mut R) -> std::io::Result<usize> {
    let line = read_line_bytes(r)?;
    let s = String::from_utf8_lossy(&line);
    let size_str = s.split(';').next().unwrap_or("").trim();
    usize::from_str_radix(size_str, 16).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid chunk size: {e}"),
        )
    })
}

fn consume_line<R: Read>(r: &mut R) -> std::io::Result<()> {
    let _ = read_line_bytes(r)?;
    Ok(())
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
    pub identity_signature: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PreassignTrustCpuTee {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub quote: String,
}

/// Engine attestation relayed with the preassignment (RB-46). Only the CPU
/// quote is read: it is what recipient trust is re-derived from.
#[derive(Debug, Clone, Deserialize)]
pub struct PreassignTrustAttestation {
    #[serde(default)]
    pub cpu_tee: Option<PreassignTrustCpuTee>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PreassignTrust {
    pub engine_id: String,
    pub epoch_id: String,
    pub not_before: String,
    pub not_after: String,
    pub hybrid: PreassignTrustHybrid,
    pub identity: PreassignTrustIdentity,
    /// Absent from gateways predating RB-46.
    #[serde(default)]
    pub attestation: Option<PreassignTrustAttestation>,
}

impl PreassignTrust {
    /// The SEV-SNP quote the epoch keys must be found in, when one was relayed.
    pub fn cpu_quote(&self) -> Option<&str> {
        self.attestation
            .as_ref()?
            .cpu_tee
            .as_ref()
            .map(|c| c.quote.trim())
            .filter(|q| !q.is_empty())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PreassignResponse {
    pub assign_id: String,
    pub engine_id: String,
    pub engine_set: String,
    pub key_set: String,
    pub openapi_key_id: String,
    pub expires_at_ms: u64,
    pub ttl_ms: u64,
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

/// EDP: `rustls-rustcrypto` (never ring/aws-lc-rs — `#UD` inside Fortanix enclaves).
/// Host (`cargo check` on non-sgx targets): `aws-lc-rs`, matching `TlsConfig::install_crypto_provider`.
#[cfg(target_env = "sgx")]
fn client_crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls_rustcrypto::provider())
}

#[cfg(not(target_env = "sgx"))]
fn client_crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn build_client_tls_config(
    config: &GatewayOpeApiConfig,
) -> Result<Arc<ClientConfig>, GatewayOpeApiError> {
    let provider = client_crypto_provider();
    let algorithms = provider.signature_verification_algorithms;
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| GatewayOpeApiError::Tls(e.to_string()))?;

    let builder = if config.insecure_skip_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerify { algorithms }))
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
    rustls_pemfile::certs(&mut std::io::Cursor::new(pem))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| GatewayOpeApiError::Tls(format!("parse cert PEM: {e}")))
}

fn load_private_key_pem(pem: &[u8]) -> Result<PrivateKeyDer<'static>, GatewayOpeApiError> {
    rustls_pemfile::private_key(&mut std::io::Cursor::new(pem))
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
struct SkipServerVerify {
    algorithms: WebPkiSupportedAlgorithms,
}

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
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(all(test, not(target_env = "sgx")))]
mod tests {
    use super::*;
    use std::fs;
    use std::thread;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn ensure_crypto() {
        // Owned `CryptoProvider` (not the `Arc` from `client_crypto_provider()`) — `install_default`
        // takes `self` by value. Mirrors `TlsConfig::install_crypto_provider`'s target split.
        #[cfg(target_env = "sgx")]
        let _ = rustls_rustcrypto::provider().install_default();
        #[cfg(not(target_env = "sgx"))]
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
            "OPENAPI_ENGINE_IDENTITY_PINS_JSON",
            "OPENAPI_OPE_EPOCH_CLOCK_SKEW_SEC",
            "OPENAPI_PROFILE",
        ] {
            std::env::remove_var(k);
        }
        std::env::set_var("OPENAPI_PROFILE", "dev");
        std::env::set_var(
            "OPENAPI_ENGINE_IDENTITY_PINS_JSON",
            r#"{"eng-1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
        );
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
    fn rejects_dns_name_host() {
        let _g = env_lock();
        clear_ope_env();
        std::env::set_var(
            "OPENAPI_GATEWAY_OPE_API_URL",
            "https://gateway.example.com:8791",
        );
        let err = GatewayOpeApiConfig::from_env().unwrap_err();
        assert!(matches!(err, GatewayOpeApiError::Config(_)));
        let msg = err.to_string();
        assert!(msg.contains("literal IP"), "{msg}");
        clear_ope_env();
    }

    #[test]
    fn rejects_clear_http_url() {
        let _g = env_lock();
        clear_ope_env();
        std::env::set_var("OPENAPI_GATEWAY_OPE_API_URL", "http://10.0.0.2:8791");
        let err = GatewayOpeApiConfig::from_env().unwrap_err();
        assert!(matches!(err, GatewayOpeApiError::Config(_)));
        clear_ope_env();
    }

    #[test]
    fn rejects_path_based_pem_on_sgx() {
        let _g = env_lock();
        clear_ope_env();
        let dir = std::env::temp_dir().join(format!("ope-api-sgx-pem-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("client.crt");
        let key_path = dir.join("client.key");
        fs::write(
            &cert_path,
            "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        fs::write(
            &key_path,
            "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();

        std::env::set_var("OPENAPI_GATEWAY_OPE_API_URL", "https://127.0.0.1:8791");
        std::env::set_var(
            "OPENAPI_GATEWAY_OPE_API_TLS_CLIENT_CERT_PEM",
            cert_path.to_str().unwrap(),
        );
        std::env::set_var(
            "OPENAPI_GATEWAY_OPE_API_TLS_CLIENT_KEY_PEM",
            key_path.to_str().unwrap(),
        );
        let err = GatewayOpeApiConfig::from_env().unwrap_err();
        assert!(matches!(err, GatewayOpeApiError::Config(_)));
        assert!(err.to_string().contains("inline PEM"), "{err}");

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

    fn serve_dispatch_once(fixtures: &MtlsFixtures) -> String {
        let (server_certs, server_key, client_ca) = fixtures.server_material();
        let mut root = RootCertStore::empty();
        root.add(client_ca).unwrap();
        let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root))
            .build()
            .expect("client verifier");
        let server_config = rustls::ServerConfig::builder_with_provider(client_crypto_provider())
            .with_protocol_versions(&[&TLS13])
            .expect("protocol versions")
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(server_certs, server_key)
            .expect("server config");
        let server_config = Arc::new(server_config);

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        thread::spawn(move || {
            let (tcp, _) = listener.accept().expect("accept");
            tcp.set_read_timeout(Some(Duration::from_secs(5))).ok();
            tcp.set_write_timeout(Some(Duration::from_secs(5))).ok();
            let conn = rustls::ServerConnection::new(server_config).expect("conn");
            let mut tls = StreamOwned::new(conn, tcp);
            let req = read_full_request(&mut tls);
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
            let _ = tls.write_all(resp.as_bytes());
            let _ = tls.flush();
        });
        format!("https://{addr}")
    }

    fn read_full_request(stream: &mut impl Read) -> String {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            let n = stream.read(&mut tmp).expect("read");
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(header_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = std::str::from_utf8(&buf[..header_end]).unwrap_or("");
                let content_len = headers
                    .lines()
                    .find_map(|l| {
                        let l = l.to_ascii_lowercase();
                        l.strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                if buf.len() >= header_end + 4 + content_len {
                    break;
                }
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[test]
    fn mtls_dispatch_against_local_rustls_server() {
        ensure_crypto();
        let fixtures = MtlsFixtures::generate();
        let base = serve_dispatch_once(&fixtures);
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
            use std::net::{IpAddr as StdIpAddr, Ipv4Addr};

            let ca_key = rcgen::KeyPair::generate().unwrap();
            let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let ca_cert = ca_params.self_signed(&ca_key).unwrap();
            let ca_pem = ca_cert.pem();

            let server_key = rcgen::KeyPair::generate().unwrap();
            let mut server_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            server_params.subject_alt_names = vec![
                SanType::IpAddress(StdIpAddr::V4(Ipv4Addr::LOCALHOST)),
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

        fn server_material(
            &self,
        ) -> (
            Vec<CertificateDer<'static>>,
            PrivateKeyDer<'static>,
            CertificateDer<'static>,
        ) {
            let certs = load_certs_pem(self.server_cert_pem.as_bytes()).unwrap();
            let key = load_private_key_pem(self.server_key_pem.as_bytes()).unwrap();
            (certs, key, self.client_ca_der.clone())
        }
    }
}
