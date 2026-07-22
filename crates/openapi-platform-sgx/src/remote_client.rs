//! Outbound L0 authorize + revocation poll over plain TCP (Fortanix EDP).

use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use openapi_core::authz::{SignedAuthz, SignedRevocation};
use openapi_core::error::ApiError;
use openapi_core::http1_body::{copy_body, read_response_headers};
use openapi_core::remote_auth::{L0AuthorizeClient, RevocationDelta, DEFAULT_REVOKE_POLL_SECS};
use tracing::warn;

use crate::upstream::HttpEndpoint;

#[derive(Debug, Clone)]
pub struct TcpL0Client {
    authorize: HttpEndpoint,
    authorize_path: String,
    revocations: HttpEndpoint,
    revocations_path: String,
    internal_token: String,
}

impl TcpL0Client {
    pub fn new(
        authorize_url: &str,
        revocations_url: Option<&str>,
        internal_token: String,
    ) -> Result<Self, ApiError> {
        let (authorize, authorize_path) = parse_http_url_with_path(authorize_url)?;
        let rev_url = revocations_url
            .map(str::to_string)
            .unwrap_or_else(|| revocations_url_from_authorize(authorize_url));
        let (revocations, revocations_path) = parse_http_url_with_path(&rev_url)?;
        Ok(Self {
            authorize,
            authorize_path,
            revocations,
            revocations_path,
            internal_token,
        })
    }

    fn exchange(
        &self,
        endpoint: &HttpEndpoint,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>), ApiError> {
        let addr = format!("{}:{}", endpoint.host, endpoint.port);
        let mut stream = TcpStream::connect(&addr)
            .map_err(|e| ApiError::Internal(format!("l0 connect {addr}: {e}")))?;
        let auth = format!("Bearer {}", self.internal_token);
        let req = if let Some(body) = body {
            format!(
                "{method} {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: {auth}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                endpoint.host,
                body.len()
            )
        } else {
            format!(
                "{method} {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: {auth}\r\nConnection: close\r\n\r\n",
                endpoint.host
            )
        };
        stream
            .write_all(req.as_bytes())
            .map_err(|e| ApiError::Internal(format!("l0 write: {e}")))?;
        if let Some(body) = body {
            stream
                .write_all(body)
                .map_err(|e| ApiError::Internal(format!("l0 write body: {e}")))?;
        }
        stream
            .flush()
            .map_err(|e| ApiError::Internal(format!("l0 flush: {e}")))?;
        let (status, _headers, framing) = read_response_headers(&mut stream)
            .map_err(|e| ApiError::Internal(format!("l0 headers: {e}")))?;
        let mut body_out = Vec::new();
        let mut buf = [0u8; 8192];
        copy_body(&mut stream, &framing, &mut body_out, &mut buf)
            .map_err(|e| ApiError::Internal(format!("l0 body: {e}")))?;
        Ok((status, body_out))
    }
}

/// Parse `http://host:port/path` (path optional). Rejects HTTPS / missing port.
fn parse_http_url_with_path(url: &str) -> Result<(HttpEndpoint, String), ApiError> {
    let url = url.trim();
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        ApiError::BadRequest("l0 url must be http://IP:port/path (no TLS, no DNS)".into())
    })?;
    let (authority, path) = match rest.split_once('/') {
        Some((auth, p)) => (auth, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let (host, port_s) = authority
        .split_once(':')
        .ok_or_else(|| ApiError::BadRequest("l0 url must include explicit port".into()))?;
    if host.is_empty() {
        return Err(ApiError::BadRequest("l0 host empty".into()));
    }
    let port: u16 = port_s
        .parse()
        .map_err(|e| ApiError::BadRequest(format!("l0 port: {e}")))?;
    let path = if path.is_empty() { "/".into() } else { path };
    Ok((
        HttpEndpoint {
            host: host.to_string(),
            port,
        },
        path,
    ))
}

fn revocations_url_from_authorize(authorize_url: &str) -> String {
    if let Some(base) = authorize_url.strip_suffix("/authorize") {
        format!("{base}/revocations")
    } else if authorize_url.ends_with('/') {
        format!("{authorize_url}revocations")
    } else {
        format!("{authorize_url}/revocations")
    }
}

impl L0AuthorizeClient for TcpL0Client {
    fn authorize(&self, key_id: &str, key_hash_hex: &str) -> Result<SignedAuthz, ApiError> {
        let body = serde_json::to_vec(&serde_json::json!({
            "key_id": key_id,
            "key_hash_hex": key_hash_hex,
        }))
        .map_err(|e| ApiError::Internal(e.to_string()))?;
        let (status, bytes) =
            self.exchange(&self.authorize, "POST", &self.authorize_path, Some(&body))?;
        if status == 401 || status == 404 {
            return Err(ApiError::Unauthorized);
        }
        if status >= 400 {
            return Err(ApiError::Internal(format!("l0 authorize status {status}")));
        }
        serde_json::from_slice(&bytes)
            .map_err(|e| ApiError::Internal(format!("l0 authorize json: {e}")))
    }

    fn fetch_revocations(&self, since_epoch: u64) -> Result<RevocationDelta, ApiError> {
        let path = if self.revocations_path.contains('?') {
            format!("{}&since_epoch={since_epoch}", self.revocations_path)
        } else {
            format!("{}?since_epoch={since_epoch}", self.revocations_path)
        };
        let (status, bytes) = self.exchange(&self.revocations, "GET", &path, None)?;
        if status >= 400 {
            return Err(ApiError::Internal(format!(
                "l0 revocations status {status}"
            )));
        }
        #[derive(serde::Deserialize)]
        struct Wire {
            epoch: u64,
            #[serde(default)]
            revocations: Vec<SignedRevocation>,
        }
        let wire: Wire = serde_json::from_slice(&bytes)
            .map_err(|e| ApiError::Internal(format!("l0 revocations json: {e}")))?;
        Ok(RevocationDelta {
            epoch: wire.epoch,
            revocations: wire.revocations,
        })
    }
}

pub fn build_remote_authenticator(
    verify_key_hex: &str,
    authorize_url: &str,
    revocations_url: Option<&str>,
    internal_token: String,
    poll_secs: Option<u64>,
) -> Result<openapi_core::remote_auth::RemoteAuthenticator, ApiError> {
    let verify_bytes = hex::decode(verify_key_hex)
        .map_err(|e| ApiError::Internal(format!("catalog verify hex: {e}")))?;
    let verify_key = VerifyingKey::from_bytes(
        verify_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ApiError::Internal("catalog verify must be 32 bytes".into()))?,
    )
    .map_err(|e| ApiError::Internal(format!("catalog verify key: {e}")))?;
    let client = Arc::new(TcpL0Client::new(
        authorize_url,
        revocations_url,
        internal_token,
    )?);
    let interval = Duration::from_secs(poll_secs.unwrap_or(DEFAULT_REVOKE_POLL_SECS).max(1));
    Ok(
        openapi_core::remote_auth::RemoteAuthenticator::with_poll_interval(
            verify_key, client, interval,
        ),
    )
}

pub fn spawn_revocation_poller(remote: Arc<openapi_core::remote_auth::RemoteAuthenticator>) {
    std::thread::Builder::new()
        .name("openapi-revoke-poll".into())
        .spawn(move || loop {
            remote.poll_clock().wait_until_due();
            match remote.sync_revocations_from_l0() {
                Ok(n) if n > 0 => {
                    tracing::info!(
                        applied = n,
                        epoch = remote.local_epoch(),
                        "revocation poll applied"
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    warn!(error = %e, "revocation poll failed");
                    remote.poll_clock().reset();
                }
            }
        })
        .expect("spawn revocation poller");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_authorize_url_with_path() {
        let (ep, path) =
            parse_http_url_with_path("http://10.0.0.1:8787/internal/openapi/v1/authorize").unwrap();
        assert_eq!(ep.host, "10.0.0.1");
        assert_eq!(ep.port, 8787);
        assert_eq!(path, "/internal/openapi/v1/authorize");
    }

    #[test]
    fn derives_revocations_url() {
        assert_eq!(
            revocations_url_from_authorize("http://gw:1/internal/openapi/v1/authorize"),
            "http://gw:1/internal/openapi/v1/revocations"
        );
    }
}
