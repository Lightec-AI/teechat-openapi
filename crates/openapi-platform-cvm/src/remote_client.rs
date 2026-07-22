use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use openapi_core::authz::SignedAuthz;
use openapi_core::error::ApiError;
use openapi_core::remote_auth::{L0AuthorizeClient, RevocationDelta, DEFAULT_REVOKE_POLL_SECS};
use openapi_core::SignedRevocation;
use tracing::warn;
use ureq::OrAnyStatus;

#[derive(Debug, Clone)]
pub struct UreqL0AuthorizeClient {
    authorize_url: String,
    revocations_url: String,
    internal_token: String,
    agent: ureq::Agent,
}

fn l0_ureq_agent() -> ureq::Agent {
    // No idle keep-alive: half-closed pooled sockets to L0 admin caused intermittent
    // transport failures under gateway churn (same class as F′ CLOSE-WAIT/FIN-WAIT-2).
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(60))
        .max_idle_connections(0)
        .max_idle_connections_per_host(0)
        .build()
}

impl UreqL0AuthorizeClient {
    pub fn new(authorize_url: String, internal_token: String) -> Self {
        let revocations_url = revocations_url_from_authorize(&authorize_url);
        Self {
            authorize_url,
            revocations_url,
            internal_token,
            agent: l0_ureq_agent(),
        }
    }

    pub fn with_urls(
        authorize_url: String,
        revocations_url: String,
        internal_token: String,
    ) -> Self {
        Self {
            authorize_url,
            revocations_url,
            internal_token,
            agent: l0_ureq_agent(),
        }
    }
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

impl L0AuthorizeClient for UreqL0AuthorizeClient {
    fn authorize(&self, key_id: &str, key_hash_hex: &str) -> Result<SignedAuthz, ApiError> {
        let body = serde_json::json!({
            "key_id": key_id,
            "key_hash_hex": key_hash_hex,
        });
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| ApiError::Internal(format!("l0 authorize json encode: {e}")))?;
        let auth_header = format!("Bearer {}", self.internal_token);
        let resp = self
            .agent
            .post(&self.authorize_url)
            .set("Authorization", &auth_header)
            .set("Content-Type", "application/json")
            .send_bytes(&body_bytes)
            .or_any_status()
            .map_err(|e| ApiError::Internal(format!("l0 authorize transport: {e}")))?;
        let status = resp.status();
        if status == 401 || status == 404 {
            return Err(ApiError::Unauthorized);
        }
        if status >= 400 {
            return Err(ApiError::Internal(format!("l0 authorize status {status}")));
        }
        let text = resp
            .into_string()
            .map_err(|e| ApiError::Internal(format!("l0 authorize body: {e}")))?;
        serde_json::from_str(&text)
            .map_err(|e| ApiError::Internal(format!("l0 authorize json: {e}")))
    }

    fn fetch_revocations(&self, since_epoch: u64) -> Result<RevocationDelta, ApiError> {
        let url = format!(
            "{}{}since_epoch={}",
            self.revocations_url,
            if self.revocations_url.contains('?') {
                "&"
            } else {
                "?"
            },
            since_epoch
        );
        let auth_header = format!("Bearer {}", self.internal_token);
        let resp = self
            .agent
            .get(&url)
            .set("Authorization", &auth_header)
            .call()
            .or_any_status()
            .map_err(|e| ApiError::Internal(format!("l0 revocations transport: {e}")))?;
        let status = resp.status();
        if status >= 400 {
            return Err(ApiError::Internal(format!(
                "l0 revocations status {status}"
            )));
        }
        let text = resp
            .into_string()
            .map_err(|e| ApiError::Internal(format!("l0 revocations body: {e}")))?;
        #[derive(serde::Deserialize)]
        struct Wire {
            epoch: u64,
            #[serde(default)]
            revocations: Vec<SignedRevocation>,
        }
        let wire: Wire = serde_json::from_str(&text)
            .map_err(|e| ApiError::Internal(format!("l0 revocations json: {e}")))?;
        Ok(RevocationDelta {
            epoch: wire.epoch,
            revocations: wire.revocations,
        })
    }
}

#[allow(dead_code)]
pub fn build_remote_authenticator(
    verify_key_hex: &str,
    authorize_url: String,
    internal_token: String,
) -> Result<openapi_core::remote_auth::RemoteAuthenticator, ApiError> {
    build_remote_authenticator_ex(verify_key_hex, authorize_url, None, internal_token, None)
}

pub fn build_remote_authenticator_ex(
    verify_key_hex: &str,
    authorize_url: String,
    revocations_url: Option<String>,
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
    let client = Arc::new(match revocations_url {
        Some(r) => UreqL0AuthorizeClient::with_urls(authorize_url, r, internal_token),
        None => UreqL0AuthorizeClient::new(authorize_url, internal_token),
    });
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
    use openapi_core::remote_auth::L0AuthorizeClient;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn serve_once(status_line: &'static str, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        });
        format!("http://{addr}/internal/openapi/v1/authorize")
    }

    #[test]
    fn l0_404_maps_to_unauthorized_not_500() {
        let url = serve_once("404 Not Found", r#"{"error":"not_found"}"#);
        let client = UreqL0AuthorizeClient::new(url, "tok".into());
        let err = client
            .authorize("tcak_bad", "deadbeef")
            .expect_err("must fail");
        assert!(
            matches!(err, ApiError::Unauthorized),
            "expected Unauthorized, got {err:?} (status {})",
            err.status_code()
        );
        assert_eq!(err.status_code(), 401);
    }

    #[test]
    fn l0_401_maps_to_unauthorized() {
        let url = serve_once("401 Unauthorized", r#"{"error":"hash_mismatch"}"#);
        let client = UreqL0AuthorizeClient::new(url, "tok".into());
        let err = client
            .authorize("tcak_bad", "deadbeef")
            .expect_err("must fail");
        assert!(matches!(err, ApiError::Unauthorized));
        assert_eq!(err.status_code(), 401);
    }

    #[test]
    fn derives_revocations_url() {
        assert_eq!(
            revocations_url_from_authorize("http://gw/internal/openapi/v1/authorize"),
            "http://gw/internal/openapi/v1/revocations"
        );
    }
}
