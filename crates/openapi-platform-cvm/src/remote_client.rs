use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use openapi_core::authz::SignedAuthz;
use openapi_core::error::ApiError;
use openapi_core::remote_auth::L0AuthorizeClient;
use ureq::OrAnyStatus;

#[derive(Debug, Clone)]
pub struct UreqL0AuthorizeClient {
    authorize_url: String,
    internal_token: String,
    agent: ureq::Agent,
}

impl UreqL0AuthorizeClient {
    pub fn new(authorize_url: String, internal_token: String) -> Self {
        Self {
            authorize_url,
            internal_token,
            agent: ureq::Agent::new(),
        }
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
        // ureq returns non-2xx as Error::Status; accept any status so we can map 401/404 → Unauthorized.
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
        serde_json::from_str(&text).map_err(|e| ApiError::Internal(format!("l0 authorize json: {e}")))
    }
}

pub fn build_remote_authenticator(
    verify_key_hex: &str,
    authorize_url: String,
    internal_token: String,
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
    let client = Arc::new(UreqL0AuthorizeClient::new(authorize_url, internal_token));
    Ok(openapi_core::remote_auth::RemoteAuthenticator::new(
        verify_key,
        client,
    ))
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
        let err = client.authorize("tcak_bad", "deadbeef").expect_err("must fail");
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
        let err = client.authorize("tcak_bad", "deadbeef").expect_err("must fail");
        assert!(matches!(err, ApiError::Unauthorized));
        assert_eq!(err.status_code(), 401);
    }
}
