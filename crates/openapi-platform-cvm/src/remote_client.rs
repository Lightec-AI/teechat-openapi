use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use openapi_core::authz::SignedAuthz;
use openapi_core::error::ApiError;
use openapi_core::remote_auth::L0AuthorizeClient;

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
        let resp = self
            .agent
            .post(&self.authorize_url)
            .set("Authorization", &auth_header)
            .set("Content-Type", "application/json")
            .send_bytes(&body_bytes)
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
