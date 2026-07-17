//! POST /v1/attestation/challenge helper.

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use openapi_platform::AttestationChallengeResponse;
use rand::RngCore;
use serde::Serialize;

use crate::error::{AttestError, Result};

#[derive(Debug, Serialize)]
struct ChallengeRequest {
    nonce_b64: String,
}

pub struct ChallengeOutcome {
    pub nonce: [u8; 32],
    pub response: AttestationChallengeResponse,
    pub endpoint: String,
}

pub fn generate_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

pub fn challenge_edge(base_url: &str, nonce: &[u8; 32]) -> Result<ChallengeOutcome> {
    let base = base_url.trim_end_matches('/');
    let url = format!("{base}/v1/attestation/challenge");
    let body = ChallengeRequest {
        nonce_b64: URL_SAFE_NO_PAD.encode(nonce),
    };
    let payload = serde_json::to_string(&body)
        .map_err(|e| AttestError::Challenge(format!("encode request: {e}")))?;
    let resp = ureq::post(&url)
        .set("Content-Type", "application/json")
        .set("Accept", "application/json")
        .send_string(&payload)
        .map_err(|e| AttestError::Http(format!("POST {url}: {e}")))?;
    let status = resp.status();
    let text = resp
        .into_string()
        .map_err(|e| AttestError::Http(e.to_string()))?;
    if status != 200 {
        return Err(AttestError::Challenge(format!(
            "HTTP {status}: {}",
            text.chars().take(240).collect::<String>()
        )));
    }
    let response: AttestationChallengeResponse = serde_json::from_str(&text)
        .map_err(|e| AttestError::Challenge(format!("decode response: {e}")))?;
    Ok(ChallengeOutcome {
        nonce: *nonce,
        response,
        endpoint: base.to_string(),
    })
}

pub fn quote_bytes(response: &AttestationChallengeResponse) -> Result<Vec<u8>> {
    STANDARD
        .decode(response.quote_b64.trim())
        .map_err(|e| AttestError::Quote(format!("quote_b64: {e}")))
}
