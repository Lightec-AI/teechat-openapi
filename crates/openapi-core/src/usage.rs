use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey, Verifier};
use openapi_platform::UsageSigningKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageReport {
    pub report_version: u32,
    pub key_id: String,
    pub model: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub timestamp_ms: u64,
    pub nonce_b64: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct UnsignedUsageReport {
    report_version: u32,
    key_id: String,
    model: String,
    prompt_tokens: u64,
    completion_tokens: u64,
    timestamp_ms: u64,
    nonce_b64: String,
}

pub struct UsageSigner {
    signing_key: SigningKey,
}

impl UsageSigner {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    pub fn sign_report(
        &self,
        key_id: &str,
        model: &str,
        prompt_tokens: u64,
        completion_tokens: u64,
        timestamp_ms: u64,
    ) -> Result<UsageReport, ApiError> {
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce);

        let unsigned = UnsignedUsageReport {
            report_version: 1,
            key_id: key_id.to_string(),
            model: model.to_string(),
            prompt_tokens,
            completion_tokens,
            timestamp_ms,
            nonce_b64: nonce_b64.clone(),
        };
        let payload =
            serde_json::to_vec(&unsigned).map_err(|e| ApiError::Internal(e.to_string()))?;
        let sig = self.signing_key.sign(&payload);
        Ok(UsageReport {
            report_version: unsigned.report_version,
            key_id: unsigned.key_id,
            model: unsigned.model,
            prompt_tokens: unsigned.prompt_tokens,
            completion_tokens: unsigned.completion_tokens,
            timestamp_ms: unsigned.timestamp_ms,
            nonce_b64,
            signature_hex: hex::encode(sig.to_bytes()),
        })
    }

    pub fn verify_report(
        report: &UsageReport,
        verify_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), ApiError> {
        let unsigned = UnsignedUsageReport {
            report_version: report.report_version,
            key_id: report.key_id.clone(),
            model: report.model.clone(),
            prompt_tokens: report.prompt_tokens,
            completion_tokens: report.completion_tokens,
            timestamp_ms: report.timestamp_ms,
            nonce_b64: report.nonce_b64.clone(),
        };
        let payload =
            serde_json::to_vec(&unsigned).map_err(|e| ApiError::Internal(e.to_string()))?;
        let sig_bytes = hex::decode(&report.signature_hex)
            .map_err(|e| ApiError::Internal(format!("usage sig hex: {e}")))?;
        let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)
            .map_err(|e| ApiError::Internal(format!("usage sig: {e}")))?;
        verify_key
            .verify(&payload, &signature)
            .map_err(|_| ApiError::Internal("usage signature invalid".into()))
    }
}

impl UsageSigningKey for UsageSigner {
    fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::VerifyingKey;

    #[test]
    fn usage_report_sign_verify() {
        let seed = [7u8; 32];
        let signer = UsageSigner::from_seed(seed);
        let report = signer
            .sign_report("k1", "gpt-test", 10, 20, 1_700_000_000_000)
            .unwrap();
        let vk = VerifyingKey::from_bytes(&signer.public_key_bytes()).unwrap();
        UsageSigner::verify_report(&report, &vk).unwrap();
    }

    #[test]
    fn tampered_usage_report_fails() {
        let seed = [8u8; 32];
        let signer = UsageSigner::from_seed(seed);
        let mut report = signer
            .sign_report("k1", "gpt-test", 10, 20, 1_700_000_000_000)
            .unwrap();
        report.completion_tokens += 1;
        let vk = VerifyingKey::from_bytes(&signer.public_key_bytes()).unwrap();
        assert!(UsageSigner::verify_report(&report, &vk).is_err());
    }
}
