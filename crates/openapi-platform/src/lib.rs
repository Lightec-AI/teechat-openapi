//! Platform abstraction for Edge KMS deployments (CVM guest or SGX enclave).

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Measurement {
    Mrenclave { value: String },
    LaunchDigest {
        launch_digest: String,
        image_digest: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeIdentity {
    pub build_version: String,
    pub code_hash: String,
    pub measurement: Measurement,
    pub tls_cert_spki_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationChallengeResponse {
    pub edge: EdgeIdentity,
    pub challenge_nonce_b64: String,
    /// Platform-specific quote bytes (hex or base64), when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quote_b64: Option<String>,
}

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("attestation failed: {0}")]
    Attestation(String),
    #[error("seal failed: {0}")]
    Seal(String),
    #[error("io: {0}")]
    Io(String),
}

pub trait AttestationPlatform: Send + Sync {
    fn identity(&self) -> &EdgeIdentity;

    fn challenge(&self, nonce: &[u8]) -> Result<AttestationChallengeResponse, PlatformError>;
}

pub trait UsageSigningKey: Send + Sync {
    fn sign(&self, message: &[u8]) -> [u8; 64];

    fn public_key_bytes(&self) -> [u8; 32];
}
