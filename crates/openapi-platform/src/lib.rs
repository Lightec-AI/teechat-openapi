//! Platform abstraction for Edge KMS deployments (CVM guest or SGX enclave).

mod seal;

use std::path::Path;

pub use seal::{
    measurement_binding_label, seal_tls_private_key, unseal_tls_private_key, SealedTlsKeyBlob,
    SEAL_AAD, SEAL_VERSION,
};

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

/// Binds TLS private key material to a TEE measurement (CVM launch digest or SGX MRENCLAVE).
pub trait Sealer: Send + Sync {
    fn sealing_measurement(&self) -> Measurement;

    fn seal_tls_key(
        &self,
        key_pem: &[u8],
        seal_root: Option<&[u8; 32]>,
    ) -> Result<SealedTlsKeyBlob, PlatformError> {
        seal_tls_private_key(&self.sealing_measurement(), key_pem, seal_root)
    }

    fn unseal_tls_key(
        &self,
        blob: &SealedTlsKeyBlob,
        seal_root: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>, PlatformError> {
        unseal_tls_private_key(blob, &self.sealing_measurement(), seal_root)
    }

    fn seal_tls_key_to_file(
        &self,
        key_pem: &[u8],
        path: &Path,
        seal_root: Option<&[u8; 32]>,
    ) -> Result<(), PlatformError> {
        let blob = self.seal_tls_key(key_pem, seal_root)?;
        let json = serde_json::to_vec_pretty(&blob)
            .map_err(|e| PlatformError::Seal(format!("encode blob: {e}")))?;
        std::fs::write(path, json).map_err(|e| PlatformError::Io(e.to_string()))?;
        Ok(())
    }

    fn unseal_tls_key_from_file(
        &self,
        path: &Path,
        seal_root: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>, PlatformError> {
        let raw = std::fs::read_to_string(path).map_err(|e| PlatformError::Io(e.to_string()))?;
        let blob: SealedTlsKeyBlob = serde_json::from_str(&raw)
            .map_err(|e| PlatformError::Seal(format!("parse blob: {e}")))?;
        self.unseal_tls_key(&blob, seal_root)
    }
}
