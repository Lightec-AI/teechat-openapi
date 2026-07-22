//! Platform abstraction for Edge KMS deployments (CVM guest or SGX enclave).
//!
//! TLS sealing summary: repo `SECURITY.md`.
//! Attestation challenge binding: `docs/attestation-challenge.md`.

mod challenge;
mod edge_policy;
mod profile;
mod seal;
pub mod tls;

use std::path::Path;

pub use challenge::{
    build_preimage_v1, build_report_data_v1, canonicalize_digest_field, canonicalize_edge_identity,
    report_data_matches_v1, sgx_dcap_quote_reportdata, sgx_report_reportdata,
    snp_report_reportdata, verify_challenge_report_data, AttestationChallengeResponse,
    ChallengeBindError, QuoteFormat, CHALLENGE_MAGIC, CHALLENGE_NONCE_LEN, REPORT_DATA_LEN,
    REPORT_DATA_VERSION, SCHEMA_VERSION, SGX_DCAP_QUOTE3_HEADER_LEN, SGX_DCAP_REPORT_DATA_OFFSET,
    SGX_REPORT_DATA_OFFSET, SNP_REPORT_DATA_OFFSET,
};
pub use edge_policy::{
    edge_runtime_policy_from_parts, EdgeRuntimePolicy,
};
pub use profile::{
    assert_dev_host_seal_tool, load_edge_profile, validate_tls_key_policy, EdgeProfile,
    ProfileError,
};
pub use seal::{
    derive_cvm_seal_root, derive_seal_key, measurement_binding_label, seal_tls_private_key,
    seal_tls_private_key_amd_sp, unseal_tls_private_key, unseal_tls_private_key_amd_sp,
    AmdSpSealMeta, SealedTlsKeyBlob, AMD_SP_GFS_GUEST_POLICY_MEASUREMENT, SEAL_AAD, SEAL_AAD_V3,
    SEAL_VERSION, SEAL_VERSION_SGX_EGETKEY, SEAL_VERSION_SNP_AMD_SP,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Measurement {
    Mrenclave {
        value: String,
    },
    LaunchDigest {
        launch_digest: String,
        image_digest: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EdgeIdentity {
    pub build_version: String,
    pub code_hash: String,
    pub measurement: Measurement,
    pub tls_cert_spki_sha256: String,
    /// SHA-256 of [`EdgeRuntimePolicy`] JSON (allowlist pin). Not in `report_data` v1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
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
