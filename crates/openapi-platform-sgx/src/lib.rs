//! SGX (Fortanix EDP) platform backend.
//!
//! Production builds target `x86_64-fortanix-unknown-sgx`. This crate exposes the same
//! [`AttestationPlatform`] surface as the CVM backend; enclave-specific quote generation
//! is wired in `deploy/sgx/` once EDP CI is enabled.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use openapi_platform::{
    AttestationChallengeResponse, AttestationPlatform, EdgeIdentity, Measurement, PlatformError,
};

#[derive(Debug, Clone)]
pub struct SgxAttestationPlatform {
    identity: EdgeIdentity,
    /// Hex-encoded quote when running inside an enclave with attestation enabled.
    quote_hex: Option<String>,
}

impl SgxAttestationPlatform {
    pub fn new(identity: EdgeIdentity, quote_hex: Option<String>) -> Self {
        Self {
            identity,
            quote_hex,
        }
    }

    pub fn from_mrenclave(
        build_version: &str,
        code_hash: &str,
        mrenclave: &str,
        tls_spki_sha256: &str,
        quote_hex: Option<String>,
    ) -> Self {
        Self::new(
            EdgeIdentity {
                build_version: build_version.to_string(),
                code_hash: code_hash.to_string(),
                measurement: Measurement::Mrenclave {
                    value: mrenclave.to_string(),
                },
                tls_cert_spki_sha256: tls_spki_sha256.to_string(),
            },
            quote_hex,
        )
    }
}

impl AttestationPlatform for SgxAttestationPlatform {
    fn identity(&self) -> &EdgeIdentity {
        &self.identity
    }

    fn challenge(&self, nonce: &[u8]) -> Result<AttestationChallengeResponse, PlatformError> {
        Ok(AttestationChallengeResponse {
            edge: self.identity.clone(),
            challenge_nonce_b64: URL_SAFE_NO_PAD.encode(nonce),
            quote_b64: self.quote_hex.as_ref().map(|q| {
                base64::engine::general_purpose::STANDARD.encode(hex::decode(q).unwrap_or_default())
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sgx_challenge_uses_mrenclave() {
        let p = SgxAttestationPlatform::from_mrenclave(
            "0.1.0",
            "hash",
            "deadbeef",
            "spki",
            None,
        );
        let resp = p.challenge(&[0u8; 32]).unwrap();
        match resp.edge.measurement {
            Measurement::Mrenclave { value } => assert_eq!(value, "deadbeef"),
            _ => panic!("expected mrenclave"),
        }
    }
}
