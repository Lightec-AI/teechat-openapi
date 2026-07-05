use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use openapi_platform::{
    AttestationChallengeResponse, AttestationPlatform, EdgeIdentity, Measurement, PlatformError,
};

use crate::report;

#[derive(Debug, Clone)]
pub struct SgxAttestationPlatform {
    identity: EdgeIdentity,
}

impl SgxAttestationPlatform {
    pub fn new(identity: EdgeIdentity) -> Self {
        Self { identity }
    }

    pub fn from_env(
        build_version: &str,
        code_hash: &str,
        mrenclave: &str,
        tls_spki_sha256: &str,
    ) -> Self {
        Self::new(EdgeIdentity {
            build_version: build_version.to_string(),
            code_hash: code_hash.to_string(),
            measurement: Measurement::Mrenclave {
                value: mrenclave.to_string(),
            },
            tls_cert_spki_sha256: tls_spki_sha256.to_string(),
        })
    }
}

impl AttestationPlatform for SgxAttestationPlatform {
    fn identity(&self) -> &EdgeIdentity {
        &self.identity
    }

    fn challenge(&self, nonce: &[u8]) -> Result<AttestationChallengeResponse, PlatformError> {
        let quote_b64 = report::local_enclave_report_b64(nonce)?;
        Ok(AttestationChallengeResponse {
            edge: self.identity.clone(),
            challenge_nonce_b64: URL_SAFE_NO_PAD.encode(nonce),
            quote_b64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_binds_nonce() {
        let platform = SgxAttestationPlatform::from_env("0.1.0", "code", "deadbeef", "spki");
        let resp = platform
            .challenge(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
            .unwrap();
        assert_eq!(resp.edge.measurement, Measurement::Mrenclave {
            value: "deadbeef".into()
        });
        assert!(!resp.challenge_nonce_b64.is_empty());
    }
}
