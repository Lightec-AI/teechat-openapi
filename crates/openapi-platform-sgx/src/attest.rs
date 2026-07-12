use openapi_platform::{
    build_report_data_v1, AttestationChallengeResponse, AttestationPlatform, EdgeIdentity,
    Measurement, PlatformError, QuoteFormat, CHALLENGE_NONCE_LEN,
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

    /// Build a challenge response from a pre-generated REPORT (tests / DCAP bridge).
    pub fn challenge_with_report(
        &self,
        nonce: &[u8],
        report_bytes: &[u8],
        quote_format: QuoteFormat,
    ) -> Result<AttestationChallengeResponse, PlatformError> {
        let _ = build_report_data_v1(nonce, &self.identity)?;
        AttestationChallengeResponse::new(
            self.identity.clone(),
            nonce,
            quote_format,
            report_bytes,
        )
        .map_err(Into::into)
    }
}

impl AttestationPlatform for SgxAttestationPlatform {
    fn identity(&self) -> &EdgeIdentity {
        &self.identity
    }

    fn challenge(&self, nonce: &[u8]) -> Result<AttestationChallengeResponse, PlatformError> {
        if nonce.len() != CHALLENGE_NONCE_LEN {
            return Err(PlatformError::Attestation(format!(
                "nonce must be exactly {CHALLENGE_NONCE_LEN} bytes"
            )));
        }
        let report_data = build_report_data_v1(nonce, &self.identity)?;
        let report_bytes = report::enclave_report_with_data(&report_data)?;
        // Local REPORT is hardware-correct for report_data binding. Remote internet
        // verifiers need DCAP (`sgx_dcap_ecdsa`); that path is not yet linked in-tree.
        AttestationChallengeResponse::new(
            self.identity.clone(),
            nonce,
            QuoteFormat::SgxReport,
            &report_bytes,
        )
        .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openapi_platform::{
        build_report_data_v1, verify_challenge_report_data, REPORT_DATA_LEN,
    };

    fn hex32(b: u8) -> String {
        hex::encode([b; 32])
    }

    fn platform() -> SgxAttestationPlatform {
        SgxAttestationPlatform::from_env("0.1.0", &hex32(0x11), &hex32(0xaa), &hex32(0xbb))
    }

    #[test]
    fn challenge_with_synthetic_report_verifies() {
        let p = platform();
        let nonce = [9u8; 32];
        let rd = build_report_data_v1(&nonce, p.identity()).unwrap();
        let mut report = vec![0u8; 320 + REPORT_DATA_LEN];
        report[320..384].copy_from_slice(&rd);
        let resp = p
            .challenge_with_report(&nonce, &report, QuoteFormat::SgxReport)
            .unwrap();
        assert_eq!(resp.schema_version, 1);
        assert_eq!(resp.quote_format, QuoteFormat::SgxReport);
        verify_challenge_report_data(&nonce, &resp).unwrap();
    }

    #[test]
    fn host_challenge_errors_without_enclave() {
        let err = platform().challenge(&[0u8; 32]).unwrap_err();
        assert!(err.to_string().contains("sgx") || err.to_string().contains("attestation"));
    }
}
