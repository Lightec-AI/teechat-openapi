use openapi_platform::{
    build_report_data_v1, AttestationChallengeResponse, AttestationPlatform, EdgeIdentity,
    Measurement, PlatformError, QuoteFormat, CHALLENGE_NONCE_LEN,
};

use crate::dcap::DcapHelperClient;
use crate::report;

#[derive(Debug, Clone)]
pub struct SgxAttestationPlatform {
    identity: EdgeIdentity,
    dcap: Option<DcapHelperClient>,
}

impl SgxAttestationPlatform {
    pub fn new(identity: EdgeIdentity) -> Self {
        Self {
            identity,
            dcap: DcapHelperClient::from_env().ok(),
        }
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

    /// Build a challenge response from a pre-generated REPORT/quote (tests).
    pub fn challenge_with_report(
        &self,
        nonce: &[u8],
        report_bytes: &[u8],
        quote_format: QuoteFormat,
    ) -> Result<AttestationChallengeResponse, PlatformError> {
        let _ = build_report_data_v1(nonce, &self.identity)?;
        AttestationChallengeResponse::new(self.identity.clone(), nonce, quote_format, report_bytes)
            .map_err(Into::into)
    }

    fn dcap_quote(&self, report_data: &[u8; 64]) -> Result<Vec<u8>, PlatformError> {
        let dcap = self.dcap.as_ref().ok_or_else(|| {
            PlatformError::Attestation(
                "DCAP helper unavailable (set OPENAPI_DCAP_HELPER_URL, start openapi-dcap-helper)"
                    .into(),
            )
        })?;
        let target_info = dcap.qe_targetinfo()?;
        let report = report::enclave_report_for_target(&target_info, report_data)?;
        dcap.quote_report(&report)
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
        // Production path: QE-targeted REPORT → AESM ECDSA quote. Fail closed —
        // never return a local REPORT labeled as sgx_dcap_ecdsa.
        let quote = self.dcap_quote(&report_data)?;
        AttestationChallengeResponse::new(
            self.identity.clone(),
            nonce,
            QuoteFormat::SgxDcapEcdsa,
            &quote,
        )
        .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openapi_platform::{build_report_data_v1, verify_challenge_report_data, REPORT_DATA_LEN};

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
    fn host_challenge_errors_without_enclave_or_helper() {
        let err = platform().challenge(&[0u8; 32]).unwrap_err();
        let s = err.to_string();
        assert!(
            s.contains("sgx")
                || s.contains("attestation")
                || s.contains("DCAP")
                || s.contains("dcap")
                || s.contains("helper"),
            "unexpected error: {s}"
        );
    }
}
