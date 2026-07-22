use openapi_platform::{
    build_report_data_v1, AttestationChallengeResponse, AttestationPlatform, EdgeIdentity,
    Measurement, PlatformError, QuoteFormat, CHALLENGE_NONCE_LEN,
};

use crate::snp_report;

#[derive(Debug, Clone)]
pub struct CvmAttestationPlatform {
    identity: EdgeIdentity,
}

impl CvmAttestationPlatform {
    pub fn new(identity: EdgeIdentity) -> Self {
        Self { identity }
    }

    pub fn from_env(
        build_version: &str,
        code_hash: &str,
        launch_digest: &str,
        image_digest: &str,
        tls_spki_sha256: &str,
        policy_hash: Option<String>,
    ) -> Self {
        Self::new(EdgeIdentity {
            build_version: build_version.to_string(),
            code_hash: code_hash.to_string(),
            measurement: Measurement::LaunchDigest {
                launch_digest: launch_digest.to_string(),
                image_digest: image_digest.to_string(),
            },
            tls_cert_spki_sha256: tls_spki_sha256.to_string(),
            policy_hash,
        })
    }

    /// Build a challenge response from pre-fetched SNP report bytes (tests).
    pub fn challenge_with_report(
        &self,
        nonce: &[u8],
        snp_report_bytes: &[u8],
    ) -> Result<AttestationChallengeResponse, PlatformError> {
        let _ = build_report_data_v1(nonce, &self.identity)?;
        AttestationChallengeResponse::new(
            self.identity.clone(),
            nonce,
            QuoteFormat::SnpReport,
            snp_report_bytes,
        )
        .map_err(Into::into)
    }
}

impl AttestationPlatform for CvmAttestationPlatform {
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
        let report_bytes = snp_report::snp_report_with_data(&report_data)?;
        AttestationChallengeResponse::new(
            self.identity.clone(),
            nonce,
            QuoteFormat::SnpReport,
            &report_bytes,
        )
        .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openapi_platform::{
        build_report_data_v1, verify_challenge_report_data, REPORT_DATA_LEN, SNP_REPORT_DATA_OFFSET,
    };

    fn hex32(b: u8) -> String {
        hex::encode([b; 32])
    }

    fn platform() -> CvmAttestationPlatform {
        CvmAttestationPlatform::from_env(
            "0.1.0",
            &hex32(0x11),
            &hex32(0xcc),
            &hex32(0xdd),
            &hex32(0xbb),
            None,
        )
    }

    #[test]
    fn challenge_with_synthetic_snp_report_verifies() {
        let p = platform();
        let nonce = [5u8; 32];
        let rd = build_report_data_v1(&nonce, p.identity()).unwrap();
        let mut report = vec![0u8; SNP_REPORT_DATA_OFFSET + REPORT_DATA_LEN];
        report[SNP_REPORT_DATA_OFFSET..SNP_REPORT_DATA_OFFSET + 64].copy_from_slice(&rd);
        let resp = p.challenge_with_report(&nonce, &report).unwrap();
        assert_eq!(resp.quote_format, QuoteFormat::SnpReport);
        assert_eq!(resp.schema_version, 1);
        verify_challenge_report_data(&nonce, &resp).unwrap();
    }

    #[test]
    fn challenge_without_hardware_errors() {
        let err = platform().challenge(&[0u8; 32]).unwrap_err();
        assert!(err.to_string().contains("SNP") || err.to_string().contains("attestation"));
    }
}
