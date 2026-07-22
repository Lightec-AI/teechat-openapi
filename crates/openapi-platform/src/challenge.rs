//! Attestation challenge binding (Option A) — locked in `docs/attestation-challenge.md`.

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{EdgeIdentity, Measurement, PlatformError};

/// Wire `schema_version` for challenge responses.
pub const SCHEMA_VERSION: u32 = 1;
/// Selects the `report_data` preimage in this module.
pub const REPORT_DATA_VERSION: u32 = 1;
/// Client nonce length (bytes).
pub const CHALLENGE_NONCE_LEN: usize = 32;
/// Hardware user-data / `report_data` length.
pub const REPORT_DATA_LEN: usize = 64;

/// ASCII magic — 28 bytes (no trailing NUL; length matches `docs/attestation-challenge.md`).
pub const CHALLENGE_MAGIC: &[u8; 28] = b"teechat-openapi-challenge-v1";

const MEASUREMENT_TAG_MRENCLAVE: u8 = 0x01;
const MEASUREMENT_TAG_LAUNCH_DIGEST: u8 = 0x02;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteFormat {
    /// Remotely verifiable SGX DCAP ECDSA quote (production target).
    SgxDcapEcdsa,
    /// Local SGX REPORT only — not remotely verifiable; lab / same-platform.
    SgxReport,
    /// AMD SEV-SNP attestation report (with VCEK chain for remote verify).
    SnpReport,
}

impl QuoteFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SgxDcapEcdsa => "sgx_dcap_ecdsa",
            Self::SgxReport => "sgx_report",
            Self::SnpReport => "snp_report",
        }
    }

    pub fn remotely_verifiable(self) -> bool {
        matches!(self, Self::SgxDcapEcdsa | Self::SnpReport)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChallengeBindError {
    #[error("nonce must be exactly {CHALLENGE_NONCE_LEN} bytes, got {0}")]
    BadNonceLen(usize),
    #[error("invalid hex field {field}: {detail}")]
    BadHex { field: &'static str, detail: String },
    #[error("hex field {field} must decode to 32 bytes")]
    BadHexLen { field: &'static str },
}

impl From<ChallengeBindError> for PlatformError {
    fn from(e: ChallengeBindError) -> Self {
        PlatformError::Attestation(e.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationChallengeResponse {
    pub schema_version: u32,
    pub report_data_version: u32,
    pub edge: EdgeIdentity,
    pub challenge_nonce_b64: String,
    pub quote_format: QuoteFormat,
    /// Standard Base64 of quote/report bytes.
    pub quote_b64: String,
}

impl AttestationChallengeResponse {
    pub fn new(
        edge: EdgeIdentity,
        nonce: &[u8],
        quote_format: QuoteFormat,
        quote_bytes: &[u8],
    ) -> Result<Self, ChallengeBindError> {
        if nonce.len() != CHALLENGE_NONCE_LEN {
            return Err(ChallengeBindError::BadNonceLen(nonce.len()));
        }
        let edge = canonicalize_edge_identity(&edge)?;
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            report_data_version: REPORT_DATA_VERSION,
            edge,
            challenge_nonce_b64: URL_SAFE_NO_PAD.encode(nonce),
            quote_format,
            quote_b64: STANDARD.encode(quote_bytes),
        })
    }
}

/// Ensure digest fields are 64 lowercase hex for binding.
///
/// - If `value` is already 64 hex chars, lowercase it.
/// - Otherwise replace with `hex(SHA-256(UTF-8 value))` (staging-friendly for non-hex env defaults).
pub fn canonicalize_digest_field(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return trimmed.to_ascii_lowercase();
    }
    hex::encode(Sha256::digest(trimmed.as_bytes()))
}

/// Canonicalize identity digests for challenge binding / response JSON.
pub fn canonicalize_edge_identity(edge: &EdgeIdentity) -> Result<EdgeIdentity, ChallengeBindError> {
    let code_hash = canonicalize_digest_field(&edge.code_hash);
    let tls_cert_spki_sha256 = canonicalize_digest_field(&edge.tls_cert_spki_sha256);
    // SPKI must be a real 32-byte digest after canonicalize; empty rejects.
    if edge.tls_cert_spki_sha256.trim().is_empty() {
        return Err(ChallengeBindError::BadHex {
            field: "tls_cert_spki_sha256",
            detail: "empty".into(),
        });
    }
    let measurement = match &edge.measurement {
        Measurement::Mrenclave { value } => Measurement::Mrenclave {
            value: canonicalize_digest_field(value),
        },
        Measurement::LaunchDigest {
            launch_digest,
            image_digest,
        } => Measurement::LaunchDigest {
            launch_digest: canonicalize_digest_field(launch_digest),
            image_digest: canonicalize_digest_field(image_digest),
        },
    };
    Ok(EdgeIdentity {
        build_version: edge.build_version.clone(),
        code_hash,
        measurement,
        tls_cert_spki_sha256,
    })
}

/// Build the 64-byte SGX/SNP `report_data` for version 1.
pub fn build_report_data_v1(
    nonce: &[u8],
    edge: &EdgeIdentity,
) -> Result<[u8; REPORT_DATA_LEN], ChallengeBindError> {
    let edge = canonicalize_edge_identity(edge)?;
    let preimage = build_preimage_v1(nonce, &edge)?;
    let digest = Sha256::digest(&preimage);
    let mut out = [0u8; REPORT_DATA_LEN];
    out[..32].copy_from_slice(&digest);
    Ok(out)
}

/// Preimage bytes hashed into `report_data[0..32]` (version 1).
///
/// Caller must pass an already-canonicalized [`EdgeIdentity`] (see [`canonicalize_edge_identity`]).
pub fn build_preimage_v1(nonce: &[u8], edge: &EdgeIdentity) -> Result<Vec<u8>, ChallengeBindError> {
    if nonce.len() != CHALLENGE_NONCE_LEN {
        return Err(ChallengeBindError::BadNonceLen(nonce.len()));
    }
    let spki = decode_hex32(&edge.tls_cert_spki_sha256, "tls_cert_spki_sha256")?;
    let code_hash = decode_hex32(&edge.code_hash, "code_hash")?;
    let build_digest = Sha256::digest(edge.build_version.as_bytes());

    let mut preimage = Vec::with_capacity(28 + 32 * 4 + 1 + 64);
    preimage.extend_from_slice(CHALLENGE_MAGIC);
    preimage.extend_from_slice(nonce);
    preimage.extend_from_slice(&spki);
    preimage.extend_from_slice(&build_digest);
    preimage.extend_from_slice(&code_hash);
    append_measurement_body(&mut preimage, &edge.measurement)?;
    Ok(preimage)
}

fn append_measurement_body(
    out: &mut Vec<u8>,
    measurement: &Measurement,
) -> Result<(), ChallengeBindError> {
    match measurement {
        Measurement::Mrenclave { value } => {
            let m = decode_hex32(value, "measurement.value")?;
            out.push(MEASUREMENT_TAG_MRENCLAVE);
            out.extend_from_slice(&m);
        }
        Measurement::LaunchDigest {
            launch_digest,
            image_digest,
        } => {
            let l = decode_hex32(launch_digest, "measurement.launch_digest")?;
            let i = decode_hex32(image_digest, "measurement.image_digest")?;
            out.push(MEASUREMENT_TAG_LAUNCH_DIGEST);
            out.extend_from_slice(&l);
            out.extend_from_slice(&i);
        }
    }
    Ok(())
}

fn decode_hex32(hex_str: &str, field: &'static str) -> Result<[u8; 32], ChallengeBindError> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| ChallengeBindError::BadHex {
        field,
        detail: e.to_string(),
    })?;
    if bytes.len() != 32 {
        return Err(ChallengeBindError::BadHexLen { field });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Recompute expected `report_data` and compare to `actual` (constant-time on the 32-byte digest).
pub fn report_data_matches_v1(
    nonce: &[u8],
    edge: &EdgeIdentity,
    actual: &[u8],
) -> Result<bool, ChallengeBindError> {
    let expected = build_report_data_v1(nonce, edge)?;
    if actual.len() != REPORT_DATA_LEN {
        return Ok(false);
    }
    use subtle::ConstantTimeEq;
    Ok(bool::from(expected.ct_eq(actual)))
}

/// Offset of `reportdata` within an SGX REPORT / report body (Intel layout).
pub const SGX_REPORT_DATA_OFFSET: usize = 320;

/// SGX DCAP Quote3 header size before the ISV enclave report body.
pub const SGX_DCAP_QUOTE3_HEADER_LEN: usize = 48;

/// Offset of `reportdata` within a Quote3 ECDSA blob (`header || report_body || …`).
pub const SGX_DCAP_REPORT_DATA_OFFSET: usize = SGX_DCAP_QUOTE3_HEADER_LEN + SGX_REPORT_DATA_OFFSET;

/// Decode a standard-Base64 SGX REPORT and return its `reportdata` field.
pub fn sgx_report_reportdata(quote_b64: &str) -> Result<[u8; REPORT_DATA_LEN], PlatformError> {
    let raw = STANDARD
        .decode(quote_b64.trim())
        .map_err(|e| PlatformError::Attestation(format!("quote_b64 decode: {e}")))?;
    // sgx_isa::Report layout: reportdata at offset 320.
    if raw.len() < SGX_REPORT_DATA_OFFSET + REPORT_DATA_LEN {
        return Err(PlatformError::Attestation(format!(
            "SGX REPORT too short: {} bytes",
            raw.len()
        )));
    }
    let mut out = [0u8; REPORT_DATA_LEN];
    out.copy_from_slice(&raw[SGX_REPORT_DATA_OFFSET..SGX_REPORT_DATA_OFFSET + REPORT_DATA_LEN]);
    Ok(out)
}

/// Extract `reportdata` from a standard-Base64 SGX DCAP Quote3 (ECDSA) blob.
///
/// This does **not** verify the quote signature or collateral — only layout parse
/// for challenge binding checks. Callers that need remote trust must verify DCAP.
pub fn sgx_dcap_quote_reportdata(quote_b64: &str) -> Result<[u8; REPORT_DATA_LEN], PlatformError> {
    let raw = STANDARD
        .decode(quote_b64.trim())
        .map_err(|e| PlatformError::Attestation(format!("quote_b64 decode: {e}")))?;
    if raw.len() < 2 {
        return Err(PlatformError::Attestation("DCAP quote too short".into()));
    }
    let version = u16::from_le_bytes([raw[0], raw[1]]);
    if version != 3 {
        return Err(PlatformError::Attestation(format!(
            "unsupported DCAP quote version {version} (want 3)"
        )));
    }
    if raw.len() < SGX_DCAP_REPORT_DATA_OFFSET + REPORT_DATA_LEN {
        return Err(PlatformError::Attestation(format!(
            "DCAP quote too short for report_data: {} bytes",
            raw.len()
        )));
    }
    let mut out = [0u8; REPORT_DATA_LEN];
    out.copy_from_slice(
        &raw[SGX_DCAP_REPORT_DATA_OFFSET..SGX_DCAP_REPORT_DATA_OFFSET + REPORT_DATA_LEN],
    );
    Ok(out)
}

/// AMD SEV-SNP attestation report: `REPORT_DATA` at offset 0x50 (64 bytes).
pub const SNP_REPORT_DATA_OFFSET: usize = 0x50;

pub fn snp_report_reportdata(quote_b64: &str) -> Result<[u8; REPORT_DATA_LEN], PlatformError> {
    let raw = STANDARD
        .decode(quote_b64.trim())
        .map_err(|e| PlatformError::Attestation(format!("quote_b64 decode: {e}")))?;
    if raw.len() < SNP_REPORT_DATA_OFFSET + REPORT_DATA_LEN {
        return Err(PlatformError::Attestation(format!(
            "SNP report too short: {} bytes",
            raw.len()
        )));
    }
    let mut out = [0u8; REPORT_DATA_LEN];
    out.copy_from_slice(&raw[SNP_REPORT_DATA_OFFSET..SNP_REPORT_DATA_OFFSET + REPORT_DATA_LEN]);
    Ok(out)
}

/// Client-side helper: check response echo + `report_data` binding for known quote formats.
pub fn verify_challenge_report_data(
    nonce: &[u8],
    response: &AttestationChallengeResponse,
) -> Result<(), PlatformError> {
    if response.schema_version != SCHEMA_VERSION {
        return Err(PlatformError::Attestation(format!(
            "unsupported schema_version {}",
            response.schema_version
        )));
    }
    if response.report_data_version != REPORT_DATA_VERSION {
        return Err(PlatformError::Attestation(format!(
            "unsupported report_data_version {}",
            response.report_data_version
        )));
    }
    let echoed = URL_SAFE_NO_PAD
        .decode(&response.challenge_nonce_b64)
        .map_err(|e| PlatformError::Attestation(format!("challenge_nonce_b64: {e}")))?;
    if echoed.as_slice() != nonce {
        return Err(PlatformError::Attestation(
            "challenge_nonce_b64 does not match client nonce".into(),
        ));
    }
    let actual = match response.quote_format {
        QuoteFormat::SgxReport => sgx_report_reportdata(&response.quote_b64)?,
        QuoteFormat::SgxDcapEcdsa => sgx_dcap_quote_reportdata(&response.quote_b64)?,
        QuoteFormat::SnpReport => snp_report_reportdata(&response.quote_b64)?,
    };
    if !report_data_matches_v1(nonce, &response.edge, &actual)? {
        return Err(PlatformError::Attestation(
            "report_data does not match recomputed binding".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn sample_sgx_edge() -> EdgeIdentity {
        EdgeIdentity {
            build_version: "0.1.0".into(),
            code_hash: hex32(0x11),
            measurement: Measurement::Mrenclave { value: hex32(0xaa) },
            tls_cert_spki_sha256: hex32(0xbb),
        }
    }

    fn sample_cvm_edge() -> EdgeIdentity {
        EdgeIdentity {
            build_version: "0.1.0".into(),
            code_hash: hex32(0x11),
            measurement: Measurement::LaunchDigest {
                launch_digest: hex32(0xcc),
                image_digest: hex32(0xdd),
            },
            tls_cert_spki_sha256: hex32(0xbb),
        }
    }

    #[test]
    fn magic_is_28_bytes() {
        assert_eq!(CHALLENGE_MAGIC.len(), 28);
        assert_eq!(CHALLENGE_MAGIC, b"teechat-openapi-challenge-v1");
    }

    #[test]
    fn report_data_rejects_short_nonce() {
        let err = build_report_data_v1(&[0u8; 16], &sample_sgx_edge()).unwrap_err();
        assert!(matches!(err, ChallengeBindError::BadNonceLen(16)));
    }

    #[test]
    fn canonicalize_hashes_non_hex_code_hash() {
        let mut edge = sample_sgx_edge();
        edge.code_hash = "unknown".into();
        let c = canonicalize_edge_identity(&edge).unwrap();
        assert_eq!(c.code_hash.len(), 64);
        assert_ne!(c.code_hash, "unknown");
        let nonce = [1u8; 32];
        build_report_data_v1(&nonce, &edge).unwrap();
    }

    #[test]
    fn report_data_rejects_bad_hex() {
        // After canonicalize, non-hex becomes sha256 — so use empty SPKI to fail.
        let mut edge = sample_sgx_edge();
        edge.tls_cert_spki_sha256 = "".into();
        assert!(matches!(
            build_report_data_v1(&[0u8; 32], &edge),
            Err(ChallengeBindError::BadHex { .. })
        ));
    }

    #[test]
    fn report_data_deterministic_and_nonce_sensitive() {
        let edge = sample_sgx_edge();
        let n1 = [1u8; 32];
        let n2 = [2u8; 32];
        let a = build_report_data_v1(&n1, &edge).unwrap();
        let b = build_report_data_v1(&n1, &edge).unwrap();
        let c = build_report_data_v1(&n2, &edge).unwrap();
        assert_eq!(a, b);
        assert_ne!(a[..32], c[..32]);
        assert_eq!(&a[32..], &[0u8; 32]);
    }

    #[test]
    fn report_data_binds_spki_and_measurement() {
        let edge = sample_sgx_edge();
        let nonce = [9u8; 32];
        let base = build_report_data_v1(&nonce, &edge).unwrap();

        let mut other_spki = edge.clone();
        other_spki.tls_cert_spki_sha256 = hex32(0xee);
        assert_ne!(
            base[..32],
            build_report_data_v1(&nonce, &other_spki).unwrap()[..32]
        );

        let mut other_m = edge.clone();
        other_m.measurement = Measurement::Mrenclave { value: hex32(0xff) };
        assert_ne!(
            base[..32],
            build_report_data_v1(&nonce, &other_m).unwrap()[..32]
        );
    }

    #[test]
    fn cvm_preimage_longer_than_sgx() {
        let nonce = [3u8; 32];
        let sgx = build_preimage_v1(&nonce, &sample_sgx_edge()).unwrap();
        let cvm = build_preimage_v1(&nonce, &sample_cvm_edge()).unwrap();
        assert_eq!(sgx.len(), 28 + 32 * 4 + 1 + 32);
        assert_eq!(cvm.len(), 28 + 32 * 4 + 1 + 64);
        assert_ne!(
            build_report_data_v1(&nonce, &sample_sgx_edge()).unwrap(),
            build_report_data_v1(&nonce, &sample_cvm_edge()).unwrap()
        );
    }

    #[test]
    fn response_json_roundtrip() {
        let edge = sample_sgx_edge();
        let nonce = [7u8; 32];
        let rd = build_report_data_v1(&nonce, &edge).unwrap();
        // Minimal fake REPORT: pad so offset 320 holds report_data.
        let mut report = vec![0u8; 320 + 64];
        report[320..384].copy_from_slice(&rd);
        let resp = AttestationChallengeResponse::new(
            edge.clone(),
            &nonce,
            QuoteFormat::SgxReport,
            &report,
        )
        .unwrap();
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["report_data_version"], 1);
        assert_eq!(json["quote_format"], "sgx_report");
        assert!(json["quote_b64"].as_str().unwrap().len() > 8);
        let back: AttestationChallengeResponse = serde_json::from_value(json).unwrap();
        verify_challenge_report_data(&nonce, &back).unwrap();
    }

    #[test]
    fn verify_detects_tampered_report_data() {
        let edge = sample_sgx_edge();
        let nonce = [7u8; 32];
        let mut report = vec![0u8; 384];
        report[320] = 0xff;
        let resp = AttestationChallengeResponse::new(edge, &nonce, QuoteFormat::SgxReport, &report)
            .unwrap();
        assert!(verify_challenge_report_data(&nonce, &resp).is_err());
    }

    #[test]
    fn snp_report_data_offset_extract() {
        let edge = sample_cvm_edge();
        let nonce = [5u8; 32];
        let rd = build_report_data_v1(&nonce, &edge).unwrap();
        let mut report = vec![0u8; SNP_REPORT_DATA_OFFSET + REPORT_DATA_LEN];
        report[SNP_REPORT_DATA_OFFSET..SNP_REPORT_DATA_OFFSET + 64].copy_from_slice(&rd);
        let resp = AttestationChallengeResponse::new(edge, &nonce, QuoteFormat::SnpReport, &report)
            .unwrap();
        verify_challenge_report_data(&nonce, &resp).unwrap();
    }

    #[test]
    fn quote_format_remote_flags() {
        assert!(QuoteFormat::SgxDcapEcdsa.remotely_verifiable());
        assert!(QuoteFormat::SnpReport.remotely_verifiable());
        assert!(!QuoteFormat::SgxReport.remotely_verifiable());
    }

    #[test]
    fn dcap_quote_report_data_offset() {
        let edge = sample_sgx_edge();
        let nonce = [5u8; 32];
        let rd = build_report_data_v1(&nonce, &edge).unwrap();
        let mut quote = vec![0u8; SGX_DCAP_REPORT_DATA_OFFSET + REPORT_DATA_LEN];
        quote[0] = 3; // Quote3 version LE
        quote[1] = 0;
        quote[SGX_DCAP_REPORT_DATA_OFFSET..SGX_DCAP_REPORT_DATA_OFFSET + 64].copy_from_slice(&rd);
        let resp =
            AttestationChallengeResponse::new(edge, &nonce, QuoteFormat::SgxDcapEcdsa, &quote)
                .unwrap();
        assert_eq!(resp.quote_format, QuoteFormat::SgxDcapEcdsa);
        assert_eq!(sgx_dcap_quote_reportdata(&resp.quote_b64).unwrap(), rd);
        verify_challenge_report_data(&nonce, &resp).unwrap();
    }
}
