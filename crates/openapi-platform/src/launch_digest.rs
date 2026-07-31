//! Composed SEV-SNP launch digest, derived from the report rather than read
//! from a claim (RB-51).
//!
//! A quote wrapper may carry a `launch_digest` claim, but that field is written
//! by the same software the digest is supposed to identify. The only value with
//! any weight is the one recomputed from the report's MEASUREMENT field, which
//! the AMD signature covers.
//!
//! Encoding: `sha256(lowercase_ascii_hex(raw_MEASUREMENT))`, byte-identical
//! with `challenge_canonical_launch_digest` in `openapi-attest`, the engine's
//! `launch_digest.rs`, the gateway, the browser client, and the factory bake.
//!
//! Field offset: AMD SEV-SNP Firmware ABI — MEASUREMENT at 0x90, length 48.

use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const MEASUREMENT_OFFSET: usize = 0x90;
const MEASUREMENT_LEN: usize = 48;

#[derive(Deserialize)]
struct QuoteWrapperHead {
    v: u8,
    kind: String,
    #[serde(default)]
    report_b64: String,
}

/// Raw SNP report bytes out of a TeeChat quote wrapper, when it is one.
pub fn snp_report_from_quote(quote: &str) -> Option<Vec<u8>> {
    let raw = URL_SAFE_NO_PAD
        .decode(quote.trim())
        .or_else(|_| URL_SAFE.decode(quote.trim()))
        .ok()?;
    let head: QuoteWrapperHead = serde_json::from_slice(&raw).ok()?;
    if head.v != 2 || head.kind != "sev-snp" || head.report_b64.is_empty() {
        return None;
    }
    STANDARD.decode(head.report_b64.trim()).ok()
}

/// The 48-byte MEASUREMENT at the ABI offset.
pub fn measurement_from_snp_report(report: &[u8]) -> Option<&[u8]> {
    report.get(MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + MEASUREMENT_LEN)
}

/// `sha256(lowercase_ascii_hex(measurement))`.
pub fn compose_launch_digest(raw_measurement_hex: &str) -> String {
    hex::encode(Sha256::digest(
        raw_measurement_hex.trim().to_ascii_lowercase().as_bytes(),
    ))
}

/// Composed launch digest for the CVM a quote came from, or `None` when the
/// quote is not a readable SNP wrapper. Callers on real hardware must treat
/// `None` as a failure, not as "skip the check".
pub fn launch_digest_from_snp_quote(quote: &str) -> Option<String> {
    let report = snp_report_from_quote(quote)?;
    let measurement = measurement_from_snp_report(&report)?;
    Some(compose_launch_digest(&hex::encode(measurement)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn quote(report: &[u8], claimed: Option<&str>) -> String {
        let mut wrapper = json!({
            "v": 2,
            "kind": "sev-snp",
            "report_b64": STANDARD.encode(report),
            "report_data_b64": STANDARD.encode([0u8; 64]),
            "claims": { "v": 1, "kind": "sev-snp" },
        });
        if let Some(c) = claimed {
            wrapper["claims"]["launch_digest"] = json!(c);
        }
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&wrapper).unwrap())
    }

    #[test]
    fn derives_the_digest_from_the_reports_measurement() {
        let mut report = vec![0u8; 1184];
        report[MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + MEASUREMENT_LEN]
            .copy_from_slice(&[0x5a; MEASUREMENT_LEN]);
        let expected = compose_launch_digest(&"5a".repeat(MEASUREMENT_LEN));
        assert_eq!(
            launch_digest_from_snp_quote(&quote(&report, None)),
            Some(expected)
        );
    }

    #[test]
    fn ignores_a_launch_digest_the_claims_assert() {
        // RB-51: the claim is self-declared, the report is signed.
        let mut report = vec![0u8; 1184];
        report[MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + MEASUREMENT_LEN]
            .copy_from_slice(&[0x11; MEASUREMENT_LEN]);
        let lie = "de".repeat(32);
        let got = launch_digest_from_snp_quote(&quote(&report, Some(&lie))).unwrap();
        assert_ne!(got, lie);
        assert_eq!(got, compose_launch_digest(&"11".repeat(MEASUREMENT_LEN)));
    }

    #[test]
    fn returns_none_for_quotes_without_a_measurement() {
        assert_eq!(launch_digest_from_snp_quote(&quote(&[0u8; 64], None)), None);
        assert_eq!(launch_digest_from_snp_quote("not-a-quote"), None);
        assert_eq!(launch_digest_from_snp_quote(""), None);
    }

    #[test]
    fn composition_is_case_insensitive_and_trims() {
        assert_eq!(
            compose_launch_digest("  AABB  "),
            compose_launch_digest("aabb")
        );
    }
}
