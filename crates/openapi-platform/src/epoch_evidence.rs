//! Per-epoch attestation evidence for the engine the edge encrypts to (RB-45).
//!
//! The edge used to decide "is this the right recipient?" from a pinned Ed25519
//! key plus the engine's own signature over the epoch. Both are software
//! statements by a key the hardware attested once, at boot, so a compromised
//! engine process could keep minting epochs the edge would accept.
//!
//! Bind v2 puts the epoch's own ML-KEM, X25519 and usage-signing keys inside
//! the attestation report's REPORT_DATA. Recomputing that preimage and finding
//! it in the report replaces the signature: the report either names these keys
//! or it is evidence for something else.
//!
//! This module deliberately stops at "the report contains this epoch's keys".
//! Verifying the AMD chain over the report is the caller's job (`openapi-attest`
//! on the CVM edge), because the SGX lab build cannot link it.
//!
//! Encoding stays byte-identical with `bind_epoch_report_data_64` in the Rust
//! engine, `bindEpochReportData64` in the TS gateway, and the browser client.

use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::challenge::SNP_REPORT_DATA_OFFSET;

const REPORT_DATA_LEN: usize = 64;

/// Epoch key material a report vouches for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteEpochClaims {
    pub engine_id: String,
    pub epoch_id: String,
    pub not_before: String,
    pub not_after: String,
    pub mlkem_encapsulation_key: String,
    pub x25519_public: String,
    pub usage_signing_public: String,
}

#[derive(Debug, Clone, Deserialize)]
struct WorkloadMeasurement {
    #[serde(default)]
    binary_sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
struct WrapperClaims {
    #[serde(default)]
    tls_client_cert_sha256: String,
    #[serde(default)]
    engine: Option<WorkloadMeasurement>,
    #[serde(default)]
    vllm: Option<WorkloadMeasurement>,
    #[serde(default)]
    epoch: Option<QuoteEpochClaims>,
    #[serde(default)]
    issued_at: String,
}

#[derive(Debug, Clone, Deserialize)]
struct QuoteWrapper {
    v: u8,
    kind: String,
    #[serde(default)]
    report_b64: String,
    #[serde(default)]
    report_data_b64: String,
    claims: WrapperClaims,
}

/// What the caller is being asked to encrypt to.
#[derive(Debug, Clone, Copy)]
pub struct EpochEvidenceSubject<'a> {
    pub engine_id: &'a str,
    pub epoch_id: &'a str,
    pub not_before: &'a str,
    pub not_after: &'a str,
    pub mlkem_encapsulation_key: &'a str,
    pub x25519_public: &'a str,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EpochEvidenceError {
    /// The engine predates bind v2. Callers keep this distinct from a mismatch
    /// so a compatibility window is possible without also accepting evidence
    /// that describes some other epoch.
    #[error("attestation carries no per-epoch evidence")]
    Absent,
    #[error("attestation quote is not a readable SEV-SNP wrapper")]
    UnreadableQuote,
    #[error("attested engine id does not match the epoch presented")]
    EngineMismatch,
    #[error("attested epoch id does not match the epoch presented")]
    EpochMismatch,
    #[error("attested epoch window does not match the epoch presented")]
    WindowMismatch,
    #[error("attested ML-KEM key does not match the epoch presented")]
    MlkemMismatch,
    #[error("attested X25519 key does not match the epoch presented")]
    X25519Mismatch,
    #[error("attested epoch carries no usage-signing key")]
    UsageKeyMissing,
    #[error("attestation report does not carry this epoch's REPORT_DATA")]
    ReportDataMismatch,
    #[error("attestation report is too short to hold REPORT_DATA")]
    ReportUnreadable,
}

/// Accepted epoch evidence, with the material a caller needs downstream.
#[derive(Debug, Clone)]
pub struct VerifiedEpochEvidence {
    pub epoch: QuoteEpochClaims,
    /// Standard-base64 SNP report the epoch keys were found in, for chain
    /// verification and launch-digest pinning by the caller.
    pub report_b64: String,
}

/// REPORT_DATA that names an epoch's own keys (bind v2).
pub fn bind_epoch_report_data_64(
    epoch: &QuoteEpochClaims,
    tls_client_cert_sha256: &str,
    engine_binary_sha256: &str,
    vllm_binary_sha256: &str,
    issued_at: &str,
    nonce: Option<&str>,
) -> [u8; 64] {
    let canonical = [
        "teechat-sev-snp-bind-v2",
        epoch.engine_id.as_str(),
        epoch.epoch_id.as_str(),
        epoch.not_before.as_str(),
        epoch.not_after.as_str(),
        epoch.mlkem_encapsulation_key.as_str(),
        epoch.x25519_public.as_str(),
        epoch.usage_signing_public.as_str(),
        &tls_client_cert_sha256.to_ascii_lowercase(),
        &engine_binary_sha256.to_ascii_lowercase(),
        &vllm_binary_sha256.to_ascii_lowercase(),
        issued_at,
        nonce.unwrap_or(""),
    ]
    .join("\0");
    let digest = Sha512::digest(canonical.as_bytes());
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest[..64]);
    out
}

fn decode_base64url(value: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value.trim())
        .or_else(|_| URL_SAFE.decode(value.trim()))
        .ok()
}

fn parse_wrapper(quote: &str) -> Option<QuoteWrapper> {
    let raw = decode_base64url(quote)?;
    let wrapper: QuoteWrapper = serde_json::from_slice(&raw).ok()?;
    if wrapper.v != 2 || wrapper.kind != "sev-snp" {
        return None;
    }
    Some(wrapper)
}

/// Whether a quote carries per-epoch evidence at all.
pub fn quote_has_epoch_evidence(quote: &str) -> bool {
    parse_wrapper(quote)
        .map(|w| w.claims.epoch.is_some())
        .unwrap_or(false)
}

fn match_fields(
    epoch: &QuoteEpochClaims,
    subject: &EpochEvidenceSubject<'_>,
) -> Result<(), EpochEvidenceError> {
    if epoch.engine_id != subject.engine_id {
        return Err(EpochEvidenceError::EngineMismatch);
    }
    if epoch.epoch_id != subject.epoch_id {
        return Err(EpochEvidenceError::EpochMismatch);
    }
    if epoch.not_before != subject.not_before || epoch.not_after != subject.not_after {
        return Err(EpochEvidenceError::WindowMismatch);
    }
    // Base64url material must match exactly, and two empty strings are not a
    // match — that would accept an epoch with no key at all.
    if epoch.mlkem_encapsulation_key.is_empty()
        || epoch.mlkem_encapsulation_key != subject.mlkem_encapsulation_key
    {
        return Err(EpochEvidenceError::MlkemMismatch);
    }
    if epoch.x25519_public.is_empty() || epoch.x25519_public != subject.x25519_public {
        return Err(EpochEvidenceError::X25519Mismatch);
    }
    if epoch.usage_signing_public.trim().is_empty() {
        return Err(EpochEvidenceError::UsageKeyMissing);
    }
    Ok(())
}

/// Check that a quote is evidence for the epoch the edge is about to use.
///
/// `nonce` is the challenge the evidence was minted against, when the caller
/// issued one. Connect-scoped and unchallenged evidence passes `None`.
pub fn verify_epoch_evidence(
    quote: &str,
    subject: &EpochEvidenceSubject<'_>,
    nonce: Option<&str>,
) -> Result<VerifiedEpochEvidence, EpochEvidenceError> {
    let wrapper = parse_wrapper(quote).ok_or(EpochEvidenceError::UnreadableQuote)?;
    let epoch = wrapper
        .claims
        .epoch
        .clone()
        .ok_or(EpochEvidenceError::Absent)?;
    match_fields(&epoch, subject)?;

    let expected = bind_epoch_report_data_64(
        &epoch,
        &wrapper.claims.tls_client_cert_sha256,
        wrapper
            .claims
            .engine
            .as_ref()
            .map(|m| m.binary_sha256.as_str())
            .unwrap_or(""),
        wrapper
            .claims
            .vllm
            .as_ref()
            .map(|m| m.binary_sha256.as_str())
            .unwrap_or(""),
        &wrapper.claims.issued_at,
        nonce,
    );

    let declared = STANDARD
        .decode(wrapper.report_data_b64.trim())
        .map_err(|_| EpochEvidenceError::ReportDataMismatch)?;
    if declared.len() != REPORT_DATA_LEN || declared.as_slice().ct_eq(&expected).unwrap_u8() != 1 {
        return Err(EpochEvidenceError::ReportDataMismatch);
    }

    // The wrapper's report_data field is self-declared; the report is the part
    // the hardware signed, so the binding only means anything when both agree.
    let report = STANDARD
        .decode(wrapper.report_b64.trim())
        .map_err(|_| EpochEvidenceError::ReportUnreadable)?;
    let end = SNP_REPORT_DATA_OFFSET + REPORT_DATA_LEN;
    if report.len() < end {
        return Err(EpochEvidenceError::ReportUnreadable);
    }
    if report[SNP_REPORT_DATA_OFFSET..end]
        .ct_eq(&expected)
        .unwrap_u8()
        != 1
    {
        return Err(EpochEvidenceError::ReportDataMismatch);
    }

    Ok(VerifiedEpochEvidence {
        epoch,
        report_b64: wrapper.report_b64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TLS_HASH: &str = "cc\
cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const ENGINE_HASH: &str = "a1b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef90";
    const VLLM_HASH: &str = "b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef9012";
    const ISSUED_AT: &str = "2026-07-31T00:00:00.000Z";

    fn epoch() -> QuoteEpochClaims {
        QuoteEpochClaims {
            engine_id: "engine-1".into(),
            epoch_id: "epoch-1".into(),
            not_before: "2026-07-31T00:00:00.000Z".into(),
            not_after: "2026-08-30T00:00:00.000Z".into(),
            mlkem_encapsulation_key: "bWxrZW0".into(),
            x25519_public: "eDI1NTE5".into(),
            usage_signing_public: "dXNhZ2U".into(),
        }
    }

    fn subject_for(e: &QuoteEpochClaims) -> EpochEvidenceSubject<'_> {
        EpochEvidenceSubject {
            engine_id: &e.engine_id,
            epoch_id: &e.epoch_id,
            not_before: &e.not_before,
            not_after: &e.not_after,
            mlkem_encapsulation_key: &e.mlkem_encapsulation_key,
            x25519_public: &e.x25519_public,
        }
    }

    struct QuoteOpts {
        epoch: Option<QuoteEpochClaims>,
        report_data: Vec<u8>,
        declared: Option<Vec<u8>>,
        report_len: usize,
        nonce: Option<String>,
    }

    impl Default for QuoteOpts {
        fn default() -> Self {
            let e = epoch();
            let data =
                bind_epoch_report_data_64(&e, TLS_HASH, ENGINE_HASH, VLLM_HASH, ISSUED_AT, None)
                    .to_vec();
            Self {
                epoch: Some(e),
                report_data: data,
                declared: None,
                report_len: 1184,
                nonce: None,
            }
        }
    }

    fn build_quote(opts: QuoteOpts) -> String {
        let mut report = vec![0u8; opts.report_len];
        if report.len() >= SNP_REPORT_DATA_OFFSET + opts.report_data.len() {
            report[SNP_REPORT_DATA_OFFSET..SNP_REPORT_DATA_OFFSET + opts.report_data.len()]
                .copy_from_slice(&opts.report_data);
        }
        let declared = opts.declared.unwrap_or(opts.report_data);
        let mut claims = json!({
            "v": 1,
            "kind": "sev-snp",
            "ed25519_public": "aWQ",
            "tls_client_cert_sha256": TLS_HASH,
            "engine": { "version": "0.12.1", "binary_sha256": ENGINE_HASH },
            "vllm": { "version": "v1", "binary_sha256": VLLM_HASH },
            "issued_at": ISSUED_AT,
        });
        if let Some(e) = &opts.epoch {
            claims["epoch"] = serde_json::to_value(e).unwrap();
        }
        let wrapper = json!({
            "v": 2,
            "kind": "sev-snp",
            "report_b64": STANDARD.encode(&report),
            "report_data_b64": STANDARD.encode(&declared),
            "claims": claims,
        });
        let _ = &opts.nonce;
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&wrapper).unwrap())
    }

    #[test]
    fn accepts_a_report_that_names_this_epochs_keys() {
        let e = epoch();
        let quote = build_quote(QuoteOpts::default());
        let verified = verify_epoch_evidence(&quote, &subject_for(&e), None).expect("verified");
        assert_eq!(verified.epoch, e);
        assert!(!verified.report_b64.is_empty());
        assert!(quote_has_epoch_evidence(&quote));
    }

    #[test]
    fn reports_absence_for_connect_scoped_evidence() {
        let e = epoch();
        let quote = build_quote(QuoteOpts {
            epoch: None,
            ..Default::default()
        });
        assert_eq!(
            verify_epoch_evidence(&quote, &subject_for(&e), None).unwrap_err(),
            EpochEvidenceError::Absent
        );
        assert!(!quote_has_epoch_evidence(&quote));
    }

    #[test]
    fn rejects_keys_the_report_does_not_attest() {
        // A relay swapping in its own recipient key is the attack this stops.
        let e = epoch();
        let quote = build_quote(QuoteOpts::default());
        let mut subject = subject_for(&e);
        subject.x25519_public = "relay-substituted-key";
        assert_eq!(
            verify_epoch_evidence(&quote, &subject, None).unwrap_err(),
            EpochEvidenceError::X25519Mismatch
        );
    }

    #[test]
    fn rejects_an_epoch_block_pasted_onto_another_epochs_report() {
        let other = QuoteEpochClaims {
            epoch_id: "epoch-other".into(),
            ..epoch()
        };
        let quote = build_quote(QuoteOpts {
            report_data: bind_epoch_report_data_64(
                &other,
                TLS_HASH,
                ENGINE_HASH,
                VLLM_HASH,
                ISSUED_AT,
                None,
            )
            .to_vec(),
            ..Default::default()
        });
        let e = epoch();
        assert_eq!(
            verify_epoch_evidence(&quote, &subject_for(&e), None).unwrap_err(),
            EpochEvidenceError::ReportDataMismatch
        );
    }

    #[test]
    fn rejects_a_wrapper_whose_declared_binding_disagrees_with_the_report() {
        let e = epoch();
        let good = bind_epoch_report_data_64(&e, TLS_HASH, ENGINE_HASH, VLLM_HASH, ISSUED_AT, None)
            .to_vec();
        let quote = build_quote(QuoteOpts {
            report_data: vec![0u8; 64],
            declared: Some(good),
            ..Default::default()
        });
        assert_eq!(
            verify_epoch_evidence(&quote, &subject_for(&e), None).unwrap_err(),
            EpochEvidenceError::ReportDataMismatch
        );
    }

    #[test]
    fn rejects_a_report_too_short_to_hold_report_data() {
        let e = epoch();
        let quote = build_quote(QuoteOpts {
            report_len: 64,
            ..Default::default()
        });
        assert_eq!(
            verify_epoch_evidence(&quote, &subject_for(&e), None).unwrap_err(),
            EpochEvidenceError::ReportUnreadable
        );
    }

    #[test]
    fn binding_is_scoped_to_the_challenge_nonce() {
        let e = epoch();
        let quote = build_quote(QuoteOpts {
            report_data: bind_epoch_report_data_64(
                &e,
                TLS_HASH,
                ENGINE_HASH,
                VLLM_HASH,
                ISSUED_AT,
                Some("challenge-1"),
            )
            .to_vec(),
            ..Default::default()
        });
        assert!(verify_epoch_evidence(&quote, &subject_for(&e), Some("challenge-1")).is_ok());
        assert_eq!(
            verify_epoch_evidence(&quote, &subject_for(&e), Some("challenge-2")).unwrap_err(),
            EpochEvidenceError::ReportDataMismatch
        );
        assert_eq!(
            verify_epoch_evidence(&quote, &subject_for(&e), None).unwrap_err(),
            EpochEvidenceError::ReportDataMismatch
        );
    }

    #[test]
    fn rejects_quotes_it_cannot_read() {
        let e = epoch();
        for quote in ["", "not-base64url!!", &URL_SAFE_NO_PAD.encode(b"{}")] {
            assert_eq!(
                verify_epoch_evidence(quote, &subject_for(&e), None).unwrap_err(),
                EpochEvidenceError::UnreadableQuote
            );
        }
    }

    #[test]
    fn rejects_an_epoch_with_no_usage_signing_key() {
        let e = QuoteEpochClaims {
            usage_signing_public: "   ".into(),
            ..epoch()
        };
        let quote = build_quote(QuoteOpts {
            epoch: Some(e.clone()),
            report_data: bind_epoch_report_data_64(
                &e,
                TLS_HASH,
                ENGINE_HASH,
                VLLM_HASH,
                ISSUED_AT,
                None,
            )
            .to_vec(),
            ..Default::default()
        });
        assert_eq!(
            verify_epoch_evidence(&quote, &subject_for(&e), None).unwrap_err(),
            EpochEvidenceError::UsageKeyMissing
        );
    }

    /// Cross-runtime contract: the engine, the gateway, and the browser all
    /// recompute this preimage. A change here that is not mirrored there
    /// silently rejects every epoch.
    #[test]
    fn bind_v2_preimage_matches_the_pinned_cross_runtime_vector() {
        let e = QuoteEpochClaims {
            epoch_id: "epoch-2026-07".into(),
            ..epoch()
        };
        let got = bind_epoch_report_data_64(
            &e,
            &"aa".repeat(32),
            &"a".repeat(64),
            &"b".repeat(64),
            "2026-07-31T00:00:00.000Z",
            None,
        );
        let canonical = [
            "teechat-sev-snp-bind-v2",
            "engine-1",
            "epoch-2026-07",
            "2026-07-31T00:00:00.000Z",
            "2026-08-30T00:00:00.000Z",
            "bWxrZW0",
            "eDI1NTE5",
            "dXNhZ2U",
            &"aa".repeat(32),
            &"a".repeat(64),
            &"b".repeat(64),
            "2026-07-31T00:00:00.000Z",
            "",
        ]
        .join("\0");
        assert_eq!(
            got.to_vec(),
            Sha512::digest(canonical.as_bytes())[..64].to_vec()
        );
    }
}
