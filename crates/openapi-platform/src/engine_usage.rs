//! Engine-signed usage reports for the OpenAPI edge (RB-37 / METER-002).
//!
//! Wire shape matches gateway ingest of `x-ope-usage-report`: base64url JSON
//! `{ "report": {…}, "sig": "<base64url ed25519>" }` with the same canonical
//! signing bytes as `@teechat/inference-engine` / Rust IE `usage_report_signing_bytes`.
//!
//! Enforcement is off by default (`OPENAPI_REQUIRE_SIGNED_USAGE` unset/false).
//! When on, missing/invalid signatures are rejected (no byte-length estimate
//! admit), reports must bind `request_id` to the request-body SHA-256 hex, and
//! engine/epoch verify-key mismatches fail closed.

use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;

const ENV_REQUIRE: &str = "OPENAPI_REQUIRE_SIGNED_USAGE";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EngineUsageError {
    #[error("engine usage report required (RB-37)")]
    Missing,
    #[error("engine usage report invalid: {0}")]
    Invalid(String),
    #[error("engine usage signature invalid (RB-37)")]
    SignatureInvalid,
    #[error("engine usage request hash mismatch (RB-37)")]
    RequestHashMismatch,
    #[error("engine usage engine_id mismatch (RB-37)")]
    EngineMismatch,
    #[error("engine usage epoch mismatch (RB-37)")]
    EpochMismatch,
    #[error("engine usage token counts exceed independent bound (RB-37)")]
    InflatedCounts,
}

/// Whether `OPENAPI_REQUIRE_SIGNED_USAGE` requests fail-closed verify.
pub fn require_signed_usage_from_env() -> bool {
    match std::env::var(ENV_REQUIRE) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "on"
        }
        Err(_) => false,
    }
}

/// Engine usage report body (gateway / IE naming).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageReport {
    pub request_id: String,
    pub conversation_id: String,
    pub engine_id: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    #[serde(default)]
    pub cached_tokens: u64,
    pub ts: String,
    /// Optional epoch bind when the engine includes it (Stage 5+).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch_id: Option<String>,
}

/// `{ report, sig }` as carried in `x-ope-usage-report`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedUsageReport {
    pub report: UsageReport,
    pub sig: String,
}

/// Context required to verify a signed usage header on the edge.
#[derive(Debug, Clone)]
pub struct UsageVerifyContext<'a> {
    pub expected_engine_id: &'a str,
    /// Epoch id from preassign; when the report carries `epoch_id`, it must match.
    pub expected_epoch_id: &'a str,
    /// Ed25519 public key (base64url raw 32 bytes) — identity or epoch usage key.
    pub verify_key_b64url: &'a str,
    /// SHA-256 hex of the OpenAPI request body (request-hash bind).
    pub expected_request_hash_hex: &'a str,
    /// Independent ceiling for prompt+completion (inflation guard).
    pub max_total_tokens: u64,
}

/// Canonical signing bytes — must stay aligned with gateway / IE metering.
pub fn usage_report_signing_bytes(report: &UsageReport) -> Vec<u8> {
    let canonical = json!({
        "cached_tokens": report.cached_tokens,
        "completion_tokens": report.completion_tokens,
        "conversation_id": report.conversation_id,
        "engine_id": report.engine_id,
        "prompt_tokens": report.prompt_tokens,
        "request_id": report.request_id,
        "ts": report.ts,
    });
    serde_json::to_vec(&canonical).unwrap_or_default()
}

pub fn request_body_hash_hex(request_body: &[u8]) -> String {
    hex::encode(Sha256::digest(request_body))
}

/// Independent token ceiling from request/response sizes (inflation bound).
pub fn independent_token_bound(request_body: &[u8], completion_text: &str) -> u64 {
    let prompt_est = (request_body.len() as u64 / 4).max(1);
    let completion_est = (completion_text.len() as u64 / 4).max(1);
    // Generous multiple so honest metered counts pass; blocks wild inflation.
    prompt_est.saturating_add(completion_est).saturating_mul(8)
}

pub fn parse_usage_report_header(header: &str) -> Result<SignedUsageReport, EngineUsageError> {
    let bytes = base64_url_decode(header.trim())
        .map_err(|_| EngineUsageError::Invalid("base64url decode failed".into()))?;
    serde_json::from_slice(&bytes).map_err(|e| EngineUsageError::Invalid(format!("json: {e}")))
}

pub fn verify_usage_signature(ed25519_public_b64url: &str, signed: &SignedUsageReport) -> bool {
    let msg = usage_report_signing_bytes(&signed.report);
    let Ok(pub_bytes) = base64_url_decode(ed25519_public_b64url.trim()) else {
        return false;
    };
    let Ok(sig_bytes) = base64_url_decode(signed.sig.trim()) else {
        return false;
    };
    let Ok(pub_arr): Result<[u8; 32], _> = pub_bytes.as_slice().try_into() else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.as_slice().try_into() else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&pub_arr) else {
        return false;
    };
    key.verify(&msg, &Signature::from_bytes(&sig_arr)).is_ok()
}

pub fn verify_signed_usage_report(
    signed: &SignedUsageReport,
    ctx: &UsageVerifyContext<'_>,
) -> Result<(), EngineUsageError> {
    if signed.report.engine_id != ctx.expected_engine_id {
        return Err(EngineUsageError::EngineMismatch);
    }
    if let Some(epoch) = signed.report.epoch_id.as_deref() {
        if epoch != ctx.expected_epoch_id {
            return Err(EngineUsageError::EpochMismatch);
        }
    }
    // Request-hash bind: request_id carries the body SHA-256 hex (RB-37.2).
    if !constant_time_eq(
        signed.report.request_id.as_bytes(),
        ctx.expected_request_hash_hex.as_bytes(),
    ) {
        return Err(EngineUsageError::RequestHashMismatch);
    }
    let total = signed
        .report
        .prompt_tokens
        .saturating_add(signed.report.completion_tokens);
    if total > ctx.max_total_tokens {
        return Err(EngineUsageError::InflatedCounts);
    }
    if !verify_usage_signature(ctx.verify_key_b64url, signed) {
        return Err(EngineUsageError::SignatureInvalid);
    }
    Ok(())
}

/// Resolve token counts from `x-ope-usage-report` or estimate.
///
/// When `require_signed` is false (default), preserves today's behavior: trust
/// unsigned header token fields when present, else byte-length estimate.
pub fn resolve_usage_tokens(
    usage_hdr: Option<&str>,
    request_body: &[u8],
    completion_text: &str,
    require_signed: bool,
    ctx: Option<&UsageVerifyContext<'_>>,
) -> Result<(u64, u64), EngineUsageError> {
    if require_signed {
        let ctx = ctx.ok_or(EngineUsageError::Missing)?;
        let hdr = usage_hdr.ok_or(EngineUsageError::Missing)?;
        let signed = parse_usage_report_header(hdr)?;
        verify_signed_usage_report(&signed, ctx)?;
        return Ok((signed.report.prompt_tokens, signed.report.completion_tokens));
    }

    if let Some(hdr) = usage_hdr {
        if let Ok(signed) = parse_usage_report_header(hdr) {
            let p = signed.report.prompt_tokens;
            let c = signed.report.completion_tokens;
            if p > 0 || c > 0 {
                return Ok((p, c));
            }
        } else if let Ok(bytes) = base64_url_decode(hdr) {
            // Legacy: unsigned JSON with prompt_tokens / completion_tokens.
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                let report = v.get("report").cloned().unwrap_or(v);
                let p = report
                    .get("prompt_tokens")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0);
                let c = report
                    .get("completion_tokens")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0);
                if p > 0 || c > 0 {
                    return Ok((p, c));
                }
            }
        }
    }
    let prompt_est = (request_body.len() as u64 / 4).max(1);
    let completion_est = (completion_text.len() as u64 / 4).max(1);
    Ok((prompt_est, completion_est))
}

pub fn sign_usage_report_for_tests(
    signing_key: &ed25519_dalek::SigningKey,
    report: &UsageReport,
) -> String {
    use ed25519_dalek::Signer;
    let sig = signing_key.sign(&usage_report_signing_bytes(report));
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes())
}

fn base64_url_decode(s: &str) -> Result<Vec<u8>, ()> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(s))
        .map_err(|_| ())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn keypair() -> (SigningKey, String) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
        (sk, pk)
    }

    fn header_for(sk: &SigningKey, report: &UsageReport) -> String {
        let signed = SignedUsageReport {
            report: report.clone(),
            sig: sign_usage_report_for_tests(sk, report),
        };
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&signed).unwrap())
    }

    fn body() -> &'static [u8] {
        br#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#
    }

    fn good_report(request_hash: &str, engine: &str) -> UsageReport {
        UsageReport {
            request_id: request_hash.to_string(),
            conversation_id: "conv".into(),
            engine_id: engine.into(),
            prompt_tokens: 11,
            completion_tokens: 22,
            cached_tokens: 0,
            ts: "2026-08-20T00:00:00.000Z".into(),
            epoch_id: Some("epoch-a".into()),
        }
    }

    /// 37.1 — missing/invalid sig rejected; no estimate admit when require_signed.
    #[test]
    fn rb37_1_unsigned_rejected_when_required() {
        let hash = request_body_hash_hex(body());
        let ctx = UsageVerifyContext {
            expected_engine_id: "eng-1",
            expected_epoch_id: "epoch-a",
            verify_key_b64url: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            expected_request_hash_hex: &hash,
            max_total_tokens: 10_000,
        };
        assert_eq!(
            resolve_usage_tokens(None, body(), "out", true, Some(&ctx)).unwrap_err(),
            EngineUsageError::Missing
        );
        let unsigned = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            br#"{"report":{"request_id":"x","conversation_id":"c","engine_id":"eng-1","prompt_tokens":9,"completion_tokens":9,"ts":"t"},"sig":"AAAA"}"#,
        );
        let err =
            resolve_usage_tokens(Some(&unsigned), body(), "out", true, Some(&ctx)).unwrap_err();
        assert!(
            matches!(
                err,
                EngineUsageError::SignatureInvalid
                    | EngineUsageError::RequestHashMismatch
                    | EngineUsageError::Invalid(_)
            ),
            "got {err:?}"
        );
        let (p, c) = resolve_usage_tokens(None, body(), "hello", false, None).unwrap();
        assert!(p >= 1 && c >= 1);
    }

    /// 37.2 — report for a different request hash is rejected.
    #[test]
    fn rb37_2_bound_to_request_hash() {
        let (sk, pk) = keypair();
        let hash = request_body_hash_hex(body());
        let mut report = good_report(&hash, "eng-1");
        report.request_id = "deadbeef".into();
        let hdr = header_for(&sk, &report);
        let ctx = UsageVerifyContext {
            expected_engine_id: "eng-1",
            expected_epoch_id: "epoch-a",
            verify_key_b64url: &pk,
            expected_request_hash_hex: &hash,
            max_total_tokens: 10_000,
        };
        assert_eq!(
            resolve_usage_tokens(Some(&hdr), body(), "out", true, Some(&ctx)).unwrap_err(),
            EngineUsageError::RequestHashMismatch
        );
        let good = good_report(&hash, "eng-1");
        let hdr_ok = header_for(&sk, &good);
        assert_eq!(
            resolve_usage_tokens(Some(&hdr_ok), body(), "out", true, Some(&ctx)).unwrap(),
            (11, 22)
        );
    }

    /// 37.3 — token counts above independent bound rejected.
    #[test]
    fn rb37_3_inflated_counts_rejected() {
        let (sk, pk) = keypair();
        let hash = request_body_hash_hex(body());
        let mut report = good_report(&hash, "eng-1");
        report.prompt_tokens = 1_000_000;
        report.completion_tokens = 1_000_000;
        let hdr = header_for(&sk, &report);
        let bound = independent_token_bound(body(), "out");
        let ctx = UsageVerifyContext {
            expected_engine_id: "eng-1",
            expected_epoch_id: "epoch-a",
            verify_key_b64url: &pk,
            expected_request_hash_hex: &hash,
            max_total_tokens: bound,
        };
        assert_eq!(
            resolve_usage_tokens(Some(&hdr), body(), "out", true, Some(&ctx)).unwrap_err(),
            EngineUsageError::InflatedCounts
        );
    }

    /// 37.4 — wrong epoch / engine rejected.
    #[test]
    fn rb37_4_wrong_epoch_or_engine_rejected() {
        let (sk, pk) = keypair();
        let hash = request_body_hash_hex(body());
        let report = good_report(&hash, "eng-other");
        let hdr = header_for(&sk, &report);
        let ctx = UsageVerifyContext {
            expected_engine_id: "eng-1",
            expected_epoch_id: "epoch-a",
            verify_key_b64url: &pk,
            expected_request_hash_hex: &hash,
            max_total_tokens: 10_000,
        };
        assert_eq!(
            resolve_usage_tokens(Some(&hdr), body(), "out", true, Some(&ctx)).unwrap_err(),
            EngineUsageError::EngineMismatch
        );

        let mut epoch_wrong = good_report(&hash, "eng-1");
        epoch_wrong.epoch_id = Some("epoch-b".into());
        let hdr2 = header_for(&sk, &epoch_wrong);
        assert_eq!(
            resolve_usage_tokens(Some(&hdr2), body(), "out", true, Some(&ctx)).unwrap_err(),
            EngineUsageError::EpochMismatch
        );

        let (sk2, _pk2) = keypair();
        let ok_report = good_report(&hash, "eng-1");
        let hdr3 = header_for(&sk2, &ok_report);
        assert_eq!(
            resolve_usage_tokens(Some(&hdr3), body(), "out", true, Some(&ctx)).unwrap_err(),
            EngineUsageError::SignatureInvalid
        );
    }
}
