//! Recipient selection for the OPE edge: which engine keys may customer
//! plaintext be encrypted to (RB-46, RB-47).
//!
//! The OPE envelope protects the payload from the gateway, so the gateway
//! cannot read a request it relays. What it *could* do before this module is
//! choose the recipient: hand the edge an epoch belonging to an engine of its
//! choosing. The edge's only defence was a pinned Ed25519 key plus the engine's
//! signature over the epoch — both software statements from a key attested once
//! at boot, and, worse, a key the engine regenerates on every restart (RB-52).
//!
//! The rule here is the one the TeeChat browser client follows:
//!
//! 1. the epoch keys must appear inside an attestation report (bind v2), and
//! 2. the code that holds them must measure to an allowlisted launch digest.
//!
//! Neither is a statement by the gateway, so a rogue relay pointing the edge at
//! an engine it controls has to produce hardware evidence for that engine, and
//! the measurement pin means that evidence has to come from an allowlisted
//! build.
//!
//! Verifying the AMD signature over the report is left to the caller: the CVM
//! edge links `openapi-attest` and does it, the SGX lab build cannot.

use std::collections::BTreeSet;

use thiserror::Error;

use crate::engine_trust::{
    parse_rfc3339_ms, verify_ephemeral_engine_trust, EngineIdentityPins, EngineTrustError,
    EphemeralEngineTrust,
};
use crate::epoch_evidence::{
    verify_epoch_evidence, EpochEvidenceError, EpochEvidenceSubject, QuoteEpochClaims,
};
use crate::launch_digest::launch_digest_from_snp_quote;
use crate::sealed_time::{epoch_window_active, sealed_time_enabled_from_env, SealedTimeStore};

/// What convinced the edge to encrypt to this epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientTrustVia {
    /// The report names these epoch keys (bind v2).
    EpochEvidence,
    /// Legacy: a pinned long-lived engine key signed the epoch. Accepted only
    /// while `require_epoch_evidence` is off **and** Stage 5 identity delete is
    /// off, for the window where the edge is ahead of the engine fleet.
    IdentitySignature,
}

#[derive(Debug, Clone)]
pub struct AcceptedRecipient {
    pub via: RecipientTrustVia,
    /// Epoch block from the report, when the evidence carried one.
    pub epoch: Option<QuoteEpochClaims>,
    /// Standard-base64 SNP report, for AMD chain verification by the caller.
    pub report_b64: Option<String>,
    /// Challenge-canonical composed launch digest of the engine CVM.
    pub launch_digest: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecipientError {
    #[error("engine epoch is not active")]
    EpochNotActive,
    #[error("invalid engine epoch timestamp")]
    InvalidTimestamp,
    #[error("engine presented no per-epoch attestation evidence")]
    EpochEvidenceRequired,
    #[error("engine epoch evidence rejected: {0}")]
    EpochEvidence(EpochEvidenceError),
    #[error("engine launch digest allowlist is required but empty")]
    LaunchDigestAllowlistMissing,
    #[error("engine attestation carries no readable launch measurement")]
    LaunchDigestUnreadable,
    #[error("engine launch digest {0} is not allowlisted")]
    LaunchDigestNotAllowed(String),
    #[error("engine identity trust rejected: {0}")]
    Identity(EngineTrustError),
}

/// Recipient policy, assembled from the edge runtime configuration.
#[derive(Debug, Clone, Default)]
pub struct EngineRecipientPolicy {
    pub identity_pins: EngineIdentityPins,
    /// Challenge-canonical composed launch digests (hex sha256) of allowlisted
    /// engine golden images. Empty disables the measurement pin.
    pub launch_digest_allowlist: BTreeSet<String>,
    /// Reject epochs that arrive without per-epoch hardware evidence.
    pub require_epoch_evidence: bool,
    /// Stage 5 (RB-52): identity pin / `OPE-ENGINE-EPHEMERAL-v1` is no longer an
    /// admit path. Empty or stale `OPENAPI_ENGINE_IDENTITY_PINS_JSON` must not
    /// admit. Default **off** so live edges stay unchanged until an explicit GO.
    pub stage5_identity_deleted: bool,
    /// Reject epochs whose measurement is absent or unlisted.
    pub require_launch_digest: bool,
    pub epoch_clock_skew_ms: u64,
}

impl EngineRecipientPolicy {
    pub fn parse_launch_digest_allowlist(raw: &str) -> BTreeSet<String> {
        raw.split([',', ' ', '\n', '\t'])
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect()
    }
}

fn check_window(
    trust: &EphemeralEngineTrust<'_>,
    now_ms: u64,
    skew_ms: u64,
) -> Result<(), RecipientError> {
    let not_before =
        parse_rfc3339_ms(trust.not_before).map_err(|_| RecipientError::InvalidTimestamp)?;
    let not_after =
        parse_rfc3339_ms(trust.not_after).map_err(|_| RecipientError::InvalidTimestamp)?;
    // RB-49.3: when sealed time is on, a floor past not_after cannot be rescued by skew.
    let sealed_floor = if sealed_time_enabled_from_env() {
        SealedTimeStore::from_env().read_floor_ms().ok().flatten()
    } else {
        None
    };
    if !epoch_window_active(now_ms, not_before, not_after, skew_ms, sealed_floor) {
        return Err(RecipientError::EpochNotActive);
    }
    Ok(())
}

fn check_launch_digest(
    policy: &EngineRecipientPolicy,
    quote: Option<&str>,
) -> Result<Option<String>, RecipientError> {
    if !policy.require_launch_digest && policy.launch_digest_allowlist.is_empty() {
        // Measurement pin disabled: still surface the digest when readable so
        // callers can log what they encrypted to.
        return Ok(quote.and_then(launch_digest_from_snp_quote));
    }
    if policy.launch_digest_allowlist.is_empty() {
        return Err(RecipientError::LaunchDigestAllowlistMissing);
    }
    let digest = quote
        .and_then(launch_digest_from_snp_quote)
        .ok_or(RecipientError::LaunchDigestUnreadable)?;
    if !policy.launch_digest_allowlist.contains(&digest) {
        return Err(RecipientError::LaunchDigestNotAllowed(digest));
    }
    Ok(Some(digest))
}

/// Decide whether customer plaintext may be encrypted to this epoch.
///
/// `nonce` is the challenge the evidence was minted against, when the caller
/// issued one; `None` for relayed connect- or rotation-scoped evidence.
pub fn accept_engine_recipient(
    policy: &EngineRecipientPolicy,
    trust: &EphemeralEngineTrust<'_>,
    attestation_quote: Option<&str>,
    nonce: Option<&str>,
    now_ms: u64,
) -> Result<AcceptedRecipient, RecipientError> {
    check_window(trust, now_ms, policy.epoch_clock_skew_ms)?;
    let launch_digest = check_launch_digest(policy, attestation_quote)?;

    let subject = EpochEvidenceSubject {
        engine_id: trust.engine_id,
        epoch_id: trust.epoch_id,
        not_before: trust.not_before,
        not_after: trust.not_after,
        mlkem_encapsulation_key: trust.mlkem_encapsulation_key,
        x25519_public: trust.x25519_public,
    };

    match attestation_quote.map(|q| verify_epoch_evidence(q, &subject, nonce)) {
        Some(Ok(verified)) => Ok(AcceptedRecipient {
            via: RecipientTrustVia::EpochEvidence,
            epoch: Some(verified.epoch),
            report_b64: Some(verified.report_b64),
            launch_digest,
        }),
        // Evidence that exists but describes another epoch is an attack signal,
        // never a reason to fall back to the weaker check.
        Some(Err(e)) if e != EpochEvidenceError::Absent => Err(RecipientError::EpochEvidence(e)),
        _ => {
            // Stage 5 and Stage 3 both refuse identity-only admit. Stage 5 also
            // makes leftover/stale pins inert even if an operator left them set.
            if policy.require_epoch_evidence || policy.stage5_identity_deleted {
                return Err(RecipientError::EpochEvidenceRequired);
            }
            verify_ephemeral_engine_trust(
                &policy.identity_pins,
                trust,
                now_ms,
                policy.epoch_clock_skew_ms,
            )
            .map_err(RecipientError::Identity)?;
            Ok(AcceptedRecipient {
                via: RecipientTrustVia::IdentitySignature,
                epoch: None,
                report_b64: None,
                launch_digest,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    use crate::challenge::SNP_REPORT_DATA_OFFSET;
    use crate::engine_trust::ephemeral_signing_bytes;
    use crate::epoch_evidence::bind_epoch_report_data_64;

    const NOT_BEFORE: &str = "2026-07-31T00:00:00.000Z";
    const NOT_AFTER: &str = "2026-08-30T00:00:00.000Z";
    const NOW: &str = "2026-08-01T00:00:00.000Z";
    const TLS_HASH: &str = "cc";
    const ISSUED_AT: &str = "2026-07-31T00:00:00.000Z";
    const MEASUREMENT_OFFSET: usize = 0x90;

    fn now_ms() -> u64 {
        parse_rfc3339_ms(NOW).unwrap()
    }

    fn epoch_claims() -> QuoteEpochClaims {
        QuoteEpochClaims {
            engine_id: "engine-1".into(),
            epoch_id: "epoch-1".into(),
            not_before: NOT_BEFORE.into(),
            not_after: NOT_AFTER.into(),
            mlkem_encapsulation_key: "bWxrZW0".into(),
            x25519_public: "eDI1NTE5".into(),
            usage_signing_public: "dXNhZ2U".into(),
        }
    }

    fn trust_for(claims: &QuoteEpochClaims) -> EphemeralEngineTrust<'_> {
        EphemeralEngineTrust {
            engine_id: &claims.engine_id,
            epoch_id: &claims.epoch_id,
            not_before: &claims.not_before,
            not_after: &claims.not_after,
            mlkem_encapsulation_key: &claims.mlkem_encapsulation_key,
            x25519_public: &claims.x25519_public,
            ed25519_public: "",
            identity_signature: "",
        }
    }

    fn measurement(byte: u8) -> Vec<u8> {
        vec![byte; 48]
    }

    fn expected_launch_digest(byte: u8) -> String {
        hex::encode(Sha256::digest(hex::encode(measurement(byte)).as_bytes()))
    }

    fn quote_with(
        claims: Option<&QuoteEpochClaims>,
        nonce: Option<&str>,
        measurement_byte: u8,
    ) -> String {
        let mut report = vec![0u8; 1184];
        report[MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + 48]
            .copy_from_slice(&measurement(measurement_byte));
        let mut wrapper_claims = json!({
            "v": 1,
            "kind": "sev-snp",
            "ed25519_public": "aWQ",
            "tls_client_cert_sha256": TLS_HASH,
            "engine": { "version": "0.12.1", "binary_sha256": "" },
            "vllm": { "version": "v1", "binary_sha256": "" },
            "issued_at": ISSUED_AT,
        });
        let mut report_data = vec![0u8; 64];
        if let Some(c) = claims {
            wrapper_claims["epoch"] = serde_json::to_value(c).unwrap();
            report_data = bind_epoch_report_data_64(c, TLS_HASH, "", "", ISSUED_AT, nonce).to_vec();
        }
        report[SNP_REPORT_DATA_OFFSET..SNP_REPORT_DATA_OFFSET + 64].copy_from_slice(&report_data);
        URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "v": 2,
                "kind": "sev-snp",
                "report_b64": STANDARD.encode(&report),
                "report_data_b64": STANDARD.encode(&report_data),
                "claims": wrapper_claims,
            }))
            .unwrap(),
        )
    }

    fn strict_policy() -> EngineRecipientPolicy {
        EngineRecipientPolicy {
            require_epoch_evidence: true,
            require_launch_digest: true,
            launch_digest_allowlist: [expected_launch_digest(0xab)].into_iter().collect(),
            epoch_clock_skew_ms: 300_000,
            ..Default::default()
        }
    }

    #[test]
    fn accepts_an_epoch_the_report_names_from_an_allowlisted_image() {
        let claims = epoch_claims();
        let accepted = accept_engine_recipient(
            &strict_policy(),
            &trust_for(&claims),
            Some(&quote_with(Some(&claims), None, 0xab)),
            None,
            now_ms(),
        )
        .expect("accepted");
        assert_eq!(accepted.via, RecipientTrustVia::EpochEvidence);
        assert_eq!(accepted.epoch.as_ref(), Some(&claims));
        assert_eq!(accepted.launch_digest, Some(expected_launch_digest(0xab)));
        assert!(accepted.report_b64.is_some());
    }

    #[test]
    fn refuses_an_engine_whose_image_is_not_allowlisted() {
        // The rogue-relay case: real hardware, real epoch binding, wrong build.
        let claims = epoch_claims();
        let err = accept_engine_recipient(
            &strict_policy(),
            &trust_for(&claims),
            Some(&quote_with(Some(&claims), None, 0x01)),
            None,
            now_ms(),
        )
        .unwrap_err();
        assert!(matches!(err, RecipientError::LaunchDigestNotAllowed(_)));
    }

    #[test]
    fn refuses_connect_scoped_evidence_when_epoch_evidence_is_required() {
        let claims = epoch_claims();
        assert_eq!(
            accept_engine_recipient(
                &strict_policy(),
                &trust_for(&claims),
                Some(&quote_with(None, None, 0xab)),
                None,
                now_ms(),
            )
            .unwrap_err(),
            RecipientError::EpochEvidenceRequired
        );
    }

    #[test]
    fn refuses_an_epoch_with_no_attestation_at_all() {
        let claims = epoch_claims();
        assert_eq!(
            accept_engine_recipient(&strict_policy(), &trust_for(&claims), None, None, now_ms())
                .unwrap_err(),
            RecipientError::LaunchDigestUnreadable
        );
    }

    #[test]
    fn refuses_keys_swapped_in_behind_valid_evidence() {
        let claims = epoch_claims();
        let quote = quote_with(Some(&claims), None, 0xab);
        let substituted = EphemeralEngineTrust {
            x25519_public: "relay-key",
            ..trust_for(&claims)
        };
        assert_eq!(
            accept_engine_recipient(&strict_policy(), &substituted, Some(&quote), None, now_ms())
                .unwrap_err(),
            RecipientError::EpochEvidence(EpochEvidenceError::X25519Mismatch)
        );
    }

    #[test]
    fn broken_evidence_never_falls_back_to_the_identity_pin() {
        let claims = epoch_claims();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let public = URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes());
        let mut trust = trust_for(&claims);
        trust.ed25519_public = Box::leak(public.clone().into_boxed_str());
        let signature =
            URL_SAFE_NO_PAD.encode(key.sign(&ephemeral_signing_bytes(&trust)).to_bytes());
        trust.identity_signature = Box::leak(signature.into_boxed_str());

        let mut lenient = strict_policy();
        lenient.require_epoch_evidence = false;
        lenient.identity_pins =
            EngineIdentityPins::parse_json(&format!(r#"{{"engine-1":"{public}"}}"#)).unwrap();

        let other = QuoteEpochClaims {
            epoch_id: "epoch-other".into(),
            ..epoch_claims()
        };
        let err = accept_engine_recipient(
            &lenient,
            &trust,
            Some(&quote_with(Some(&other), None, 0xab)),
            None,
            now_ms(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            RecipientError::EpochEvidence(EpochEvidenceError::EpochMismatch)
        );
    }

    #[test]
    fn compatibility_window_accepts_a_pinned_identity_signature() {
        let claims = epoch_claims();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let public = URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes());
        let mut trust = trust_for(&claims);
        trust.ed25519_public = Box::leak(public.clone().into_boxed_str());
        let signature =
            URL_SAFE_NO_PAD.encode(key.sign(&ephemeral_signing_bytes(&trust)).to_bytes());
        trust.identity_signature = Box::leak(signature.into_boxed_str());

        let policy = EngineRecipientPolicy {
            require_epoch_evidence: false,
            identity_pins: EngineIdentityPins::parse_json(&format!(r#"{{"engine-1":"{public}"}}"#))
                .unwrap(),
            epoch_clock_skew_ms: 300_000,
            ..Default::default()
        };
        let accepted = accept_engine_recipient(
            &policy,
            &trust,
            Some(&quote_with(None, None, 0xab)),
            None,
            now_ms(),
        )
        .expect("accepted");
        assert_eq!(accepted.via, RecipientTrustVia::IdentitySignature);
    }

    /// RB-52 case 52.1 / 52.2 — identity-only (connect quote + valid pin) is
    /// refused once Stage 5 is on; `OPE-ENGINE-EPHEMERAL-v1` is not an admit path.
    #[test]
    fn stage5_refuses_identity_only_even_with_matching_pins() {
        let claims = epoch_claims();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let public = URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes());
        let mut trust = trust_for(&claims);
        trust.ed25519_public = Box::leak(public.clone().into_boxed_str());
        let signature =
            URL_SAFE_NO_PAD.encode(key.sign(&ephemeral_signing_bytes(&trust)).to_bytes());
        trust.identity_signature = Box::leak(signature.into_boxed_str());

        let policy = EngineRecipientPolicy {
            require_epoch_evidence: false,
            stage5_identity_deleted: true,
            identity_pins: EngineIdentityPins::parse_json(&format!(r#"{{"engine-1":"{public}"}}"#))
                .unwrap(),
            epoch_clock_skew_ms: 300_000,
            ..Default::default()
        };
        assert_eq!(
            accept_engine_recipient(
                &policy,
                &trust,
                Some(&quote_with(None, None, 0xab)),
                None,
                now_ms(),
            )
            .unwrap_err(),
            RecipientError::EpochEvidenceRequired
        );
    }

    /// RB-52 case 52.3 — empty or stale pin env must not admit under Stage 5.
    #[test]
    fn stage5_empty_or_stale_pins_do_not_admit() {
        let claims = epoch_claims();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let public = URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes());
        let mut trust = trust_for(&claims);
        trust.ed25519_public = Box::leak(public.clone().into_boxed_str());
        let signature =
            URL_SAFE_NO_PAD.encode(key.sign(&ephemeral_signing_bytes(&trust)).to_bytes());
        trust.identity_signature = Box::leak(signature.into_boxed_str());

        let empty = EngineRecipientPolicy {
            require_epoch_evidence: false,
            stage5_identity_deleted: true,
            identity_pins: EngineIdentityPins::default(),
            epoch_clock_skew_ms: 300_000,
            ..Default::default()
        };
        assert_eq!(
            accept_engine_recipient(
                &empty,
                &trust,
                Some(&quote_with(None, None, 0xab)),
                None,
                now_ms(),
            )
            .unwrap_err(),
            RecipientError::EpochEvidenceRequired
        );

        let stale = EngineRecipientPolicy {
            require_epoch_evidence: false,
            stage5_identity_deleted: true,
            // Wrong pin for this identity — must still refuse as evidence-required,
            // not as IdentityPinMismatch (pins are inert after Stage 5).
            identity_pins: EngineIdentityPins::parse_json(
                r#"{"engine-1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
            )
            .unwrap(),
            epoch_clock_skew_ms: 300_000,
            ..Default::default()
        };
        assert_eq!(
            accept_engine_recipient(
                &stale,
                &trust,
                Some(&quote_with(None, None, 0xab)),
                None,
                now_ms(),
            )
            .unwrap_err(),
            RecipientError::EpochEvidenceRequired
        );
    }

    #[test]
    fn refuses_an_expired_epoch_before_looking_at_evidence() {
        let claims = epoch_claims();
        let late = parse_rfc3339_ms("2026-09-30T00:00:00.000Z").unwrap();
        assert_eq!(
            accept_engine_recipient(
                &strict_policy(),
                &trust_for(&claims),
                Some(&quote_with(Some(&claims), None, 0xab)),
                None,
                late,
            )
            .unwrap_err(),
            RecipientError::EpochNotActive
        );
    }

    #[test]
    fn refuses_when_the_allowlist_is_required_but_unset() {
        let claims = epoch_claims();
        let policy = EngineRecipientPolicy {
            require_launch_digest: true,
            require_epoch_evidence: true,
            epoch_clock_skew_ms: 300_000,
            ..Default::default()
        };
        assert_eq!(
            accept_engine_recipient(
                &policy,
                &trust_for(&claims),
                Some(&quote_with(Some(&claims), None, 0xab)),
                None,
                now_ms(),
            )
            .unwrap_err(),
            RecipientError::LaunchDigestAllowlistMissing
        );
    }

    #[test]
    fn binds_evidence_to_the_challenge_nonce_when_one_was_issued() {
        let claims = epoch_claims();
        let quote = quote_with(Some(&claims), Some("nonce-a"), 0xab);
        assert!(accept_engine_recipient(
            &strict_policy(),
            &trust_for(&claims),
            Some(&quote),
            Some("nonce-a"),
            now_ms()
        )
        .is_ok());
        assert_eq!(
            accept_engine_recipient(
                &strict_policy(),
                &trust_for(&claims),
                Some(&quote),
                Some("nonce-b"),
                now_ms()
            )
            .unwrap_err(),
            RecipientError::EpochEvidence(EpochEvidenceError::ReportDataMismatch)
        );
    }

    #[test]
    fn allowlist_parsing_is_forgiving_about_separators_and_case() {
        let parsed =
            EngineRecipientPolicy::parse_launch_digest_allowlist(" AABB , ccdd\nEEFF\t, , ");
        assert_eq!(
            parsed.into_iter().collect::<Vec<_>>(),
            vec!["aabb", "ccdd", "eeff"]
        );
    }
}
