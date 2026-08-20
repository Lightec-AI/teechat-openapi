//! Rust OPE encrypt/decrypt helpers for the OpenAPI edge (same crates.io pins as
//! desktop / `openapi-platform-cvm`). Pure computation — no TLS/network deps, so this
//! file is portable to the Fortanix SGX target unchanged.

use ope_crypto::{mock_keypair_from_seed, DEV_VECTOR_001_SEED};
use ope_e2e::{decrypt_response_chunk, encrypt_request, ClientSession, EngineIdentity};
use ope_envelope::{sign_envelope, Envelope};
use serde_json::{json, Value};
use thiserror::Error;

use crate::gateway_ope_api::PreassignTrust;

#[derive(Debug, Error)]
pub enum OpeWrapError {
    #[error("ope: {0}")]
    Ope(String),
    #[error("encode: {0}")]
    Encode(String),
}

pub fn normalize_kex(kex: &str) -> String {
    let t = kex.trim();
    if t.is_empty()
        || t.eq_ignore_ascii_case("mlkem768+x25519")
        || t.eq_ignore_ascii_case("x25519+mlkem768")
        || t.eq_ignore_ascii_case("X25519MLKEM768")
    {
        EngineIdentity::KEX_X25519_MLKEM768.into()
    } else {
        t.to_string()
    }
}

pub fn engine_identity_from_trust(trust: &PreassignTrust) -> EngineIdentity {
    EngineIdentity {
        engine_id: trust.engine_id.clone(),
        kex: normalize_kex(&trust.hybrid.kex),
        mlkem_encapsulation_key: trust.hybrid.mlkem_encapsulation_key.clone(),
        x25519_public: trust.hybrid.x25519_public.clone(),
        ed25519_public: trust.identity.ed25519_public.clone(),
    }
}

pub struct EncryptedOpeRequest {
    pub envelope: Envelope,
    pub client_session: ClientSession,
    pub ephemeral_epoch: String,
}

pub fn encrypt_openai_body(
    trust: &PreassignTrust,
    kid: &str,
    payload: &Value,
) -> Result<EncryptedOpeRequest, OpeWrapError> {
    encrypt_openai_body_with_path(trust, kid, payload, "/v1/chat/completions")
}

pub fn encrypt_openai_body_with_path(
    trust: &PreassignTrust,
    kid: &str,
    payload: &Value,
    openai_path: &str,
) -> Result<EncryptedOpeRequest, OpeWrapError> {
    let identity = engine_identity_from_trust(trust);
    let client_session = ClientSession::generate().map_err(|e| OpeWrapError::Ope(e.to_string()))?;

    let mut envelope = Envelope {
        ope_version: "1.0".into(),
        alg: "EdDSA".into(),
        enc: "none".into(),
        kid: "prod-bootstrap".into(),
        recipient: "teechat-gateway".into(),
        engine_id: Some(identity.engine_id.clone()),
        ts: chrono_like_now(),
        nonce: uuid_v4_simple(),
        payload_hash: String::new(),
        payload: None,
        ciphertext: None,
        iv: None,
        aad: None,
        meta: Some(json!({
            "model": payload.get("model").cloned().unwrap_or(Value::Null),
            "openai_path": openai_path,
            "openapi_key_id": kid,
        })),
        e2e: None,
        sig: None,
    };

    encrypt_request(&mut envelope, &identity, payload, Some(&client_session))
        .map_err(|e| OpeWrapError::Ope(e.to_string()))?;

    // Merge ephemeral_epoch into e2e (required by engine gate).
    if let Some(e2e) = envelope.e2e.as_mut() {
        if let Some(obj) = e2e.as_object_mut() {
            obj.insert("ephemeral_epoch".into(), json!(trust.epoch_id));
        }
    }

    // RB-47: sign over engine_id and e2e after the epoch is in `e2e`.
    // Kid is the engine trust map key (`prod-bootstrap`). Prod must sign with
    // the same seed as desktop (`OPENAPI_OPE_ENVELOPE_SIGNING_SEED_HEX`), not
    // DEV_VECTOR_001 — that public key is forbidden on the live trust map
    // (`ope_invalid_signature` on 0.11.0).
    let kp = mock_keypair_from_seed(&envelope_signing_seed()?);
    sign_envelope(&mut envelope, &kp.secret).map_err(|e| OpeWrapError::Ope(e.to_string()))?;

    Ok(EncryptedOpeRequest {
        envelope,
        client_session,
        ephemeral_epoch: trust.epoch_id.clone(),
    })
}

pub fn envelope_to_bytes(envelope: &Envelope) -> Result<Vec<u8>, OpeWrapError> {
    serde_json::to_vec(envelope).map_err(|e| OpeWrapError::Encode(e.to_string()))
}

pub fn decrypt_chunk(
    request_envelope: &Envelope,
    client_session: &ClientSession,
    server_share: &str,
    seq: u32,
    ciphertext: &str,
) -> Result<Vec<u8>, OpeWrapError> {
    decrypt_response_chunk(
        request_envelope,
        client_session,
        server_share,
        seq,
        ciphertext,
    )
    .map_err(|e| OpeWrapError::Ope(e.to_string()))
}

fn parse_signing_seed_hex(hex: &str) -> Result<[u8; 32], OpeWrapError> {
    let raw = hex.trim().to_ascii_lowercase();
    if raw.len() != 64 || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(OpeWrapError::Ope(
            "OPENAPI_OPE_ENVELOPE_SIGNING_SEED_HEX must be 64 hex characters".into(),
        ));
    }
    let bytes = hex::decode(&raw).map_err(|e| OpeWrapError::Ope(format!("signing seed hex: {e}")))?;
    let seed: [u8; 32] = bytes.try_into().map_err(|_| {
        OpeWrapError::Ope("OPENAPI_OPE_ENVELOPE_SIGNING_SEED_HEX must decode to 32 bytes".into())
    })?;
    Ok(seed)
}

fn edge_profile_is_prod() -> bool {
    matches!(
        std::env::var("OPENAPI_PROFILE")
            .ok()
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref(),
        Some("prod") | Some("production")
    )
}

/// Prod: data-disk seed matching desktop `VITE_OPE_ENVELOPE_SIGNING_SEED_HEX`.
/// Non-prod: DEV_VECTOR_001 when unset (unit tests / lab).
fn envelope_signing_seed() -> Result<[u8; 32], OpeWrapError> {
    let raw = std::env::var("OPENAPI_OPE_ENVELOPE_SIGNING_SEED_HEX")
        .ok()
        .or_else(|| std::env::var("TEECHAT_OPE_ENVELOPE_SIGNING_SEED_HEX").ok())
        .unwrap_or_default();
    let raw = raw.trim();
    let prod = edge_profile_is_prod();
    if raw.is_empty() {
        if prod {
            return Err(OpeWrapError::Ope(
                "OPENAPI_OPE_ENVELOPE_SIGNING_SEED_HEX is required in prod \
                 (desktop prod-bootstrap seed; not DEV_VECTOR_001)"
                    .into(),
            ));
        }
        return Ok(DEV_VECTOR_001_SEED);
    }
    let seed = parse_signing_seed_hex(raw)?;
    if prod && seed == DEV_VECTOR_001_SEED {
        return Err(OpeWrapError::Ope(
            "OPENAPI_OPE_ENVELOPE_SIGNING_SEED_HEX must not be DEV_VECTOR_001 in prod"
                .into(),
        ));
    }
    Ok(seed)
}

pub(crate) fn chrono_like_now() -> String {
    // Must be real RFC3339 — ope-envelope::verify_timestamp parses with chrono.
    // (A prior `{unix_secs}.000Z` form caused live `ope_invalid_timestamp` / client timeouts.)
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn uuid_v4_simple() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
        b[14], b[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ope_crypto::encode;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());
    use ope_e2e::{
        begin_response_session_from_share, decrypt_request, encrypt_response_chunk,
        mock_engine_from_seed, DEV_ENGINE_SEED,
    };

    #[test]
    fn normalize_kex_aliases() {
        assert_eq!(
            normalize_kex("mlkem768+x25519"),
            EngineIdentity::KEX_X25519_MLKEM768
        );
        assert_eq!(normalize_kex(""), EngineIdentity::KEX_X25519_MLKEM768);
    }

    /// Regression: 0.10.4 used `format!("{secs}.000Z")`, which OPE rejects as
    /// `ope_invalid_timestamp` once envelopes are signed (`signed-only` VERIFY).
    #[test]
    fn chrono_like_now_is_rfc3339_not_unix_secs_dot_z() {
        let ts = chrono_like_now();
        let parsed = ts
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap_or_else(|e| panic!("ts must parse as RFC3339, got {ts:?}: {e}"));
        assert!(
            ts.contains('T') && ts.ends_with('Z'),
            "expected RFC3339 millis UTC, got {ts}"
        );
        let unix_bogus = format!(
            "{}.000Z",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
        assert!(
            unix_bogus.parse::<chrono::DateTime<chrono::Utc>>().is_err(),
            "precondition: legacy shape must stay unparseable"
        );
        assert_ne!(ts, unix_bogus);
        assert!(
            !ts.chars().all(|c| c.is_ascii_digit() || c == '.' || c == 'Z'),
            "ts must not be unix-secs.000Z, got {ts}"
        );
        let skew = (chrono::Utc::now() - parsed).num_seconds().abs();
        assert!(skew < 5, "ts should be wall-clock now, skew={skew}s ts={ts}");
    }

    #[test]
    fn encrypt_sets_rfc3339_ts_compatible_with_ope_verify() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("OPENAPI_PROFILE");
        std::env::remove_var("OPENAPI_OPE_ENVELOPE_SIGNING_SEED_HEX");
        std::env::remove_var("TEECHAT_OPE_ENVELOPE_SIGNING_SEED_HEX");
        let (_engine_secret, identity) = mock_engine_from_seed(&DEV_ENGINE_SEED);
        let trust = PreassignTrust {
            engine_id: identity.engine_id.clone(),
            epoch_id: "epoch-test".into(),
            not_before: "2026-07-30T08:00:00.000Z".into(),
            not_after: "2026-07-30T10:00:00.000Z".into(),
            hybrid: crate::gateway_ope_api::PreassignTrustHybrid {
                kex: identity.kex.clone(),
                mlkem_encapsulation_key: identity.mlkem_encapsulation_key.clone(),
                x25519_public: identity.x25519_public.clone(),
            },
            identity: crate::gateway_ope_api::PreassignTrustIdentity {
                ed25519_public: identity.ed25519_public.clone(),
                identity_signature: String::new(),
            },
            attestation: None,
        };
        let payload = json!({
            "model": "m1",
            "messages": [{"role":"user","content":"hi"}]
        });
        let enc = encrypt_openai_body(&trust, "tcak_test", &payload).unwrap();
        ope_envelope::verify_envelope(
            &enc.envelope,
            &mock_keypair_from_seed(&DEV_VECTOR_001_SEED).public,
            &ope_envelope::VerifyOptions {
                max_skew: std::time::Duration::from_secs(300),
                expected_recipient: Some("teechat-gateway".into()),
                opaque_e2e: true,
                ..ope_envelope::VerifyOptions::with_defaults()
            },
        )
        .unwrap_or_else(|e| panic!("signed edge envelope must verify (ts/sig): {e}"));
    }

    #[test]
    fn encrypt_decrypt_roundtrip_with_mock_engine() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("OPENAPI_PROFILE");
        std::env::remove_var("OPENAPI_OPE_ENVELOPE_SIGNING_SEED_HEX");
        std::env::remove_var("TEECHAT_OPE_ENVELOPE_SIGNING_SEED_HEX");
        let (engine_secret, identity) = mock_engine_from_seed(&DEV_ENGINE_SEED);
        let trust = PreassignTrust {
            engine_id: identity.engine_id.clone(),
            epoch_id: "epoch-test".into(),
            not_before: "2026-07-30T08:00:00.000Z".into(),
            not_after: "2026-07-30T10:00:00.000Z".into(),
            hybrid: crate::gateway_ope_api::PreassignTrustHybrid {
                kex: identity.kex.clone(),
                mlkem_encapsulation_key: identity.mlkem_encapsulation_key.clone(),
                x25519_public: identity.x25519_public.clone(),
            },
            identity: crate::gateway_ope_api::PreassignTrustIdentity {
                ed25519_public: identity.ed25519_public.clone(),
                identity_signature: String::new(),
            },
            attestation: None,
        };
        let payload = json!({
            "model": "m1",
            "messages": [{"role":"user","content":"hi"}]
        });
        let enc = encrypt_openai_body(&trust, "tcak_test", &payload).unwrap();
        assert!(
            enc.envelope.ts.contains('T') && enc.envelope.ts.ends_with('Z'),
            "envelope.ts must be RFC3339, got {}",
            enc.envelope.ts
        );
        assert!(
            enc.envelope
                .ts
                .parse::<chrono::DateTime<chrono::Utc>>()
                .is_ok(),
            "envelope.ts must parse as RFC3339, got {}",
            enc.envelope.ts
        );
        assert_eq!(enc.envelope.enc, "e2e-hybrid-pq");
        let e2e = enc.envelope.e2e.as_ref().unwrap();
        assert_eq!(
            e2e.get("ephemeral_epoch").and_then(|v| v.as_str()),
            Some("epoch-test")
        );
        assert_eq!(enc.envelope.engine_id.as_deref(), Some(identity.engine_id.as_str()));
        assert!(
            enc.envelope.sig.as_deref().is_some_and(|s| !s.is_empty()),
            "edge envelope must be signed (RB-47)"
        );
        assert_eq!(enc.envelope.kid, "prod-bootstrap");

        let decrypted = decrypt_request(&enc.envelope, &engine_secret).unwrap();
        assert_eq!(decrypted, payload);

        let client_share = e2e
            .get("client_share")
            .and_then(|v| v.as_str())
            .expect("client_share");
        let (resp_key, resp_iv, server) =
            begin_response_session_from_share(&engine_secret, &enc.envelope, client_share).unwrap();
        let server_share = encode(&server.bytes);
        let ct = encrypt_response_chunk(&resp_key, &resp_iv, 0, b"hello").unwrap();
        let plain =
            decrypt_chunk(&enc.envelope, &enc.client_session, &server_share, 0, &ct).unwrap();
        assert_eq!(plain, b"hello");
    }

    #[test]
    fn prod_without_signing_seed_fails_closed() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("OPENAPI_OPE_ENVELOPE_SIGNING_SEED_HEX");
        std::env::remove_var("TEECHAT_OPE_ENVELOPE_SIGNING_SEED_HEX");
        std::env::set_var("OPENAPI_PROFILE", "prod");
        let err = envelope_signing_seed().unwrap_err().to_string();
        std::env::remove_var("OPENAPI_PROFILE");
        assert!(err.contains("required in prod"), "{err}");
    }

    #[test]
    fn prod_rejects_vector001_seed() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("OPENAPI_PROFILE", "prod");
        std::env::set_var(
            "OPENAPI_OPE_ENVELOPE_SIGNING_SEED_HEX",
            "01".repeat(32),
        );
        let err = envelope_signing_seed().unwrap_err().to_string();
        std::env::remove_var("OPENAPI_PROFILE");
        std::env::remove_var("OPENAPI_OPE_ENVELOPE_SIGNING_SEED_HEX");
        assert!(err.contains("DEV_VECTOR_001"), "{err}");
    }

    #[test]
    fn custom_seed_verifies_with_that_public_not_vector001() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("OPENAPI_PROFILE");
        let seed = [2u8; 32];
        std::env::set_var(
            "OPENAPI_OPE_ENVELOPE_SIGNING_SEED_HEX",
            hex::encode(seed),
        );
        let (_engine_secret, identity) = mock_engine_from_seed(&DEV_ENGINE_SEED);
        let trust = PreassignTrust {
            engine_id: identity.engine_id.clone(),
            epoch_id: "epoch-test".into(),
            not_before: "2026-07-30T08:00:00.000Z".into(),
            not_after: "2026-07-30T10:00:00.000Z".into(),
            hybrid: crate::gateway_ope_api::PreassignTrustHybrid {
                kex: identity.kex.clone(),
                mlkem_encapsulation_key: identity.mlkem_encapsulation_key.clone(),
                x25519_public: identity.x25519_public.clone(),
            },
            identity: crate::gateway_ope_api::PreassignTrustIdentity {
                ed25519_public: identity.ed25519_public.clone(),
                identity_signature: String::new(),
            },
            attestation: None,
        };
        let payload = json!({"model": "m1", "messages": [{"role":"user","content":"hi"}]});
        let enc = encrypt_openai_body(&trust, "tcak_test", &payload).unwrap();
        std::env::remove_var("OPENAPI_OPE_ENVELOPE_SIGNING_SEED_HEX");
        let opts = ope_envelope::VerifyOptions {
            max_skew: std::time::Duration::from_secs(300),
            expected_recipient: Some("teechat-gateway".into()),
            opaque_e2e: true,
            ..ope_envelope::VerifyOptions::with_defaults()
        };
        ope_envelope::verify_envelope(
            &enc.envelope,
            &mock_keypair_from_seed(&seed).public,
            &opts,
        )
        .expect("custom seed must verify");
        assert!(
            ope_envelope::verify_envelope(
                &enc.envelope,
                &mock_keypair_from_seed(&DEV_VECTOR_001_SEED).public,
                &opts,
            )
            .is_err(),
            "vector-001 must not verify a custom-seed signature"
        );
    }
}
