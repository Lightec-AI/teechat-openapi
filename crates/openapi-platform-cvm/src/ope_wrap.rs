//! Rust OPE encrypt/decrypt helpers for the OpenAPI edge (same crates.io pins as desktop).

use ope_e2e::{decrypt_response_chunk, encrypt_request, ClientSession, EngineIdentity};
use ope_envelope::Envelope;
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
    let identity = engine_identity_from_trust(trust);
    let client_session = ClientSession::generate().map_err(|e| OpeWrapError::Ope(e.to_string()))?;

    let mut envelope = Envelope {
        ope_version: "1.0".into(),
        alg: "EdDSA".into(),
        enc: "none".into(),
        kid: kid.into(),
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

fn chrono_like_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    // RFC3339-ish UTC without chrono dep — engines accept ISO-ish timestamps.
    let secs = ms / 1000;
    format!("{secs}.000Z")
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

    #[test]
    fn encrypt_decrypt_roundtrip_with_mock_engine() {
        let (engine_secret, identity) = mock_engine_from_seed(&DEV_ENGINE_SEED);
        let trust = PreassignTrust {
            engine_id: identity.engine_id.clone(),
            epoch_id: "epoch-test".into(),
            not_before: None,
            not_after: None,
            hybrid: crate::gateway_ope_api::PreassignTrustHybrid {
                kex: identity.kex.clone(),
                mlkem_encapsulation_key: identity.mlkem_encapsulation_key.clone(),
                x25519_public: identity.x25519_public.clone(),
            },
            identity: crate::gateway_ope_api::PreassignTrustIdentity {
                ed25519_public: identity.ed25519_public.clone(),
                identity_signature: None,
            },
        };
        let payload = json!({
            "model": "m1",
            "messages": [{"role":"user","content":"hi"}]
        });
        let enc = encrypt_openai_body(&trust, "tcak_test", &payload).unwrap();
        assert_eq!(enc.envelope.enc, "e2e-hybrid-pq");
        let e2e = enc.envelope.e2e.as_ref().unwrap();
        assert_eq!(
            e2e.get("ephemeral_epoch").and_then(|v| v.as_str()),
            Some("epoch-test")
        );

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
}
