//! Verification of gateway-preassigned engine ephemeral identities.
//!
//! The stable Ed25519 identity pins are part of the OpenAPI runtime-policy hash.
//! A signed OpenAPI allowlist therefore authorizes the pinned identity set, while
//! each engine signs its short-lived hybrid keys with `OPE-ENGINE-EPHEMERAL-v1`.

use std::collections::BTreeMap;

use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const EPHEMERAL_DOMAIN: &str = "OPE-ENGINE-EPHEMERAL-v1";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct EngineIdentityPins(BTreeMap<String, String>);

impl EngineIdentityPins {
    pub fn parse_json(raw: &str) -> Result<Self, EngineTrustError> {
        let pins: BTreeMap<String, String> = serde_json::from_str(raw)
            .map_err(|e| EngineTrustError::InvalidPinsJson(e.to_string()))?;
        for (engine_id, public_key) in &pins {
            if engine_id.trim().is_empty() {
                return Err(EngineTrustError::InvalidPinsJson(
                    "engine id must not be empty".into(),
                ));
            }
            decode_public_key(public_key)?;
        }
        Ok(Self(pins))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn policy_hash_hex(&self) -> String {
        let canonical = serde_json::to_vec(&self.0).expect("BTreeMap serializes");
        hex::encode(Sha256::digest(canonical))
    }

    pub fn pinned_public_key(&self, engine_id: &str) -> Option<&str> {
        self.0.get(engine_id).map(String::as_str)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EphemeralEngineTrust<'a> {
    pub engine_id: &'a str,
    pub epoch_id: &'a str,
    pub not_before: &'a str,
    pub not_after: &'a str,
    pub mlkem_encapsulation_key: &'a str,
    pub x25519_public: &'a str,
    pub ed25519_public: &'a str,
    pub identity_signature: &'a str,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EngineTrustError {
    #[error("invalid engine identity pins JSON: {0}")]
    InvalidPinsJson(String),
    #[error("engine identity pins are required")]
    MissingPins,
    #[error("engine {0:?} has no pinned identity")]
    UnpinnedEngine(String),
    #[error("engine identity key does not match the signed runtime-policy pin")]
    IdentityPinMismatch,
    #[error("invalid Ed25519 public key")]
    InvalidPublicKey,
    #[error("invalid engine identity signature")]
    InvalidIdentitySignature,
    #[error("invalid engine epoch timestamp")]
    InvalidTimestamp,
    #[error("engine epoch is not active")]
    EpochNotActive,
}

pub fn ephemeral_signing_bytes(trust: &EphemeralEngineTrust<'_>) -> Vec<u8> {
    [
        EPHEMERAL_DOMAIN,
        trust.engine_id,
        trust.epoch_id,
        trust.not_after,
        trust.mlkem_encapsulation_key,
        trust.x25519_public,
    ]
    .join("\0")
    .into_bytes()
}

pub fn verify_ephemeral_engine_trust(
    pins: &EngineIdentityPins,
    trust: &EphemeralEngineTrust<'_>,
    now_ms: u64,
    clock_skew_ms: u64,
) -> Result<(), EngineTrustError> {
    if pins.is_empty() {
        return Err(EngineTrustError::MissingPins);
    }
    let pinned = pins
        .pinned_public_key(trust.engine_id)
        .ok_or_else(|| EngineTrustError::UnpinnedEngine(trust.engine_id.to_string()))?;
    let pinned_bytes = decode_public_key(pinned)?;
    let presented_bytes = decode_public_key(trust.ed25519_public)?;
    if pinned_bytes != presented_bytes {
        return Err(EngineTrustError::IdentityPinMismatch);
    }

    let not_before = parse_rfc3339_ms(trust.not_before)?;
    let not_after = parse_rfc3339_ms(trust.not_after)?;
    if not_before > not_after
        || now_ms < not_before.saturating_sub(clock_skew_ms)
        || now_ms > not_after.saturating_add(clock_skew_ms)
    {
        return Err(EngineTrustError::EpochNotActive);
    }

    let key =
        VerifyingKey::from_bytes(&pinned_bytes).map_err(|_| EngineTrustError::InvalidPublicKey)?;
    let signature_bytes = decode_base64url(trust.identity_signature)
        .map_err(|_| EngineTrustError::InvalidIdentitySignature)?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| EngineTrustError::InvalidIdentitySignature)?;
    key.verify(&ephemeral_signing_bytes(trust), &signature)
        .map_err(|_| EngineTrustError::InvalidIdentitySignature)
}

fn decode_base64url(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
}

fn decode_public_key(value: &str) -> Result<[u8; 32], EngineTrustError> {
    let bytes = decode_base64url(value).map_err(|_| EngineTrustError::InvalidPublicKey)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| EngineTrustError::InvalidPublicKey)
}

pub(crate) fn parse_rfc3339_ms(value: &str) -> Result<u64, EngineTrustError> {
    let (date, time) = value
        .trim()
        .strip_suffix('Z')
        .and_then(|v| v.split_once('T'))
        .ok_or(EngineTrustError::InvalidTimestamp)?;
    let mut date_parts = date.split('-');
    let year: i64 = parse_part(date_parts.next())?;
    let month: u32 = parse_part(date_parts.next())?;
    let day: u32 = parse_part(date_parts.next())?;
    if date_parts.next().is_some()
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
    {
        return Err(EngineTrustError::InvalidTimestamp);
    }

    let mut time_parts = time.split(':');
    let hour: u32 = parse_part(time_parts.next())?;
    let minute: u32 = parse_part(time_parts.next())?;
    let second_and_fraction = time_parts
        .next()
        .ok_or(EngineTrustError::InvalidTimestamp)?;
    if time_parts.next().is_some() || hour > 23 || minute > 59 {
        return Err(EngineTrustError::InvalidTimestamp);
    }
    let (second_raw, fraction) = second_and_fraction
        .split_once('.')
        .map_or((second_and_fraction, ""), |(s, f)| (s, f));
    let second: u32 = second_raw
        .parse()
        .map_err(|_| EngineTrustError::InvalidTimestamp)?;
    if second > 59 || (!fraction.is_empty() && !fraction.bytes().all(|b| b.is_ascii_digit())) {
        return Err(EngineTrustError::InvalidTimestamp);
    }
    let millis = fraction
        .bytes()
        .take(3)
        .enumerate()
        .fold(0u32, |acc, (idx, digit)| {
            acc + ((digit - b'0') as u32) * [100, 10, 1][idx]
        });

    let days = days_from_civil(year, month, day)?;
    let seconds = days
        .checked_mul(86_400)
        .and_then(|v| v.checked_add((hour as u64) * 3_600))
        .and_then(|v| v.checked_add((minute as u64) * 60))
        .and_then(|v| v.checked_add(second as u64))
        .ok_or(EngineTrustError::InvalidTimestamp)?;
    seconds
        .checked_mul(1_000)
        .and_then(|v| v.checked_add(millis as u64))
        .ok_or(EngineTrustError::InvalidTimestamp)
}

fn parse_part<T: std::str::FromStr>(value: Option<&str>) -> Result<T, EngineTrustError> {
    value
        .ok_or(EngineTrustError::InvalidTimestamp)?
        .parse()
        .map_err(|_| EngineTrustError::InvalidTimestamp)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 31,
    }
}

fn days_from_civil(year: i64, month: u32, day: u32) -> Result<u64, EngineTrustError> {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let shifted_month = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted_month as i64 + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    u64::try_from(days).map_err(|_| EngineTrustError::InvalidTimestamp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed_trust<'a>(
        key: &SigningKey,
        signature_out: &'a mut String,
    ) -> EphemeralEngineTrust<'a> {
        let public = URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes());
        let unsigned = EphemeralEngineTrust {
            engine_id: "engine-1",
            epoch_id: "epoch-1",
            not_before: "2026-07-30T08:00:00.000Z",
            not_after: "2026-07-30T10:00:00.000Z",
            mlkem_encapsulation_key: "mlkem",
            x25519_public: "x25519",
            ed25519_public: Box::leak(public.into_boxed_str()),
            identity_signature: "",
        };
        *signature_out =
            URL_SAFE_NO_PAD.encode(key.sign(&ephemeral_signing_bytes(&unsigned)).to_bytes());
        EphemeralEngineTrust {
            identity_signature: signature_out,
            ..unsigned
        }
    }

    fn pins_for(key: &SigningKey) -> EngineIdentityPins {
        EngineIdentityPins::parse_json(&format!(
            r#"{{"engine-1":"{}"}}"#,
            URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes())
        ))
        .unwrap()
    }

    #[test]
    fn verifies_pinned_active_ephemeral_identity() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut signature = String::new();
        let trust = signed_trust(&key, &mut signature);
        let now = parse_rfc3339_ms("2026-07-30T09:00:00.000Z").unwrap();
        verify_ephemeral_engine_trust(&pins_for(&key), &trust, now, 0).unwrap();
    }

    #[test]
    fn rejects_stale_epoch() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut signature = String::new();
        let trust = signed_trust(&key, &mut signature);
        let now = parse_rfc3339_ms("2026-07-30T10:10:00.000Z").unwrap();
        assert_eq!(
            verify_ephemeral_engine_trust(&pins_for(&key), &trust, now, 0),
            Err(EngineTrustError::EpochNotActive)
        );
    }

    #[test]
    fn rejects_substituted_hybrid_key_or_identity() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let other = SigningKey::from_bytes(&[8u8; 32]);
        let mut signature = String::new();
        let trust = signed_trust(&key, &mut signature);
        let now = parse_rfc3339_ms("2026-07-30T09:00:00.000Z").unwrap();
        assert_eq!(
            verify_ephemeral_engine_trust(&pins_for(&other), &trust, now, 0),
            Err(EngineTrustError::IdentityPinMismatch)
        );
        let tampered = EphemeralEngineTrust {
            x25519_public: "substituted",
            ..trust
        };
        assert_eq!(
            verify_ephemeral_engine_trust(&pins_for(&key), &tampered, now, 0),
            Err(EngineTrustError::InvalidIdentitySignature)
        );
    }
}
