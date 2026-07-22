use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenApiKeyPolicy {
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default = "default_rpm")]
    pub rpm: u32,
    /// API key set for gateway key_set×engine_set matrix. Default `"api"`.
    /// Omitted from signed authz JSON when `"api"` so legacy fixtures / caches verify.
    #[serde(
        default = "default_key_set",
        skip_serializing_if = "is_default_key_set"
    )]
    pub key_set: String,
    /// Remaining prepaid tokens for this API account (optional). When set, edge
    /// applies the near-exhaust long-context gate (QUOTA-001).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining_tokens: Option<u64>,
    /// Max concurrent in-flight completions for this account (optional hint from L0).
    /// Must stay in Family B unsigned JSON when set — Node `policyForAuthzSign` includes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_in_flight: Option<u32>,
}

fn default_rpm() -> u32 {
    120
}

fn default_key_set() -> String {
    "api".into()
}

fn is_default_key_set(s: &str) -> bool {
    s.is_empty() || s == "api"
}

impl OpenApiKeyPolicy {
    /// Catalog / legacy keys: any model, no per-key RPM cap (`rpm = 0` → unlimited).
    pub fn unrestricted() -> Self {
        Self {
            models: vec!["*".into()],
            rpm: 0,
            key_set: default_key_set(),
            remaining_tokens: None,
            max_in_flight: None,
        }
    }

    /// `true` if `model` is allowed. `"*"` allows any id. Empty list denies all (fail-closed).
    pub fn allows_model(&self, model: &str) -> bool {
        self.models
            .iter()
            .any(|entry| entry == "*" || entry == model)
    }

    /// Effective API-key RPM: `min(global, policy)`, treating either `0` as unlimited.
    pub fn effective_rpm(&self, global_rpm: u32) -> u32 {
        match (global_rpm, self.rpm) {
            (0, 0) => 0,
            (0, policy) => policy,
            (global, 0) => global,
            (global, policy) => global.min(policy),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedAuthz {
    pub authz_version: u32,
    pub key_id: String,
    pub key_hash_hex: String,
    pub account_id: String,
    pub policy: OpenApiKeyPolicy,
    pub exp_ms: u64,
    pub epoch: u64,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct UnsignedAuthz {
    authz_version: u32,
    key_id: String,
    key_hash_hex: String,
    account_id: String,
    policy: OpenApiKeyPolicy,
    exp_ms: u64,
    epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedRevocation {
    pub revoke_version: u32,
    pub key_id: String,
    pub revoked_at_ms: u64,
    pub epoch: u64,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct UnsignedRevocation {
    revoke_version: u32,
    key_id: String,
    revoked_at_ms: u64,
    epoch: u64,
}

impl SignedAuthz {
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, ApiError> {
        let unsigned = UnsignedAuthz {
            authz_version: self.authz_version,
            key_id: self.key_id.clone(),
            key_hash_hex: self.key_hash_hex.clone(),
            account_id: self.account_id.clone(),
            policy: self.policy.clone(),
            exp_ms: self.exp_ms,
            epoch: self.epoch,
        };
        serde_json::to_vec(&unsigned).map_err(|e| ApiError::Internal(e.to_string()))
    }

    pub fn verify_signature(&self, verify_key: &VerifyingKey) -> Result<(), ApiError> {
        verify_family_b(&self.unsigned_bytes()?, &self.signature_hex, verify_key)
    }
}

impl SignedRevocation {
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, ApiError> {
        let unsigned = UnsignedRevocation {
            revoke_version: self.revoke_version,
            key_id: self.key_id.clone(),
            revoked_at_ms: self.revoked_at_ms,
            epoch: self.epoch,
        };
        serde_json::to_vec(&unsigned).map_err(|e| ApiError::Internal(e.to_string()))
    }

    pub fn verify_signature(&self, verify_key: &VerifyingKey) -> Result<(), ApiError> {
        verify_family_b(&self.unsigned_bytes()?, &self.signature_hex, verify_key)
    }
}

/// Build a signed authz for unit tests (same canonical JSON as verification).
#[cfg(any(test, feature = "test-utils"))]
pub fn sign_test_authz(
    key_id: &str,
    key_hash_hex: &str,
    exp_ms: u64,
    signing_key: &ed25519_dalek::SigningKey,
) -> SignedAuthz {
    sign_test_authz_with_policy(
        key_id,
        key_hash_hex,
        exp_ms,
        OpenApiKeyPolicy {
            models: vec!["*".into()],
            rpm: 120,
            key_set: "api".into(),
            remaining_tokens: None,
            max_in_flight: None,
        },
        1,
        signing_key,
    )
}

/// Build a signed authz with an explicit L0 policy (AUTH-001 tests).
#[cfg(any(test, feature = "test-utils"))]
pub fn sign_test_authz_with_policy(
    key_id: &str,
    key_hash_hex: &str,
    exp_ms: u64,
    policy: OpenApiKeyPolicy,
    epoch: u64,
    signing_key: &ed25519_dalek::SigningKey,
) -> SignedAuthz {
    use ed25519_dalek::Signer;

    let unsigned = UnsignedAuthz {
        authz_version: 1,
        key_id: key_id.into(),
        key_hash_hex: key_hash_hex.into(),
        account_id: "usr".into(),
        policy,
        exp_ms,
        epoch,
    };
    let payload = serde_json::to_vec(&unsigned).unwrap();
    let sig = signing_key.sign(&payload);
    SignedAuthz {
        authz_version: unsigned.authz_version,
        key_id: unsigned.key_id,
        key_hash_hex: unsigned.key_hash_hex,
        account_id: unsigned.account_id,
        policy: unsigned.policy,
        exp_ms: unsigned.exp_ms,
        epoch: unsigned.epoch,
        signature_hex: hex::encode(sig.to_bytes()),
    }
}

/// Build a signed revocation for unit tests.
#[cfg(any(test, feature = "test-utils"))]
pub fn sign_test_revocation(
    key_id: &str,
    revoked_at_ms: u64,
    epoch: u64,
    signing_key: &ed25519_dalek::SigningKey,
) -> SignedRevocation {
    use ed25519_dalek::Signer;

    let unsigned = UnsignedRevocation {
        revoke_version: 1,
        key_id: key_id.into(),
        revoked_at_ms,
        epoch,
    };
    let payload = serde_json::to_vec(&unsigned).unwrap();
    let sig = signing_key.sign(&payload);
    SignedRevocation {
        revoke_version: unsigned.revoke_version,
        key_id: unsigned.key_id,
        revoked_at_ms: unsigned.revoked_at_ms,
        epoch: unsigned.epoch,
        signature_hex: hex::encode(sig.to_bytes()),
    }
}

pub fn verify_family_b(
    payload: &[u8],
    signature_hex: &str,
    verify_key: &VerifyingKey,
) -> Result<(), ApiError> {
    let sig_bytes = hex::decode(signature_hex)
        .map_err(|e| ApiError::Internal(format!("invalid signature hex: {e}")))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| ApiError::Internal(format!("invalid signature: {e}")))?;
    verify_key
        .verify(payload, &signature)
        .map_err(|_| ApiError::Internal("family B signature invalid".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    #[test]
    fn max_in_flight_in_signed_authz_roundtrip() {
        let signing = SigningKey::generate(&mut OsRng);
        let verify_key = signing.verifying_key();
        let unsigned = UnsignedAuthz {
            authz_version: 1,
            key_id: "tcak_test01".into(),
            key_hash_hex: "ab".repeat(32),
            account_id: "usr".into(),
            policy: OpenApiKeyPolicy {
                models: vec!["*".into()],
                rpm: 30,
                key_set: "api".into(),
                remaining_tokens: Some(1000),
                max_in_flight: Some(2),
            },
            exp_ms: 9_999,
            epoch: 1,
        };
        let payload = serde_json::to_vec(&unsigned).unwrap();
        // Node field order for default key_set: models,rpm,remaining_tokens,max_in_flight
        let s = String::from_utf8(payload.clone()).unwrap();
        assert!(s.contains("\"max_in_flight\":2"), "{s}");
        assert!(!s.contains("key_set"), "{s}");
        let sig = signing.sign(&payload);
        let signed = SignedAuthz {
            authz_version: unsigned.authz_version,
            key_id: unsigned.key_id.clone(),
            key_hash_hex: unsigned.key_hash_hex.clone(),
            account_id: unsigned.account_id.clone(),
            policy: unsigned.policy.clone(),
            exp_ms: unsigned.exp_ms,
            epoch: unsigned.epoch,
            signature_hex: hex::encode(sig.to_bytes()),
        };
        signed.verify_signature(&verify_key).unwrap();
    }

    #[test]
    fn authz_signature_roundtrip() {
        let signing = SigningKey::generate(&mut OsRng);
        let verify_key = signing.verifying_key();
        let unsigned = UnsignedAuthz {
            authz_version: 1,
            key_id: "tcak_test01".into(),
            key_hash_hex: "abc".into(),
            account_id: "usr".into(),
            policy: OpenApiKeyPolicy {
                models: vec!["*".into()],
                rpm: 120,
                key_set: "api".into(),
                remaining_tokens: None,
                max_in_flight: None,
            },
            exp_ms: 1_700_003_600_000,
            epoch: 42,
        };
        let payload = serde_json::to_vec(&unsigned).unwrap();
        let sig = signing.sign(&payload);
        let signed = SignedAuthz {
            authz_version: unsigned.authz_version,
            key_id: unsigned.key_id.clone(),
            key_hash_hex: unsigned.key_hash_hex.clone(),
            account_id: unsigned.account_id.clone(),
            policy: unsigned.policy.clone(),
            exp_ms: unsigned.exp_ms,
            epoch: unsigned.epoch,
            signature_hex: hex::encode(sig.to_bytes()),
        };
        signed.verify_signature(&verify_key).unwrap();
    }

    #[test]
    fn cross_lang_fixture_authz() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-fixtures/openapi-cross-sign.json"
        );
        let raw = std::fs::read_to_string(path).expect("fixture");
        let fixture: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let verify_hex = fixture["verify_key_hex"].as_str().unwrap();
        let verify_bytes = hex::decode(verify_hex).unwrap();
        let verify_key =
            ed25519_dalek::VerifyingKey::from_bytes(verify_bytes.as_slice().try_into().unwrap())
                .unwrap();
        let signed: SignedAuthz = serde_json::from_value(fixture["signed_authz"].clone()).unwrap();
        signed.verify_signature(&verify_key).unwrap();
        let payload_hex = fixture["unsigned_authz_bytes_hex"].as_str().unwrap();
        let payload = hex::decode(payload_hex).unwrap();
        assert_eq!(signed.unsigned_bytes().unwrap(), payload);
    }

    #[test]
    fn policy_allows_wildcard_and_exact() {
        let p = OpenApiKeyPolicy {
            models: vec!["teechat-a".into()],
            rpm: 10,
            key_set: "api".into(),
            remaining_tokens: None,
            max_in_flight: None,
        };
        assert!(p.allows_model("teechat-a"));
        assert!(!p.allows_model("teechat-b"));
        assert!(!OpenApiKeyPolicy {
            models: vec![],
            rpm: 10,
            key_set: "api".into(),
            remaining_tokens: None,
            max_in_flight: None,
        }
        .allows_model("anything"));
        assert!(OpenApiKeyPolicy::unrestricted().allows_model("anything"));
    }

    #[test]
    fn effective_rpm_min_with_zero_unlimited() {
        let p = OpenApiKeyPolicy {
            models: vec!["*".into()],
            rpm: 30,
            key_set: "api".into(),
            remaining_tokens: None,
            max_in_flight: None,
        };
        assert_eq!(p.effective_rpm(120), 30);
        assert_eq!(p.effective_rpm(10), 10);
        assert_eq!(p.effective_rpm(0), 30);
        assert_eq!(OpenApiKeyPolicy::unrestricted().effective_rpm(120), 120);
        assert_eq!(OpenApiKeyPolicy::unrestricted().effective_rpm(0), 0);
    }
}
