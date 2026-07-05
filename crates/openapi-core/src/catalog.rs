use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::ApiError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRecord {
    pub key_id: String,
    /// SHA-256 hex of the full API key secret (lowercase).
    pub key_hash_hex: String,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedKeyCatalog {
    pub catalog_version: u32,
    pub issued_at_ms: u64,
    pub keys: Vec<KeyRecord>,
    /// Ed25519 signature (hex) over canonical unsigned payload bytes.
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct UnsignedCatalog {
    catalog_version: u32,
    issued_at_ms: u64,
    keys: Vec<KeyRecord>,
}

impl SignedKeyCatalog {
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, ApiError> {
        let unsigned = UnsignedCatalog {
            catalog_version: self.catalog_version,
            issued_at_ms: self.issued_at_ms,
            keys: self.keys.clone(),
        };
        serde_json::to_vec(&unsigned).map_err(|e| ApiError::Internal(e.to_string()))
    }

    pub fn verify_signature(&self, verify_key: &VerifyingKey) -> Result<(), ApiError> {
        let payload = self.unsigned_bytes()?;
        let sig_bytes = hex::decode(&self.signature_hex)
            .map_err(|e| ApiError::Internal(format!("invalid signature hex: {e}")))?;
        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|e| ApiError::Internal(format!("invalid signature: {e}")))?;
        verify_key
            .verify(&payload, &signature)
            .map_err(|_| ApiError::Internal("catalog signature invalid".into()))
    }
}

#[derive(Debug, Clone)]
pub struct KeyCatalog {
    catalog: SignedKeyCatalog,
    verify_key: VerifyingKey,
}

impl KeyCatalog {
    pub fn from_signed(catalog: SignedKeyCatalog, verify_key: VerifyingKey) -> Result<Self, ApiError> {
        catalog.verify_signature(&verify_key)?;
        Ok(Self {
            catalog,
            verify_key,
        })
    }

    pub fn catalog(&self) -> &SignedKeyCatalog {
        &self.catalog
    }

    pub fn verify_key(&self) -> &VerifyingKey {
        &self.verify_key
    }

    pub fn lookup_by_api_key(&self, api_key: &str) -> Result<&KeyRecord, ApiError> {
        let hash = hash_api_key(api_key);
        self.catalog
            .keys
            .iter()
            .find(|k| {
                !k.revoked
                    && k.key_hash_hex.as_bytes().ct_eq(hash.as_bytes()).into()
            })
            .ok_or(ApiError::Unauthorized)
    }
}

pub fn hash_api_key(api_key: &str) -> String {
    let digest = Sha256::digest(api_key.as_bytes());
    hex::encode(digest)
}

/// Build a signed catalog for unit tests (same canonical JSON as verification).
#[cfg(any(test, feature = "test-utils"))]
pub fn sign_test_catalog(keys: Vec<KeyRecord>, signing_key: &ed25519_dalek::SigningKey) -> SignedKeyCatalog {
    use ed25519_dalek::Signer;

    let unsigned = UnsignedCatalog {
        catalog_version: 1,
        issued_at_ms: 1_700_000_000_000,
        keys,
    };
    let payload = serde_json::to_vec(&unsigned).unwrap();
    let sig = signing_key.sign(&payload);
    SignedKeyCatalog {
        catalog_version: unsigned.catalog_version,
        issued_at_ms: unsigned.issued_at_ms,
        keys: unsigned.keys,
        signature_hex: hex::encode(sig.to_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn catalog_signature_roundtrip() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verify_key = signing_key.verifying_key();

        let api_key = "sk-teechat-test-key-001";
        let record = KeyRecord {
            key_id: "k1".into(),
            key_hash_hex: hash_api_key(api_key),
            revoked: false,
        };
        let signed = sign_test_catalog(vec![record], &signing_key);
        let catalog = KeyCatalog::from_signed(signed, verify_key).unwrap();
        let found = catalog.lookup_by_api_key(api_key).unwrap();
        assert_eq!(found.key_id, "k1");
    }

    #[test]
    fn revoked_key_rejected() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verify_key = signing_key.verifying_key();
        let api_key = "sk-teechat-revoked";
        let record = KeyRecord {
            key_id: "k2".into(),
            key_hash_hex: hash_api_key(api_key),
            revoked: true,
        };
        let signed = sign_test_catalog(vec![record], &signing_key);
        let catalog = KeyCatalog::from_signed(signed, verify_key).unwrap();
        assert!(catalog.lookup_by_api_key(api_key).is_err());
    }

    #[test]
    fn tampered_catalog_rejected() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verify_key = signing_key.verifying_key();
        let api_key = "sk-teechat-tamper";
        let record = KeyRecord {
            key_id: "k3".into(),
            key_hash_hex: hash_api_key(api_key),
            revoked: false,
        };
        let mut signed = sign_test_catalog(vec![record], &signing_key);
        signed.issued_at_ms += 1;
        assert!(KeyCatalog::from_signed(signed, verify_key).is_err());
    }
}
