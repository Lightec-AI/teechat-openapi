use std::fs;
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use openapi_core::auth::Authenticator;
use openapi_core::catalog::{KeyCatalog, SignedKeyCatalog};
use openapi_core::config::Config;
use openapi_core::limits::Limits;
use openapi_core::usage::UsageSigner;
use thiserror::Error;

use crate::seal::SgxSealer;

#[derive(Debug, Clone)]
pub struct SgxEdgeEnv {
    pub listen_addr: String,
    pub region: String,
    pub upstream_base_url: String,
    pub catalog_path: String,
    pub catalog_verify_key_hex: String,
    pub usage_sign_seed_hex: String,
    pub build_version: String,
    pub code_hash: String,
    pub mrenclave: String,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub tls_sealed_key_path: Option<String>,
    pub seal_root_hex: Option<String>,
    pub max_body_bytes: usize,
    pub requests_per_minute: u32,
}

#[derive(Debug, Error)]
pub enum EnvError {
    #[error("missing env var {0}")]
    Missing(&'static str),
    #[error("invalid env {0}: {1}")]
    Invalid(&'static str, String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("catalog: {0}")]
    Catalog(String),
}

impl SgxEdgeEnv {
    pub fn config(&self) -> Config {
        Config {
            region: self.region.clone(),
            upstream_base_url: self.upstream_base_url.clone(),
            max_body_bytes: self.max_body_bytes,
        }
    }

    pub fn limits(&self) -> Limits {
        Limits {
            requests_per_minute: self.requests_per_minute,
            max_body_bytes: self.max_body_bytes,
        }
    }

    pub fn load_catalog(&self) -> Result<KeyCatalog, EnvError> {
        let raw = fs::read_to_string(&self.catalog_path)?;
        let signed: SignedKeyCatalog = serde_json::from_str(&raw)
            .map_err(|e| EnvError::Catalog(format!("parse catalog: {e}")))?;
        let verify_bytes = hex::decode(&self.catalog_verify_key_hex)
            .map_err(|e| EnvError::Invalid("OPENAPI_CATALOG_VERIFY_KEY_HEX", e.to_string()))?;
        let verify_key = VerifyingKey::from_bytes(
            verify_bytes
                .as_slice()
                .try_into()
                .map_err(|_| EnvError::Invalid("OPENAPI_CATALOG_VERIFY_KEY_HEX", "must be 32 bytes".into()))?,
        )
        .map_err(|e| EnvError::Invalid("OPENAPI_CATALOG_VERIFY_KEY_HEX", e.to_string()))?;
        KeyCatalog::from_signed(signed, verify_key).map_err(|e| EnvError::Catalog(e.to_string()))
    }

    pub fn authenticator(&self) -> Result<Authenticator, EnvError> {
        Ok(Authenticator::new(self.load_catalog()?))
    }

    pub fn usage_signer(&self) -> Result<UsageSigner, EnvError> {
        let seed_bytes = hex::decode(&self.usage_sign_seed_hex)
            .map_err(|e| EnvError::Invalid("OPENAPI_USAGE_SIGN_SEED_HEX", e.to_string()))?;
        let seed: [u8; 32] = seed_bytes
            .as_slice()
            .try_into()
            .map_err(|_| EnvError::Invalid("OPENAPI_USAGE_SIGN_SEED_HEX", "must be 32 bytes".into()))?;
        Ok(UsageSigner::from_seed(seed))
    }

    pub fn seal_root(&self) -> Result<Option<[u8; 32]>, EnvError> {
        parse_seal_root_hex(self.seal_root_hex.as_deref())
    }

    pub fn sgx_sealer(&self) -> SgxSealer {
        SgxSealer::new(self.mrenclave.clone())
    }
}

pub fn load_sgx_edge_env() -> Result<SgxEdgeEnv, EnvError> {
    fn req(name: &'static str) -> Result<String, EnvError> {
        std::env::var(name).map_err(|_| EnvError::Missing(name))
    }

    fn opt(name: &'static str) -> Option<String> {
        std::env::var(name).ok().filter(|s| !s.is_empty())
    }

    Ok(SgxEdgeEnv {
        listen_addr: opt("OPENAPI_LISTEN_ADDR").unwrap_or_else(|| "0.0.0.0:8443".into()),
        region: opt("OPENAPI_REGION").unwrap_or_else(|| "global".into()),
        upstream_base_url: req("OPENAPI_UPSTREAM_BASE_URL")?,
        catalog_path: req("OPENAPI_CATALOG_PATH")?,
        catalog_verify_key_hex: req("OPENAPI_CATALOG_VERIFY_KEY_HEX")?,
        usage_sign_seed_hex: req("OPENAPI_USAGE_SIGN_SEED_HEX")?,
        build_version: opt("OPENAPI_BUILD_VERSION").unwrap_or_else(|| "dev".into()),
        code_hash: opt("OPENAPI_CODE_HASH").unwrap_or_else(|| "unknown".into()),
        mrenclave: req("OPENAPI_MRENCLAVE")?,
        tls_cert_path: opt("OPENAPI_TLS_CERT_PATH"),
        tls_key_path: opt("OPENAPI_TLS_KEY_PATH"),
        tls_sealed_key_path: opt("OPENAPI_TLS_SEALED_KEY_PATH"),
        seal_root_hex: opt("OPENAPI_SEAL_ROOT_HEX"),
        max_body_bytes: opt("OPENAPI_MAX_BODY_BYTES")
            .and_then(|v| v.parse().ok())
            .unwrap_or(4 * 1024 * 1024),
        requests_per_minute: opt("OPENAPI_REQUESTS_PER_MINUTE")
            .and_then(|v| v.parse().ok())
            .unwrap_or(128),
    })
}

pub fn parse_seal_root_hex(raw: Option<&str>) -> Result<Option<[u8; 32]>, EnvError> {
    match raw {
        None => Ok(None),
        Some("") => Ok(None),
        Some(hex_str) => {
            let bytes = hex::decode(hex_str)
                .map_err(|e| EnvError::Invalid("OPENAPI_SEAL_ROOT_HEX", e.to_string()))?;
            let root: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                EnvError::Invalid("OPENAPI_SEAL_ROOT_HEX", "must be 32 bytes".into())
            })?;
            Ok(Some(root))
        }
    }
}

pub fn write_dev_catalog(
    path: &Path,
    api_key: &str,
    signing_key: &SigningKey,
) -> Result<(), EnvError> {
    use ed25519_dalek::Signer;
    use openapi_core::catalog::{hash_api_key, KeyRecord, SignedKeyCatalog};
    use serde::Serialize;

    #[derive(Serialize)]
    struct UnsignedCatalog {
        catalog_version: u32,
        issued_at_ms: u64,
        keys: Vec<KeyRecord>,
    }

    let record = KeyRecord {
        key_id: "dev".into(),
        key_hash_hex: hash_api_key(api_key),
        revoked: false,
    };
    let unsigned = UnsignedCatalog {
        catalog_version: 1,
        issued_at_ms: 1,
        keys: vec![record],
    };
    let payload = serde_json::to_vec(&unsigned).unwrap();
    let sig = signing_key.sign(&payload);
    let signed = SignedKeyCatalog {
        catalog_version: unsigned.catalog_version,
        issued_at_ms: unsigned.issued_at_ms,
        keys: unsigned.keys,
        signature_hex: hex::encode(sig.to_bytes()),
    };
    fs::write(path, serde_json::to_vec_pretty(&signed).unwrap())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn sgx_env_requires_mrenclave() {
        env::set_var("OPENAPI_UPSTREAM_BASE_URL", "http://127.0.0.1:8000");
        env::set_var("OPENAPI_CATALOG_PATH", "/tmp/unused");
        env::set_var("OPENAPI_CATALOG_VERIFY_KEY_HEX", hex::encode([1u8; 32]));
        env::set_var("OPENAPI_USAGE_SIGN_SEED_HEX", hex::encode([2u8; 32]));
        assert!(load_sgx_edge_env().is_err());
        env::set_var("OPENAPI_MRENCLAVE", "abc123");
        let edge = load_sgx_edge_env().unwrap();
        assert_eq!(edge.mrenclave, "abc123");
        env::remove_var("OPENAPI_UPSTREAM_BASE_URL");
        env::remove_var("OPENAPI_CATALOG_PATH");
        env::remove_var("OPENAPI_CATALOG_VERIFY_KEY_HEX");
        env::remove_var("OPENAPI_USAGE_SIGN_SEED_HEX");
        env::remove_var("OPENAPI_MRENCLAVE");
    }
}
