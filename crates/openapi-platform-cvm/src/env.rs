use std::fs;
use std::path::Path;

use openapi_platform::{load_edge_profile, validate_tls_key_policy, EdgeProfile, ProfileError};

use crate::seal::CvmSealer;
use ed25519_dalek::{SigningKey, VerifyingKey};
use openapi_core::auth::Authenticator;
use openapi_core::catalog::{KeyCatalog, SignedKeyCatalog};
use openapi_core::config::Config;
use openapi_core::limits::Limits;
use openapi_core::remote_auth::EdgeAuthenticator;
use openapi_core::usage::UsageSigner;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct EdgeEnv {
    pub listen_addr: String,
    pub region: String,
    pub upstream_base_url: String,
    pub catalog_path: Option<String>,
    pub catalog_verify_key_hex: String,
    pub auth_mode: OpenApiAuthMode,
    pub l0_authorize_url: Option<String>,
    pub l0_internal_token: Option<String>,
    pub push_listen_addr: Option<String>,
    pub usage_sign_seed_hex: String,
    pub build_version: String,
    pub code_hash: String,
    pub launch_digest: String,
    pub image_digest: String,
    pub tls_cert_path: Option<String>,
    /// Plaintext key path — dev only; production uses `tls_sealed_key_path`.
    pub tls_key_path: Option<String>,
    pub tls_sealed_key_path: Option<String>,
    pub seal_root_hex: Option<String>,
    pub max_body_bytes: usize,
    pub requests_per_minute: u32,
    pub challenge_requests_per_minute: u32,
    pub challenge_max_inflight: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenApiAuthMode {
    Catalog,
    Remote,
}

impl OpenApiAuthMode {
    fn parse(raw: &str) -> Self {
        match raw.trim().to_lowercase().as_str() {
            "remote" | "d6" => Self::Remote,
            _ => Self::Catalog,
        }
    }
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
    #[error("profile: {0}")]
    Profile(#[from] ProfileError),
    #[error("seal: {0}")]
    Seal(String),
}

impl EdgeEnv {
    pub fn from_env() -> Result<Self, EnvError> {
        load_edge_env()
    }

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
            challenge_requests_per_minute: self.challenge_requests_per_minute,
            challenge_max_inflight: self.challenge_max_inflight,
        }
    }

    pub fn load_catalog(&self) -> Result<KeyCatalog, EnvError> {
        let path = self
            .catalog_path
            .as_ref()
            .ok_or_else(|| EnvError::Missing("OPENAPI_CATALOG_PATH"))?;
        let raw = fs::read_to_string(path)?;
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

    pub fn edge_authenticator(&self) -> Result<EdgeAuthenticator, EnvError> {
        match self.auth_mode {
            OpenApiAuthMode::Catalog => Ok(EdgeAuthenticator::from_catalog(
                Authenticator::new(self.load_catalog()?),
            )),
            OpenApiAuthMode::Remote => {
                let authorize_url = self
                    .l0_authorize_url
                    .clone()
                    .ok_or(EnvError::Missing("OPENAPI_L0_AUTHORIZE_URL"))?;
                let token = self
                    .l0_internal_token
                    .clone()
                    .ok_or(EnvError::Missing("OPENAPI_L0_INTERNAL_TOKEN"))?;
                let remote = crate::remote_client::build_remote_authenticator(
                    &self.catalog_verify_key_hex,
                    authorize_url,
                    token,
                )
                .map_err(|e| EnvError::Catalog(e.to_string()))?;
                Ok(EdgeAuthenticator::from_remote(remote))
            }
        }
    }

    /** @deprecated Use `edge_authenticator` — file catalog mode only. */
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

    pub fn profile(&self) -> EdgeProfile {
        load_edge_profile()
    }

    pub fn validate_profile(&self) -> Result<(), EnvError> {
        validate_tls_key_policy(self.profile())?;
        Ok(())
    }

    pub fn seal_root(&self) -> Result<Option<[u8; 32]>, EnvError> {
        self.cvm_sealer()
            .resolve_seal_root(
                parse_seal_root_hex(self.seal_root_hex.as_deref())?.as_ref(),
            )
            .map_err(|e| EnvError::Seal(e.to_string()))
    }

    pub fn cvm_sealer(&self) -> CvmSealer {
        CvmSealer::with_profile(
            &self.launch_digest,
            &self.image_digest,
            self.profile().is_prod(),
        )
    }
}

pub fn load_edge_env() -> Result<EdgeEnv, EnvError> {
    fn req(name: &'static str) -> Result<String, EnvError> {
        std::env::var(name).map_err(|_| EnvError::Missing(name))
    }

    fn opt(name: &'static str) -> Option<String> {
        std::env::var(name).ok().filter(|s| !s.is_empty())
    }

    let auth_mode = OpenApiAuthMode::parse(
        &opt("OPENAPI_AUTH_MODE").unwrap_or_else(|| "catalog".into()),
    );
    let catalog_path = if auth_mode == OpenApiAuthMode::Catalog {
        Some(req("OPENAPI_CATALOG_PATH")?)
    } else {
        opt("OPENAPI_CATALOG_PATH")
    };

    Ok(EdgeEnv {
        listen_addr: opt("OPENAPI_LISTEN_ADDR").unwrap_or_else(|| "0.0.0.0:8443".into()),
        region: opt("OPENAPI_REGION").unwrap_or_else(|| "global".into()),
        upstream_base_url: req("OPENAPI_UPSTREAM_BASE_URL")?,
        catalog_path,
        catalog_verify_key_hex: req("OPENAPI_CATALOG_VERIFY_KEY_HEX")?,
        auth_mode,
        l0_authorize_url: opt("OPENAPI_L0_AUTHORIZE_URL"),
        l0_internal_token: opt("OPENAPI_L0_INTERNAL_TOKEN"),
        push_listen_addr: opt("OPENAPI_PUSH_LISTEN_ADDR"),
        usage_sign_seed_hex: req("OPENAPI_USAGE_SIGN_SEED_HEX")?,
        build_version: opt("OPENAPI_BUILD_VERSION").unwrap_or_else(|| "dev".into()),
        code_hash: opt("OPENAPI_CODE_HASH").unwrap_or_else(|| "unknown".into()),
        launch_digest: opt("OPENAPI_LAUNCH_DIGEST").unwrap_or_else(|| "unknown".into()),
        image_digest: opt("OPENAPI_IMAGE_DIGEST").unwrap_or_else(|| "unknown".into()),
        tls_cert_path: opt("OPENAPI_TLS_CERT_PATH"),
        tls_key_path: opt("OPENAPI_TLS_KEY_PATH"),
        tls_sealed_key_path: opt("OPENAPI_TLS_SEALED_KEY_PATH"),
        seal_root_hex: opt("OPENAPI_SEAL_ROOT_HEX"),
        max_body_bytes: opt("OPENAPI_MAX_BODY_BYTES")
            .and_then(|v| v.parse().ok())
            .unwrap_or(4 * 1024 * 1024),
        requests_per_minute: opt("OPENAPI_REQUESTS_PER_MINUTE")
            .and_then(|v| v.parse().ok())
            .unwrap_or(120),
        challenge_requests_per_minute: opt("OPENAPI_CHALLENGE_RPM")
            .and_then(|v| v.parse().ok())
            .unwrap_or(10),
        challenge_max_inflight: opt("OPENAPI_CHALLENGE_MAX_INFLIGHT")
            .and_then(|v| v.parse().ok())
            .unwrap_or(4),
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::env;

    #[test]
    fn load_catalog_from_file() {
        let dir = std::env::temp_dir().join(format!("openapi-env-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let catalog_path = dir.join("catalog.json");
        let mut csprng = OsRng;
        let signing = SigningKey::generate(&mut csprng);
        write_dev_catalog(&catalog_path, "sk-teechat-dev", &signing).unwrap();

        env::set_var("OPENAPI_UPSTREAM_BASE_URL", "http://127.0.0.1:1");
        env::set_var("OPENAPI_CATALOG_PATH", catalog_path.to_str().unwrap());
        env::set_var(
            "OPENAPI_CATALOG_VERIFY_KEY_HEX",
            hex::encode(signing.verifying_key().to_bytes()),
        );
        env::set_var("OPENAPI_USAGE_SIGN_SEED_HEX", hex::encode([4u8; 32]));

        let edge = load_edge_env().unwrap();
        let catalog = edge.load_catalog().unwrap();
        assert!(catalog.lookup_by_api_key("sk-teechat-dev").is_ok());

        env::remove_var("OPENAPI_UPSTREAM_BASE_URL");
        env::remove_var("OPENAPI_CATALOG_PATH");
        env::remove_var("OPENAPI_CATALOG_VERIFY_KEY_HEX");
        env::remove_var("OPENAPI_USAGE_SIGN_SEED_HEX");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_seal_root_hex_valid() {
        let root = parse_seal_root_hex(Some(&hex::encode([9u8; 32]))).unwrap();
        assert_eq!(root, Some([9u8; 32]));
        assert_eq!(parse_seal_root_hex(None).unwrap(), None);
    }

    #[test]
    fn parse_seal_root_hex_invalid_length() {
        assert!(parse_seal_root_hex(Some("abcd")).is_err());
    }

    #[test]
    fn env_loads_sealed_tls_paths() {
        env::set_var("OPENAPI_UPSTREAM_BASE_URL", "http://127.0.0.1:1");
        env::set_var("OPENAPI_CATALOG_PATH", "/tmp/unused");
        env::set_var("OPENAPI_CATALOG_VERIFY_KEY_HEX", hex::encode([1u8; 32]));
        env::set_var("OPENAPI_USAGE_SIGN_SEED_HEX", hex::encode([2u8; 32]));
        env::set_var("OPENAPI_TLS_CERT_PATH", "/etc/cert.pem");
        env::set_var("OPENAPI_TLS_SEALED_KEY_PATH", "/var/openapi/tls-key.sealed.json");
        env::set_var("OPENAPI_SEAL_ROOT_HEX", hex::encode([3u8; 32]));

        let edge = load_edge_env().unwrap();
        assert_eq!(edge.tls_sealed_key_path.as_deref(), Some("/var/openapi/tls-key.sealed.json"));
        assert_eq!(edge.seal_root().unwrap(), Some([3u8; 32]));

        env::remove_var("OPENAPI_UPSTREAM_BASE_URL");
        env::remove_var("OPENAPI_CATALOG_PATH");
        env::remove_var("OPENAPI_CATALOG_VERIFY_KEY_HEX");
        env::remove_var("OPENAPI_USAGE_SIGN_SEED_HEX");
        env::remove_var("OPENAPI_TLS_CERT_PATH");
        env::remove_var("OPENAPI_TLS_SEALED_KEY_PATH");
        env::remove_var("OPENAPI_SEAL_ROOT_HEX");
    }
}
