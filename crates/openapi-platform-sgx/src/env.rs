use std::fs;
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use openapi_core::auth::Authenticator;
use openapi_core::catalog::{KeyCatalog, SignedKeyCatalog};
use openapi_core::config::Config;
use openapi_core::limits::Limits;
use openapi_core::remote_auth::EdgeAuthenticator;
use openapi_core::routes::ProxyMode;
use openapi_core::usage::UsageSigner;
use thiserror::Error;

use openapi_platform::{load_edge_profile, validate_tls_key_policy, EdgeProfile, ProfileError};

use crate::seal::{local_mrenclave_hex, SgxSealer};

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

#[derive(Debug, Clone)]
pub struct SgxEdgeEnv {
    pub listen_addr: String,
    pub region: String,
    pub upstream_base_url: String,
    pub catalog_path: String,
    /// Inline catalog JSON (Fortanix: no host filesystem). Takes precedence over path.
    pub catalog_json: Option<String>,
    pub catalog_verify_key_hex: String,
    pub auth_mode: OpenApiAuthMode,
    pub l0_authorize_url: Option<String>,
    pub l0_revocations_url: Option<String>,
    pub l0_internal_token: Option<String>,
    pub revoke_poll_secs: u64,
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
    pub challenge_requests_per_minute: u32,
    pub challenge_max_inflight: u32,
    pub challenge_bench_token: Option<String>,
    pub ip_max_connections: u32,
    pub ip_requests_per_minute: u32,
    pub proxy_mode: ProxyMode,
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

impl SgxEdgeEnv {
    pub fn config(&self) -> Config {
        Config {
            region: self.region.clone(),
            upstream_base_url: self.upstream_base_url.clone(),
            max_body_bytes: self.max_body_bytes,
            proxy_mode: self.proxy_mode,
        }
    }

    pub fn limits(&self) -> Limits {
        Limits {
            requests_per_minute: self.requests_per_minute,
            max_body_bytes: self.max_body_bytes,
            challenge_requests_per_minute: self.challenge_requests_per_minute,
            challenge_max_inflight: self.challenge_max_inflight,
            // BENCH-001: never expose bench bypass under prod even if env slipped through.
            challenge_bench_token: if self.profile().is_prod() {
                None
            } else {
                self.challenge_bench_token.clone()
            },
            ip_max_connections: self.ip_max_connections,
            ip_requests_per_minute: self.ip_requests_per_minute,
        }
    }

    pub fn load_catalog(&self) -> Result<KeyCatalog, EnvError> {
        let raw = if let Some(json) = &self.catalog_json {
            json.clone()
        } else {
            fs::read_to_string(&self.catalog_path)?
        };
        let signed: SignedKeyCatalog = serde_json::from_str(&raw)
            .map_err(|e| EnvError::Catalog(format!("parse catalog: {e}")))?;
        let verify_bytes = hex::decode(&self.catalog_verify_key_hex)
            .map_err(|e| EnvError::Invalid("OPENAPI_CATALOG_VERIFY_KEY_HEX", e.to_string()))?;
        let verify_key =
            VerifyingKey::from_bytes(verify_bytes.as_slice().try_into().map_err(|_| {
                EnvError::Invalid("OPENAPI_CATALOG_VERIFY_KEY_HEX", "must be 32 bytes".into())
            })?)
            .map_err(|e| EnvError::Invalid("OPENAPI_CATALOG_VERIFY_KEY_HEX", e.to_string()))?;
        KeyCatalog::from_signed(signed, verify_key).map_err(|e| EnvError::Catalog(e.to_string()))
    }

    pub fn edge_authenticator(&self) -> Result<EdgeAuthenticator, EnvError> {
        match self.auth_mode {
            OpenApiAuthMode::Catalog => Ok(EdgeAuthenticator::from_catalog(Authenticator::new(
                self.load_catalog()?,
            ))),
            OpenApiAuthMode::Remote => {
                let authorize_url = self
                    .l0_authorize_url
                    .as_deref()
                    .ok_or(EnvError::Missing("OPENAPI_L0_AUTHORIZE_URL"))?;
                let token = self
                    .l0_internal_token
                    .clone()
                    .ok_or(EnvError::Missing("OPENAPI_L0_INTERNAL_TOKEN"))?;
                let remote = crate::remote_client::build_remote_authenticator(
                    &self.catalog_verify_key_hex,
                    authorize_url,
                    self.l0_revocations_url.as_deref(),
                    token,
                    Some(self.revoke_poll_secs),
                )
                .map_err(|e| EnvError::Catalog(e.to_string()))?;
                Ok(EdgeAuthenticator::from_remote(remote))
            }
        }
    }

    /// Lab/dev file catalog only. Prefer `edge_authenticator`.
    pub fn authenticator(&self) -> Result<Authenticator, EnvError> {
        Ok(Authenticator::new(self.load_catalog()?))
    }

    pub fn usage_signer(&self) -> Result<UsageSigner, EnvError> {
        let seed_bytes = hex::decode(&self.usage_sign_seed_hex)
            .map_err(|e| EnvError::Invalid("OPENAPI_USAGE_SIGN_SEED_HEX", e.to_string()))?;
        let seed: [u8; 32] = seed_bytes.as_slice().try_into().map_err(|_| {
            EnvError::Invalid("OPENAPI_USAGE_SIGN_SEED_HEX", "must be 32 bytes".into())
        })?;
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
        if self.profile().is_prod() {
            return self
                .runtime_sgx_sealer()?
                .resolve_seal_root(None, true)
                .map_err(|e| EnvError::Seal(e.to_string()));
        }
        parse_seal_root_hex(self.seal_root_hex.as_deref())
    }

    pub fn sgx_sealer(&self) -> SgxSealer {
        SgxSealer::new(self.mrenclave.clone())
    }

    /// Runtime sealer: MRENCLAVE from enclave report when inside SGX.
    pub fn runtime_sgx_sealer(&self) -> Result<SgxSealer, EnvError> {
        let runtime_mr =
            local_mrenclave_hex().map_err(|e| EnvError::Invalid("MRENCLAVE", e.to_string()))?;
        if (self.profile().is_prod() || self.mrenclave != "unknown") && self.mrenclave != runtime_mr
        {
            return Err(EnvError::Invalid(
                "OPENAPI_MRENCLAVE",
                format!("env={} report={runtime_mr}", self.mrenclave),
            ));
        }
        Ok(SgxSealer::new(runtime_mr))
    }
}

pub fn load_sgx_edge_env() -> Result<SgxEdgeEnv, EnvError> {
    fn req(name: &'static str) -> Result<String, EnvError> {
        std::env::var(name).map_err(|_| EnvError::Missing(name))
    }

    fn opt(name: &'static str) -> Option<String> {
        std::env::var(name).ok().filter(|s| !s.is_empty())
    }

    let auth_mode =
        OpenApiAuthMode::parse(&opt("OPENAPI_AUTH_MODE").unwrap_or_else(|| "catalog".into()));
    let catalog_json = opt("OPENAPI_CATALOG_JSON");
    let catalog_path = opt("OPENAPI_CATALOG_PATH").unwrap_or_default();
    if auth_mode == OpenApiAuthMode::Catalog && catalog_json.is_none() && catalog_path.is_empty() {
        return Err(EnvError::Missing(
            "OPENAPI_CATALOG_JSON|OPENAPI_CATALOG_PATH",
        ));
    }

    Ok(SgxEdgeEnv {
        listen_addr: opt("OPENAPI_LISTEN_ADDR").unwrap_or_else(|| "0.0.0.0:8443".into()),
        region: opt("OPENAPI_REGION").unwrap_or_else(|| "global".into()),
        upstream_base_url: req("OPENAPI_UPSTREAM_BASE_URL")?,
        catalog_json,
        catalog_path,
        catalog_verify_key_hex: req("OPENAPI_CATALOG_VERIFY_KEY_HEX")?,
        auth_mode,
        l0_authorize_url: opt("OPENAPI_L0_AUTHORIZE_URL"),
        l0_revocations_url: opt("OPENAPI_L0_REVOCATIONS_URL"),
        l0_internal_token: opt("OPENAPI_L0_INTERNAL_TOKEN"),
        revoke_poll_secs: opt("OPENAPI_REVOKE_POLL_SECS")
            .and_then(|v| v.parse().ok())
            .unwrap_or(15),
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
            .unwrap_or(5000),
        challenge_requests_per_minute: opt("OPENAPI_CHALLENGE_RPM")
            .and_then(|v| v.parse().ok())
            .unwrap_or(10),
        challenge_max_inflight: opt("OPENAPI_CHALLENGE_MAX_INFLIGHT")
            .and_then(|v| v.parse().ok())
            .unwrap_or(4),
        challenge_bench_token: opt("OPENAPI_CHALLENGE_BENCH_TOKEN"),
        ip_max_connections: opt("OPENAPI_IP_MAX_CONNS")
            .and_then(|v| v.parse().ok())
            .unwrap_or(16),
        ip_requests_per_minute: opt("OPENAPI_IP_REQUESTS_PER_MINUTE")
            .and_then(|v| v.parse().ok())
            .unwrap_or(180),
        proxy_mode: ProxyMode::parse(opt("OPENAPI_PROXY_MODE").as_deref())
            .map_err(|e| EnvError::Invalid("OPENAPI_PROXY_MODE", e))?,
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

    #[test]
    fn sgx_env_loads_per_ip_limits() {
        env::set_var("OPENAPI_UPSTREAM_BASE_URL", "http://127.0.0.1:8000");
        env::set_var("OPENAPI_CATALOG_PATH", "/tmp/unused");
        env::set_var("OPENAPI_CATALOG_VERIFY_KEY_HEX", hex::encode([1u8; 32]));
        env::set_var("OPENAPI_USAGE_SIGN_SEED_HEX", hex::encode([2u8; 32]));
        env::set_var("OPENAPI_MRENCLAVE", "abc123");
        env::remove_var("OPENAPI_IP_MAX_CONNS");
        env::remove_var("OPENAPI_IP_REQUESTS_PER_MINUTE");

        let edge = load_sgx_edge_env().unwrap();
        let limits = edge.limits();
        assert_eq!(limits.ip_max_connections, 16);
        assert_eq!(limits.ip_requests_per_minute, 180);

        env::set_var("OPENAPI_IP_MAX_CONNS", "5");
        env::set_var("OPENAPI_IP_REQUESTS_PER_MINUTE", "42");
        let edge = load_sgx_edge_env().unwrap();
        let limits = edge.limits();
        assert_eq!(limits.ip_max_connections, 5);
        assert_eq!(limits.ip_requests_per_minute, 42);

        env::remove_var("OPENAPI_UPSTREAM_BASE_URL");
        env::remove_var("OPENAPI_CATALOG_PATH");
        env::remove_var("OPENAPI_CATALOG_VERIFY_KEY_HEX");
        env::remove_var("OPENAPI_USAGE_SIGN_SEED_HEX");
        env::remove_var("OPENAPI_MRENCLAVE");
        env::remove_var("OPENAPI_IP_MAX_CONNS");
        env::remove_var("OPENAPI_IP_REQUESTS_PER_MINUTE");
    }
}
