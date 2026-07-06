//! Runtime profile (`dev` vs `prod`) for seal and TLS key policy.

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeProfile {
    Dev,
    Prod,
}

impl EdgeProfile {
    pub fn is_prod(self) -> bool {
        matches!(self, EdgeProfile::Prod)
    }
}

#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("prod forbids plaintext TLS key (OPENAPI_TLS_KEY_PATH)")]
    ProdPlaintextTlsKey,
    #[error("prod requires sealed TLS key (OPENAPI_TLS_SEALED_KEY_PATH)")]
    ProdMissingSealedTlsKey,
    #[error("prod forbids host-supplied OPENAPI_SEAL_ROOT_HEX — seal root is derived inside TEE")]
    ProdHostSealRoot,
}

/// Load profile from `OPENAPI_PROFILE` (`dev` default, `prod` / `production` → prod).
pub fn load_edge_profile() -> EdgeProfile {
    match std::env::var("OPENAPI_PROFILE")
        .ok()
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("prod") | Some("production") => EdgeProfile::Prod,
        _ => EdgeProfile::Dev,
    }
}

/// Validate TLS key env against profile. Call at startup before unseal.
pub fn validate_tls_key_policy(profile: EdgeProfile) -> Result<(), ProfileError> {
    let sealed = std::env::var("OPENAPI_TLS_SEALED_KEY_PATH")
        .ok()
        .filter(|s| !s.is_empty());
    let plain = std::env::var("OPENAPI_TLS_KEY_PATH")
        .ok()
        .filter(|s| !s.is_empty());

    if profile.is_prod() {
        if plain.is_some() {
            return Err(ProfileError::ProdPlaintextTlsKey);
        }
        if sealed.is_none() {
            return Err(ProfileError::ProdMissingSealedTlsKey);
        }
        if std::env::var("OPENAPI_SEAL_ROOT_HEX")
            .ok()
            .filter(|s| !s.is_empty())
            .is_some()
        {
            return Err(ProfileError::ProdHostSealRoot);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Mutex;

    /// Env vars are process-global; serialize profile tests to avoid races.
    static ENV_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn clear_tls_env() {
        env::remove_var("OPENAPI_PROFILE");
        env::remove_var("OPENAPI_TLS_SEALED_KEY_PATH");
        env::remove_var("OPENAPI_TLS_KEY_PATH");
        env::remove_var("OPENAPI_SEAL_ROOT_HEX");
    }

    #[test]
    fn default_profile_is_dev() {
        let _lock = ENV_TEST_LOCK.lock().unwrap();
        clear_tls_env();
        assert_eq!(load_edge_profile(), EdgeProfile::Dev);
    }

    #[test]
    fn prod_profile_from_env() {
        let _lock = ENV_TEST_LOCK.lock().unwrap();
        clear_tls_env();
        env::set_var("OPENAPI_PROFILE", "prod");
        assert_eq!(load_edge_profile(), EdgeProfile::Prod);
        env::remove_var("OPENAPI_PROFILE");
    }

    #[test]
    fn prod_rejects_plaintext_key() {
        let _lock = ENV_TEST_LOCK.lock().unwrap();
        clear_tls_env();
        env::set_var("OPENAPI_PROFILE", "prod");
        env::set_var("OPENAPI_TLS_SEALED_KEY_PATH", "/var/sealed.json");
        env::set_var("OPENAPI_TLS_KEY_PATH", "/var/key.pem");
        assert!(matches!(
            validate_tls_key_policy(EdgeProfile::Prod),
            Err(ProfileError::ProdPlaintextTlsKey)
        ));
        clear_tls_env();
    }

    #[test]
    fn prod_requires_sealed_key() {
        let _lock = ENV_TEST_LOCK.lock().unwrap();
        clear_tls_env();
        env::set_var("OPENAPI_PROFILE", "prod");
        assert!(matches!(
            validate_tls_key_policy(EdgeProfile::Prod),
            Err(ProfileError::ProdMissingSealedTlsKey)
        ));
        clear_tls_env();
    }

    #[test]
    fn prod_rejects_host_seal_root() {
        let _lock = ENV_TEST_LOCK.lock().unwrap();
        clear_tls_env();
        env::set_var("OPENAPI_PROFILE", "prod");
        env::set_var("OPENAPI_TLS_SEALED_KEY_PATH", "/var/sealed.json");
        env::set_var("OPENAPI_SEAL_ROOT_HEX", "aa".repeat(32));
        assert!(matches!(
            validate_tls_key_policy(EdgeProfile::Prod),
            Err(ProfileError::ProdHostSealRoot)
        ));
        clear_tls_env();
    }
}
