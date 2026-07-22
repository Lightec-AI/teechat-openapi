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
    #[error("prod requires TLS certificate (OPENAPI_TLS_CERT_PATH) — TLS-001")]
    ProdMissingTlsCert,
    #[error("prod forbids host-supplied OPENAPI_SEAL_ROOT_HEX — seal root is derived inside TEE")]
    ProdHostSealRoot,
    #[error(
        "prod forbids OPENAPI_ATTESTED_LAUNCH_DIGEST — use snpguest / /dev/sev-guest (OPS-001)"
    )]
    ProdAttestedLaunchOverride,
    #[error(
        "prod forbids OPENAPI_AMD_SP_DERIVED_KEY_HEX — use SNP_GET_DERIVED_KEY via /dev/sev-guest (OPS-003)"
    )]
    ProdAmdSpDerivedKeyOverride,
    #[error(
        "OPENAPI_PROFILE=prod forbids host-side seal-tls-key tools — run the in-TEE ceremony"
    )]
    ProdHostSealTool,
    #[error(
        "prod forbids OPENAPI_CHALLENGE_BENCH_TOKEN — challenge DoS caps must stay on (BENCH-001)"
    )]
    ProdChallengeBenchToken,
    #[error(
        "prod forbids OPENAPI_PROXY_MODE=transparent — use allowlist (PROXY-001)"
    )]
    ProdTransparentProxy,
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
        // TLS-001: sealed key alone is insufficient — must also present a cert chain.
        if std::env::var("OPENAPI_TLS_CERT_PATH")
            .ok()
            .filter(|s| !s.is_empty())
            .is_none()
        {
            return Err(ProfileError::ProdMissingTlsCert);
        }
        if std::env::var("OPENAPI_SEAL_ROOT_HEX")
            .ok()
            .filter(|s| !s.is_empty())
            .is_some()
        {
            return Err(ProfileError::ProdHostSealRoot);
        }
        // OPS-001: CVM test hook must never be live on prod units.
        if std::env::var("OPENAPI_ATTESTED_LAUNCH_DIGEST")
            .ok()
            .filter(|s| !s.is_empty() && s != "unknown")
            .is_some()
        {
            return Err(ProfileError::ProdAttestedLaunchOverride);
        }
        // OPS-003: AMD-SP derived-key inject must never be live on prod units.
        if std::env::var("OPENAPI_AMD_SP_DERIVED_KEY_HEX")
            .ok()
            .filter(|s| !s.is_empty())
            .is_some()
        {
            return Err(ProfileError::ProdAmdSpDerivedKeyOverride);
        }
        // BENCH-001: challenge rate-limit bypass must never be live on prod.
        if std::env::var("OPENAPI_CHALLENGE_BENCH_TOKEN")
            .ok()
            .filter(|s| !s.is_empty())
            .is_some()
        {
            return Err(ProfileError::ProdChallengeBenchToken);
        }
        // PROXY-001: transparent /v1/* must never be the prod default surface.
        if let Ok(mode) = std::env::var("OPENAPI_PROXY_MODE") {
            if mode.trim().eq_ignore_ascii_case("transparent")
                || mode.trim().eq_ignore_ascii_case("proxy")
            {
                return Err(ProfileError::ProdTransparentProxy);
            }
        }
    }
    Ok(())
}

/// Host-side `seal-tls-key` / `seal-tls-key-sgx` are **dev/lab only** (OPS-002).
pub fn assert_dev_host_seal_tool(profile: EdgeProfile) -> Result<(), ProfileError> {
    if profile.is_prod() {
        return Err(ProfileError::ProdHostSealTool);
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
        env::remove_var("OPENAPI_TLS_CERT_PATH");
        env::remove_var("OPENAPI_SEAL_ROOT_HEX");
        env::remove_var("OPENAPI_ATTESTED_LAUNCH_DIGEST");
        env::remove_var("OPENAPI_AMD_SP_DERIVED_KEY_HEX");
        env::remove_var("OPENAPI_CHALLENGE_BENCH_TOKEN");
        env::remove_var("OPENAPI_PROXY_MODE");
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
        env::set_var("OPENAPI_TLS_CERT_PATH", "/var/cert.pem");
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
    fn prod_requires_tls_cert() {
        let _lock = ENV_TEST_LOCK.lock().unwrap();
        clear_tls_env();
        env::set_var("OPENAPI_PROFILE", "prod");
        env::set_var("OPENAPI_TLS_SEALED_KEY_PATH", "/var/sealed.json");
        assert!(matches!(
            validate_tls_key_policy(EdgeProfile::Prod),
            Err(ProfileError::ProdMissingTlsCert)
        ));
        clear_tls_env();
    }

    #[test]
    fn prod_rejects_host_seal_root() {
        let _lock = ENV_TEST_LOCK.lock().unwrap();
        clear_tls_env();
        env::set_var("OPENAPI_PROFILE", "prod");
        env::set_var("OPENAPI_TLS_CERT_PATH", "/var/cert.pem");
        env::set_var("OPENAPI_TLS_SEALED_KEY_PATH", "/var/sealed.json");
        env::set_var("OPENAPI_SEAL_ROOT_HEX", "aa".repeat(32));
        assert!(matches!(
            validate_tls_key_policy(EdgeProfile::Prod),
            Err(ProfileError::ProdHostSealRoot)
        ));
        clear_tls_env();
    }

    #[test]
    fn prod_rejects_attested_launch_override() {
        let _lock = ENV_TEST_LOCK.lock().unwrap();
        clear_tls_env();
        env::set_var("OPENAPI_PROFILE", "prod");
        env::set_var("OPENAPI_TLS_CERT_PATH", "/var/cert.pem");
        env::set_var("OPENAPI_TLS_SEALED_KEY_PATH", "/var/sealed.json");
        env::set_var("OPENAPI_ATTESTED_LAUNCH_DIGEST", "a".repeat(64));
        assert!(matches!(
            validate_tls_key_policy(EdgeProfile::Prod),
            Err(ProfileError::ProdAttestedLaunchOverride)
        ));
        clear_tls_env();
    }

    #[test]
    fn prod_rejects_amd_sp_derived_key_override() {
        let _lock = ENV_TEST_LOCK.lock().unwrap();
        clear_tls_env();
        env::set_var("OPENAPI_PROFILE", "prod");
        env::set_var("OPENAPI_TLS_CERT_PATH", "/var/cert.pem");
        env::set_var("OPENAPI_TLS_SEALED_KEY_PATH", "/var/sealed.json");
        env::set_var("OPENAPI_AMD_SP_DERIVED_KEY_HEX", "ab".repeat(32));
        assert!(matches!(
            validate_tls_key_policy(EdgeProfile::Prod),
            Err(ProfileError::ProdAmdSpDerivedKeyOverride)
        ));
        clear_tls_env();
    }

    #[test]
    fn host_seal_tool_forbidden_in_prod() {
        assert!(matches!(
            assert_dev_host_seal_tool(EdgeProfile::Prod),
            Err(ProfileError::ProdHostSealTool)
        ));
        assert!(assert_dev_host_seal_tool(EdgeProfile::Dev).is_ok());
    }

    #[test]
    fn prod_rejects_challenge_bench_token() {
        let _lock = ENV_TEST_LOCK.lock().unwrap();
        clear_tls_env();
        env::set_var("OPENAPI_PROFILE", "prod");
        env::set_var("OPENAPI_TLS_CERT_PATH", "/var/cert.pem");
        env::set_var("OPENAPI_TLS_SEALED_KEY_PATH", "/var/sealed.json");
        env::set_var("OPENAPI_CHALLENGE_BENCH_TOKEN", "lab-secret");
        assert!(matches!(
            validate_tls_key_policy(EdgeProfile::Prod),
            Err(ProfileError::ProdChallengeBenchToken)
        ));
        clear_tls_env();
    }

    #[test]
    fn prod_rejects_transparent_proxy_mode() {
        let _lock = ENV_TEST_LOCK.lock().unwrap();
        clear_tls_env();
        env::set_var("OPENAPI_PROFILE", "prod");
        env::set_var("OPENAPI_TLS_CERT_PATH", "/var/cert.pem");
        env::set_var("OPENAPI_TLS_SEALED_KEY_PATH", "/var/sealed.json");
        env::set_var("OPENAPI_PROXY_MODE", "transparent");
        assert!(matches!(
            validate_tls_key_policy(EdgeProfile::Prod),
            Err(ProfileError::ProdTransparentProxy)
        ));
        clear_tls_env();
    }

    #[test]
    fn prod_ok_with_cert_and_sealed_key() {
        let _lock = ENV_TEST_LOCK.lock().unwrap();
        clear_tls_env();
        env::set_var("OPENAPI_PROFILE", "prod");
        env::set_var("OPENAPI_TLS_CERT_PATH", "/var/cert.pem");
        env::set_var("OPENAPI_TLS_SEALED_KEY_PATH", "/var/sealed.json");
        assert!(validate_tls_key_policy(EdgeProfile::Prod).is_ok());
        clear_tls_env();
    }
}
