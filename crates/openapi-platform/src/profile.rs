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
    #[error("OPENAPI_PROFILE is required (expected dev|prod|production)")]
    MissingProfile,
    #[error("invalid OPENAPI_PROFILE {0:?} (expected dev|prod|production)")]
    UnknownProfile(String),
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
    #[error("OPENAPI_PROFILE=prod forbids host-side seal-tls-key tools — run the in-TEE ceremony")]
    ProdHostSealTool,
    #[error(
        "prod forbids OPENAPI_CHALLENGE_BENCH_TOKEN — challenge DoS caps must stay on (BENCH-001)"
    )]
    ProdChallengeBenchToken,
    #[error("prod forbids OPENAPI_PROXY_MODE=transparent — use allowlist (PROXY-001)")]
    ProdTransparentProxy,
    #[error(
        "prod forbids OPENAPI_TLS_KEY_POLICY_PATH — use measured /etc/tls_key_policy (POLICY-001)"
    )]
    ProdTlsKeyPolicyPathOverride,
    #[error(
        "prod forbids OPENAPI_SNPGUEST_BIN on unmeasured data paths — use measured helper (SNPGUEST-001)"
    )]
    ProdUnmeasuredSnpguestBin,
    #[error(
        "prod requires measured app path — teechat.app_verity_root on cmdline and binary not under /data (APP-VERITY-001)"
    )]
    ProdMissingAppVerity,
}

pub fn parse_edge_profile(raw: Option<&str>) -> Result<EdgeProfile, ProfileError> {
    let raw = raw.map(str::trim).filter(|s| !s.is_empty());
    match raw.map(str::to_ascii_lowercase).as_deref() {
        Some("dev") => Ok(EdgeProfile::Dev),
        Some("prod") | Some("production") => Ok(EdgeProfile::Prod),
        Some(other) => Err(ProfileError::UnknownProfile(other.to_string())),
        None => Err(ProfileError::MissingProfile),
    }
}

/// Load the explicit runtime profile. Missing or unknown values fail closed.
pub fn load_edge_profile() -> Result<EdgeProfile, ProfileError> {
    let raw = std::env::var("OPENAPI_PROFILE").ok();
    parse_edge_profile(raw.as_deref())
}

/// Validate TLS key env against profile. Call at startup before unseal.
pub fn validate_tls_key_policy(profile: EdgeProfile) -> Result<(), ProfileError> {
    let sealed = std::env::var("OPENAPI_TLS_SEALED_KEY_PATH")
        .ok()
        .filter(|s| !s.is_empty());
    let plain = std::env::var("OPENAPI_TLS_KEY_PATH")
        .ok()
        .filter(|s| !s.is_empty());

    let ceremony_helper = std::env::var("OPENAPI_CEREMONY_HELPER_URL")
        .ok()
        .filter(|s| !s.is_empty());

    if profile.is_prod() {
        if plain.is_some() {
            return Err(ProfileError::ProdPlaintextTlsKey);
        }
        // Option A (SGX EDP): ceremony helper serves sealed-key.json + tls.crt over TCP.
        if ceremony_helper.is_none() {
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
        // POLICY-001: tls_key_policy must come from measured /etc/tls_key_policy.
        if std::env::var("OPENAPI_TLS_KEY_POLICY_PATH")
            .ok()
            .filter(|s| !s.is_empty())
            .is_some()
        {
            return Err(ProfileError::ProdTlsKeyPolicyPathOverride);
        }
        // SNPGUEST-001: soft-gate helper must not live on unmeasured data mounts.
        if let Ok(bin) = std::env::var("OPENAPI_SNPGUEST_BIN") {
            if is_unmeasured_guest_path(bin.trim()) {
                return Err(ProfileError::ProdUnmeasuredSnpguestBin);
            }
        }
    }
    Ok(())
}

/// Paths under known unmeasured OpenAPI data mounts (Talos `/var/mnt/…`, pod `/data/…`).
/// Measured app volume lives under `/var/mnt/teechat-openapi/app/…` (verity) — still on the
/// data *disk* but opened via dm-verity; Phase-1 `…/bin/openapi` (no `/app/`) is rejected.
pub fn is_unmeasured_guest_path(path: &str) -> bool {
    let lower = path.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }
    if lower == "/data" || lower.starts_with("/data/") {
        return true;
    }
    // Data disk helpers / Phase-1 binary — but allow measured app mount.
    if lower.starts_with("/var/mnt/teechat-openapi/app/")
        || lower.starts_with("/usr/local/teechat/")
    {
        return false;
    }
    lower.starts_with("/var/mnt/teechat-openapi/")
}

/// Kernel cmdline (Linux `/proc/cmdline`, or `OPENAPI_TEST_CMDLINE` under `cfg(test)`).
fn read_kernel_cmdline() -> Option<String> {
    #[cfg(test)]
    if let Ok(c) = std::env::var("OPENAPI_TEST_CMDLINE") {
        return Some(c);
    }
    std::fs::read_to_string("/proc/cmdline").ok()
}

/// Prod fail-closed: measured app volume (`teechat.app_verity_root`) + not exec from `/data`.
pub fn validate_measured_app_path(profile: EdgeProfile) -> Result<(), ProfileError> {
    if !profile.is_prod() {
        return Ok(());
    }
    let cmdline = read_kernel_cmdline().unwrap_or_default();
    if !cmdline
        .split_whitespace()
        .any(|t| t.starts_with("teechat.app_verity_root="))
    {
        return Err(ProfileError::ProdMissingAppVerity);
    }
    if let Ok(exe) = std::env::current_exe() {
        let p = exe.to_string_lossy();
        if is_unmeasured_guest_path(&p) {
            return Err(ProfileError::ProdMissingAppVerity);
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
        env::remove_var("OPENAPI_TLS_KEY_POLICY_PATH");
        env::remove_var("OPENAPI_SNPGUEST_BIN");
        env::remove_var("OPENAPI_TEST_CMDLINE");
    }

    #[test]
    fn missing_profile_is_rejected() {
        let _lock = ENV_TEST_LOCK.lock().unwrap();
        clear_tls_env();
        assert!(matches!(
            load_edge_profile(),
            Err(ProfileError::MissingProfile)
        ));
    }

    #[test]
    fn unknown_profile_is_rejected() {
        let _lock = ENV_TEST_LOCK.lock().unwrap();
        clear_tls_env();
        env::set_var("OPENAPI_PROFILE", "prd");
        assert!(matches!(
            load_edge_profile(),
            Err(ProfileError::UnknownProfile(v)) if v == "prd"
        ));
        env::remove_var("OPENAPI_PROFILE");
    }

    #[test]
    fn explicit_dev_profile() {
        let _lock = ENV_TEST_LOCK.lock().unwrap();
        clear_tls_env();
        env::set_var("OPENAPI_PROFILE", "dev");
        assert_eq!(load_edge_profile().unwrap(), EdgeProfile::Dev);
        env::remove_var("OPENAPI_PROFILE");
    }

    #[test]
    fn prod_profile_from_env() {
        let _lock = ENV_TEST_LOCK.lock().unwrap();
        clear_tls_env();
        env::set_var("OPENAPI_PROFILE", "prod");
        assert_eq!(load_edge_profile().unwrap(), EdgeProfile::Prod);
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

    #[test]
    fn prod_rejects_tls_key_policy_path_override() {
        let _lock = ENV_TEST_LOCK.lock().unwrap();
        clear_tls_env();
        env::set_var("OPENAPI_PROFILE", "prod");
        env::set_var("OPENAPI_TLS_CERT_PATH", "/var/cert.pem");
        env::set_var("OPENAPI_TLS_SEALED_KEY_PATH", "/var/sealed.json");
        env::set_var(
            "OPENAPI_TLS_KEY_POLICY_PATH",
            "/var/mnt/teechat-openapi/tls_key_policy",
        );
        assert!(matches!(
            validate_tls_key_policy(EdgeProfile::Prod),
            Err(ProfileError::ProdTlsKeyPolicyPathOverride)
        ));
        clear_tls_env();
    }

    #[test]
    fn prod_rejects_unmeasured_snpguest_bin() {
        let _lock = ENV_TEST_LOCK.lock().unwrap();
        clear_tls_env();
        env::set_var("OPENAPI_PROFILE", "prod");
        env::set_var("OPENAPI_TLS_CERT_PATH", "/var/cert.pem");
        env::set_var("OPENAPI_TLS_SEALED_KEY_PATH", "/var/sealed.json");
        env::set_var("OPENAPI_SNPGUEST_BIN", "/data/bin/snpguest");
        assert!(matches!(
            validate_tls_key_policy(EdgeProfile::Prod),
            Err(ProfileError::ProdUnmeasuredSnpguestBin)
        ));
        clear_tls_env();
    }

    #[test]
    fn unmeasured_guest_path_detects_data_mounts() {
        assert!(is_unmeasured_guest_path("/data/bin/snpguest"));
        assert!(is_unmeasured_guest_path(
            "/var/mnt/teechat-openapi/bin/snpguest"
        ));
        assert!(!is_unmeasured_guest_path(
            "/var/mnt/teechat-openapi/app/usr/local/teechat/bin/openapi"
        ));
        assert!(!is_unmeasured_guest_path("/usr/local/teechat/bin/snpguest"));
        assert!(!is_unmeasured_guest_path("snpguest"));
    }

    #[test]
    fn prod_requires_app_verity_cmdline() {
        let _lock = ENV_TEST_LOCK.lock().unwrap();
        clear_tls_env();
        env::remove_var("OPENAPI_TEST_CMDLINE");
        env::set_var("OPENAPI_PROFILE", "prod");
        assert!(matches!(
            validate_measured_app_path(EdgeProfile::Prod),
            Err(ProfileError::ProdMissingAppVerity)
        ));
        env::set_var(
            "OPENAPI_TEST_CMDLINE",
            "BOOT_IMAGE=/boot/vmlinuz teechat.app_verity_root=abc123",
        );
        assert!(validate_measured_app_path(EdgeProfile::Prod).is_ok());
        env::remove_var("OPENAPI_TEST_CMDLINE");
        clear_tls_env();
    }
}
