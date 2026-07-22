//! AMD Secure Processor derived keys for CVM TLS sealing (`seal_version` 3).
//!
//! Thin OpenAPI wrapper over public `attested-mtls-snp-seal` (hardware derive +
//! OPS-003 prod env forbid). Production path: `SNP_GET_DERIVED_KEY` via
//! `/dev/sev-guest`.

use attested_mtls_snp_seal::{derive_amd_sp_seal_key as snp_derive, DerivePolicy};
use openapi_platform::{load_edge_profile, AmdSpSealMeta, PlatformError};

/// Dev/CI hook (legacy name — forwarded to snp-seal).
#[cfg(test)]
const AMD_SP_KEY_ENV: &str = "OPENAPI_AMD_SP_DERIVED_KEY_HEX";

/// Serializes tests that mutate AMD-SP key env / inject.
#[cfg(test)]
pub(crate) static AMD_SP_KEY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Derive the 32-byte sealing key from the AMD Secure Processor.
pub fn derive_amd_sp_seal_key(meta: &AmdSpSealMeta) -> Result<[u8; 32], PlatformError> {
    let policy = if load_edge_profile().is_prod() {
        DerivePolicy::prod()
    } else {
        DerivePolicy::dev()
    };
    snp_derive(meta, policy).map_err(|e| PlatformError::Seal(e.to_string()))
}

/// cfg(test) only — inject AMD-SP key for prod-path unit tests.
#[cfg(test)]
pub(crate) fn set_test_amd_sp_derived_key(v: Option<[u8; 32]>) {
    attested_mtls_snp_seal::set_test_amd_sp_derived_key(v);
}

#[cfg(test)]
mod tests {
    use super::*;
    use openapi_platform::AmdSpSealMeta;

    fn with_amd_sp_env(f: impl FnOnce()) {
        let _guard = AMD_SP_KEY_TEST_LOCK.lock().unwrap();
        std::env::remove_var(AMD_SP_KEY_ENV);
        std::env::remove_var("TEECHAT_AMD_SP_DERIVED_KEY_HEX");
        std::env::remove_var("OPENAPI_PROFILE");
        set_test_amd_sp_derived_key(None);
        f();
        std::env::remove_var(AMD_SP_KEY_ENV);
        std::env::remove_var("TEECHAT_AMD_SP_DERIVED_KEY_HEX");
        std::env::remove_var("OPENAPI_PROFILE");
        set_test_amd_sp_derived_key(None);
    }

    #[test]
    fn parses_env_hex_in_dev() {
        with_amd_sp_env(|| {
            let key = [0x11u8; 32];
            std::env::set_var(AMD_SP_KEY_ENV, hex::encode(key));
            let got = derive_amd_sp_seal_key(&AmdSpSealMeta::teechat_default()).unwrap();
            assert_eq!(got, key);
        });
    }

    #[test]
    fn prod_forbids_env_override() {
        with_amd_sp_env(|| {
            std::env::set_var("OPENAPI_PROFILE", "prod");
            std::env::set_var(AMD_SP_KEY_ENV, hex::encode([0x22u8; 32]));
            let err = derive_amd_sp_seal_key(&AmdSpSealMeta::teechat_default()).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("forbidden") && msg.contains("production"),
                "got: {msg}"
            );
        });
    }

    #[test]
    fn prod_allows_test_inject() {
        with_amd_sp_env(|| {
            let key = [0x33u8; 32];
            std::env::set_var("OPENAPI_PROFILE", "prod");
            set_test_amd_sp_derived_key(Some(key));
            assert_eq!(
                derive_amd_sp_seal_key(&AmdSpSealMeta::teechat_default()).unwrap(),
                key
            );
        });
    }

    #[test]
    fn rejects_wrong_hex_length() {
        with_amd_sp_env(|| {
            std::env::set_var(AMD_SP_KEY_ENV, "abcd");
            assert!(derive_amd_sp_seal_key(&AmdSpSealMeta::teechat_default()).is_err());
        });
    }
}
