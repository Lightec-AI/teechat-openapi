//! AMD Secure Processor derived keys for CVM TLS sealing (`seal_version` 3).
//!
//! Production path: `SNP_GET_DERIVED_KEY` / firmware `MSG_KEY_REQ` via `/dev/sev-guest`
//! ([Linux sev-guest docs](https://docs.kernel.org/virt/coco/sev-guest.html)).
//!
//! **OPS-003:** `OPENAPI_AMD_SP_DERIVED_KEY_HEX` is a **dev/CI-only** bypass. When
//! `OPENAPI_PROFILE=prod`, the override is forbidden (fail closed).

use openapi_platform::{load_edge_profile, AmdSpSealMeta, PlatformError};

/// Dev/CI hook: 64 hex chars → 32-byte stand-in for AMD-SP derived key.
const AMD_SP_KEY_ENV: &str = "OPENAPI_AMD_SP_DERIVED_KEY_HEX";

/// Unit-test inject (works under `OPENAPI_PROFILE=prod` without the env bypass).
#[cfg(test)]
static TEST_AMD_SP_KEY: std::sync::Mutex<Option<[u8; 32]>> = std::sync::Mutex::new(None);

/// Serializes tests that mutate AMD-SP key env / inject.
#[cfg(test)]
pub(crate) static AMD_SP_KEY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Derive the 32-byte sealing key from the AMD Secure Processor.
///
/// Order (prod): hardware `/dev/sev-guest` only.  
/// Order (dev): env override → hardware → error.
pub fn derive_amd_sp_seal_key(meta: &AmdSpSealMeta) -> Result<[u8; 32], PlatformError> {
    #[cfg(test)]
    {
        if let Some(k) = *TEST_AMD_SP_KEY.lock().unwrap() {
            return Ok(k);
        }
    }

    if let Ok(v) = std::env::var(AMD_SP_KEY_ENV) {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            if load_edge_profile().is_prod() {
                return Err(PlatformError::Seal(
                    "OPENAPI_AMD_SP_DERIVED_KEY_HEX is forbidden when OPENAPI_PROFILE=prod; \
                     use SNP_GET_DERIVED_KEY via /dev/sev-guest (OPS-003)"
                        .into(),
                ));
            }
            return parse_key_hex(trimmed);
        }
    }

    derive_amd_sp_seal_key_hardware(meta)
}

/// cfg(test) only — inject AMD-SP key for prod-path unit tests.
#[cfg(test)]
pub(crate) fn set_test_amd_sp_derived_key(v: Option<[u8; 32]>) {
    *TEST_AMD_SP_KEY.lock().unwrap() = v;
}

fn parse_key_hex(hex_str: &str) -> Result<[u8; 32], PlatformError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| PlatformError::Seal(format!("OPENAPI_AMD_SP_DERIVED_KEY_HEX decode: {e}")))?;
    if bytes.len() != 32 {
        return Err(PlatformError::Seal(format!(
            "OPENAPI_AMD_SP_DERIVED_KEY_HEX must be 32 bytes (64 hex chars), got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(target_os = "linux")]
fn derive_amd_sp_seal_key_hardware(meta: &AmdSpSealMeta) -> Result<[u8; 32], PlatformError> {
    use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};
    use std::path::Path;

    if !Path::new("/dev/sev-guest").exists() {
        return Err(PlatformError::Seal(
            "AMD-SP seal requires /dev/sev-guest (SNP_GET_DERIVED_KEY)".into(),
        ));
    }

    let root_vmrk = match meta.root_key.as_str() {
        "vcek" => false,
        "vmrk" => true,
        other => {
            return Err(PlatformError::Seal(format!(
                "unsupported amd_sp.root_key {other:?} (expected vcek|vmrk)"
            )));
        }
    };

    let request = DerivedKey::new(
        root_vmrk,
        GuestFieldSelect(meta.guest_field_select),
        meta.vmpl,
        meta.guest_svn,
        meta.tcb_version,
        None, // msg_version 1 — launch_mit_vector unused
    );

    let mut fw = Firmware::open().map_err(|e| {
        PlatformError::Seal(format!("open /dev/sev-guest for AMD-SP derive: {e}"))
    })?;

    fw.get_derived_key(Some(meta.msg_version), request)
        .map_err(|e| PlatformError::Seal(format!("SNP_GET_DERIVED_KEY failed: {e}")))
}

#[cfg(not(target_os = "linux"))]
fn derive_amd_sp_seal_key_hardware(_meta: &AmdSpSealMeta) -> Result<[u8; 32], PlatformError> {
    Err(PlatformError::Seal(
        "AMD-SP SNP_GET_DERIVED_KEY is only available on Linux SNP guests".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openapi_platform::AmdSpSealMeta;

    fn with_amd_sp_env(f: impl FnOnce()) {
        let _guard = AMD_SP_KEY_TEST_LOCK.lock().unwrap();
        std::env::remove_var(AMD_SP_KEY_ENV);
        std::env::remove_var("OPENAPI_PROFILE");
        set_test_amd_sp_derived_key(None);
        f();
        std::env::remove_var(AMD_SP_KEY_ENV);
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
                msg.contains("OPENAPI_AMD_SP_DERIVED_KEY_HEX") && msg.contains("prod"),
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
