use openapi_platform::{
    derive_cvm_seal_root, seal_tls_private_key_amd_sp, unseal_tls_private_key,
    unseal_tls_private_key_amd_sp, AmdSpSealMeta, Measurement, PlatformError, SealedTlsKeyBlob,
    Sealer, SEAL_VERSION, SEAL_VERSION_SNP_AMD_SP,
};

use crate::amd_sp_key::derive_amd_sp_seal_key;
use crate::guest_digest::verify_launch_digest_attested;

#[derive(Debug, Clone)]
pub struct CvmSealer {
    launch_digest: String,
    image_digest: String,
    prod: bool,
}

impl CvmSealer {
    pub fn new(launch_digest: impl Into<String>, image_digest: impl Into<String>) -> Self {
        Self {
            launch_digest: launch_digest.into(),
            image_digest: image_digest.into(),
            prod: false,
        }
    }

    pub fn with_profile(
        launch_digest: impl Into<String>,
        image_digest: impl Into<String>,
        prod: bool,
    ) -> Self {
        Self {
            launch_digest: launch_digest.into(),
            image_digest: image_digest.into(),
            prod,
        }
    }

    pub fn from_env(launch_digest: &str, image_digest: &str) -> Self {
        Self::new(launch_digest, image_digest)
    }

    /// Resolve host-supplied seal root (`OPENAPI_SEAL_ROOT_HEX`).
    ///
    /// Prod always returns `None`: `seal_tls_key` / `unseal_tls_key` derive AMD-SP (v3)
    /// or measurement HKDF (legacy v1) internally. Passing a host root into those
    /// methods is rejected — so this must not return `Some(amd_sp_key)` (that was a
    /// startup footgun: main forwarded it and unseal failed closed).
    pub fn resolve_seal_root(
        &self,
        host_env_supplied: Option<&[u8; 32]>,
    ) -> Result<Option<[u8; 32]>, PlatformError> {
        if self.prod {
            if host_env_supplied.is_some() {
                return Err(PlatformError::Seal(
                    "OPENAPI_SEAL_ROOT_HEX must not be host-supplied in prod".into(),
                ));
            }
            return Ok(None);
        }
        Ok(host_env_supplied.copied())
    }

    fn amd_sp_meta(&self) -> AmdSpSealMeta {
        AmdSpSealMeta::teechat_default()
    }
}

impl Sealer for CvmSealer {
    fn sealing_measurement(&self) -> Measurement {
        Measurement::LaunchDigest {
            launch_digest: self.launch_digest.clone(),
            image_digest: self.image_digest.clone(),
        }
    }

    fn seal_tls_key(
        &self,
        key_pem: &[u8],
        seal_root: Option<&[u8; 32]>,
    ) -> Result<SealedTlsKeyBlob, PlatformError> {
        if self.prod {
            if seal_root.is_some() {
                return Err(PlatformError::Seal(
                    "OPENAPI_SEAL_ROOT_HEX must not be host-supplied in prod".into(),
                ));
            }
            verify_launch_digest_attested(&self.launch_digest)?;
            let meta = self.amd_sp_meta();
            let amd_key = derive_amd_sp_seal_key(&meta)?;
            return seal_tls_private_key_amd_sp(
                &self.sealing_measurement(),
                key_pem,
                &amd_key,
                &meta,
            );
        }
        openapi_platform::seal_tls_private_key(&self.sealing_measurement(), key_pem, seal_root)
    }

    fn unseal_tls_key(
        &self,
        blob: &SealedTlsKeyBlob,
        seal_root: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>, PlatformError> {
        if self.prod {
            if seal_root.is_some() {
                return Err(PlatformError::Seal(
                    "OPENAPI_SEAL_ROOT_HEX must not be host-supplied in prod".into(),
                ));
            }
            verify_launch_digest_attested(&self.launch_digest)?;
            match blob.seal_version {
                SEAL_VERSION_SNP_AMD_SP => {
                    let meta = blob.amd_sp.as_ref().ok_or_else(|| {
                        PlatformError::Seal("amd_sp metadata required for seal_version 3".into())
                    })?;
                    let amd_key = derive_amd_sp_seal_key(meta)?;
                    unseal_tls_private_key_amd_sp(blob, &self.sealing_measurement(), &amd_key)
                }
                SEAL_VERSION => {
                    // Legacy grace: v1 measurement-labeled blobs still unseal after digest gate.
                    let root = derive_cvm_seal_root(&self.launch_digest, &self.image_digest);
                    unseal_tls_private_key(blob, &self.sealing_measurement(), Some(&root))
                }
                other => Err(PlatformError::Seal(format!(
                    "unsupported seal_version {other} for CVM prod unseal (expected {SEAL_VERSION_SNP_AMD_SP} or legacy {SEAL_VERSION})"
                ))),
            }
        } else {
            unseal_tls_private_key(blob, &self.sealing_measurement(), seal_root)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openapi_platform::{seal_tls_private_key, unseal_tls_private_key};

    use crate::amd_sp_key::{set_test_amd_sp_derived_key, AMD_SP_KEY_TEST_LOCK};
    use crate::guest_digest::{set_test_attested_launch_digest, ATTESTED_ENV_TEST_LOCK};

    const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\ncvm-test\n-----END PRIVATE KEY-----\n";

    fn launch_hex() -> String {
        "d".repeat(64)
    }

    fn with_prod_injects(f: impl FnOnce()) {
        let _g1 = ATTESTED_ENV_TEST_LOCK.lock().unwrap();
        let _g2 = AMD_SP_KEY_TEST_LOCK.lock().unwrap();
        std::env::remove_var("OPENAPI_ATTESTED_LAUNCH_DIGEST");
        std::env::remove_var("OPENAPI_AMD_SP_DERIVED_KEY_HEX");
        std::env::remove_var("OPENAPI_PROFILE");
        set_test_attested_launch_digest(None);
        set_test_amd_sp_derived_key(None);
        f();
        std::env::remove_var("OPENAPI_ATTESTED_LAUNCH_DIGEST");
        std::env::remove_var("OPENAPI_AMD_SP_DERIVED_KEY_HEX");
        std::env::remove_var("OPENAPI_PROFILE");
        set_test_attested_launch_digest(None);
        set_test_amd_sp_derived_key(None);
    }

    #[test]
    fn cvm_sealer_roundtrip_via_trait() {
        let sealer = CvmSealer::new("ld1", "id1");
        let blob = sealer.seal_tls_key(KEY, None).unwrap();
        assert_eq!(blob.measurement, sealer.sealing_measurement());
        assert_eq!(blob.seal_version, SEAL_VERSION);
        let plain = sealer.unseal_tls_key(&blob, None).unwrap();
        assert_eq!(plain, KEY);
    }

    #[test]
    fn cvm_sealer_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("cvm-seal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tls-key.sealed.json");

        let sealer = CvmSealer::new("ld-file", "id-file");
        sealer.seal_tls_key_to_file(KEY, &path, None).unwrap();
        let plain = sealer.unseal_tls_key_from_file(&path, None).unwrap();
        assert_eq!(plain, KEY);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cvm_sealer_wrong_guest_fails() {
        let sealer_a = CvmSealer::new("ld-a", "id-a");
        let sealer_b = CvmSealer::new("ld-b", "id-a");
        let blob = sealer_a.seal_tls_key(KEY, None).unwrap();
        assert!(sealer_b.unseal_tls_key(&blob, None).is_err());
    }

    #[test]
    fn cvm_sealer_matches_low_level_api() {
        let sealer = CvmSealer::new("ld-low", "id-low");
        let m = sealer.sealing_measurement();
        let blob = seal_tls_private_key(&m, KEY, None).unwrap();
        let plain = unseal_tls_private_key(&blob, &m, None).unwrap();
        assert_eq!(plain, KEY);
    }

    #[test]
    fn prod_seals_with_amd_sp_version() {
        with_prod_injects(|| {
            let launch = launch_hex();
            set_test_attested_launch_digest(Some(launch.clone()));
            set_test_amd_sp_derived_key(Some([0xABu8; 32]));
            let sealer = CvmSealer::with_profile(&launch, "id-prod", true);
            let blob = sealer.seal_tls_key(KEY, None).unwrap();
            assert_eq!(blob.seal_version, SEAL_VERSION_SNP_AMD_SP);
            assert!(blob.amd_sp.is_some());
            assert_eq!(sealer.unseal_tls_key(&blob, None).unwrap(), KEY);
        });
    }

    #[test]
    fn prod_unseal_requires_attested_launch_digest() {
        with_prod_injects(|| {
            let launch = launch_hex();
            set_test_amd_sp_derived_key(Some([0xABu8; 32]));
            let sealer = CvmSealer::with_profile(&launch, "id-prod", true);
            assert!(sealer.seal_tls_key(KEY, None).is_err());

            set_test_attested_launch_digest(Some(launch.clone()));
            let blob = sealer.seal_tls_key(KEY, None).unwrap();
            assert_eq!(sealer.unseal_tls_key(&blob, None).unwrap(), KEY);
        });
    }

    #[test]
    fn prod_unseal_rejects_launch_digest_mismatch() {
        with_prod_injects(|| {
            let launch = launch_hex();
            set_test_attested_launch_digest(Some(launch.clone()));
            set_test_amd_sp_derived_key(Some([0xABu8; 32]));
            let blob = CvmSealer::with_profile(&launch, "id-prod", true)
                .seal_tls_key(KEY, None)
                .unwrap();
            let sealer = CvmSealer::with_profile("e".repeat(64), "id-prod", true);
            assert!(sealer.unseal_tls_key(&blob, None).is_err());
        });
    }

    #[test]
    fn prod_rejects_host_seal_root() {
        with_prod_injects(|| {
            let launch = launch_hex();
            set_test_attested_launch_digest(Some(launch.clone()));
            set_test_amd_sp_derived_key(Some([0xABu8; 32]));
            let sealer = CvmSealer::with_profile(&launch, "id-prod", true);
            assert!(sealer.resolve_seal_root(Some(&[1u8; 32])).is_err());
            assert!(sealer.seal_tls_key(KEY, Some(&[1u8; 32])).is_err());
            // Prod callers (bins/openapi) must get None and pass None into unseal.
            assert_eq!(sealer.resolve_seal_root(None).unwrap(), None);
        });
    }

    #[test]
    fn prod_different_amd_sp_key_cannot_unseal() {
        with_prod_injects(|| {
            let launch = launch_hex();
            set_test_attested_launch_digest(Some(launch.clone()));
            set_test_amd_sp_derived_key(Some([0xABu8; 32]));
            let sealer = CvmSealer::with_profile(&launch, "id-prod", true);
            let blob = sealer.seal_tls_key(KEY, None).unwrap();
            set_test_amd_sp_derived_key(Some([0xCDu8; 32]));
            assert!(sealer.unseal_tls_key(&blob, None).is_err());
        });
    }

    #[test]
    fn prod_still_unseals_legacy_v1_blobs() {
        with_prod_injects(|| {
            let launch = launch_hex();
            set_test_attested_launch_digest(Some(launch.clone()));
            set_test_amd_sp_derived_key(Some([0xABu8; 32]));
            let root = derive_cvm_seal_root(&launch, "id-prod");
            let m = Measurement::LaunchDigest {
                launch_digest: launch.clone(),
                image_digest: "id-prod".into(),
            };
            let legacy = seal_tls_private_key(&m, KEY, Some(&root)).unwrap();
            assert_eq!(legacy.seal_version, SEAL_VERSION);
            let sealer = CvmSealer::with_profile(&launch, "id-prod", true);
            assert_eq!(sealer.unseal_tls_key(&legacy, None).unwrap(), KEY);
        });
    }

    #[test]
    fn ops001_prod_profile_rejects_env_attested_override() {
        with_prod_injects(|| {
            let launch = launch_hex();
            std::env::set_var("OPENAPI_PROFILE", "prod");
            std::env::set_var("OPENAPI_ATTESTED_LAUNCH_DIGEST", &launch);
            set_test_amd_sp_derived_key(Some([0xABu8; 32]));
            let sealer = CvmSealer::with_profile(&launch, "id-prod", true);
            assert!(sealer.seal_tls_key(KEY, None).is_err());
            set_test_attested_launch_digest(Some(launch.clone()));
            let blob = sealer.seal_tls_key(KEY, None).unwrap();
            assert_eq!(blob.seal_version, SEAL_VERSION_SNP_AMD_SP);
            assert_eq!(sealer.unseal_tls_key(&blob, None).unwrap(), KEY);
        });
    }

    #[test]
    fn ops003_prod_profile_rejects_env_amd_sp_override() {
        with_prod_injects(|| {
            let launch = launch_hex();
            std::env::set_var("OPENAPI_PROFILE", "prod");
            set_test_attested_launch_digest(Some(launch.clone()));
            std::env::set_var("OPENAPI_AMD_SP_DERIVED_KEY_HEX", hex::encode([0xABu8; 32]));
            let sealer = CvmSealer::with_profile(&launch, "id-prod", true);
            let err = sealer.seal_tls_key(KEY, None).unwrap_err();
            assert!(
                err.to_string().contains("OPENAPI_AMD_SP_DERIVED_KEY_HEX"),
                "got: {err}"
            );
        });
    }
}
