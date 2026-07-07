use openapi_platform::{
    derive_cvm_seal_root, unseal_tls_private_key, Measurement, PlatformError, Sealer,
};

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

    /// Resolve seal root from **host env** (`OPENAPI_SEAL_ROOT_HEX`); prod derives inside guest.
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
            verify_launch_digest_attested(&self.launch_digest)?;
            return Ok(Some(derive_cvm_seal_root(
                &self.launch_digest,
                &self.image_digest,
            )));
        }
        Ok(host_env_supplied.copied())
    }

    fn effective_seal_root(
        &self,
        caller_supplied: Option<&[u8; 32]>,
    ) -> Result<Option<[u8; 32]>, PlatformError> {
        if self.prod {
            verify_launch_digest_attested(&self.launch_digest)?;
            return Ok(Some(derive_cvm_seal_root(
                &self.launch_digest,
                &self.image_digest,
            )));
        }
        Ok(caller_supplied.copied())
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
        let effective_root = self.effective_seal_root(seal_root)?;
        openapi_platform::seal_tls_private_key(
            &self.sealing_measurement(),
            key_pem,
            effective_root.as_ref(),
        )
    }

    fn unseal_tls_key(
        &self,
        blob: &SealedTlsKeyBlob,
        seal_root: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>, PlatformError> {
        let effective_root = self.effective_seal_root(seal_root)?;
        unseal_tls_private_key(blob, &self.sealing_measurement(), effective_root.as_ref())
    }
}

use openapi_platform::SealedTlsKeyBlob;

#[cfg(test)]
mod tests {
    use super::*;
    use openapi_platform::{seal_tls_private_key, unseal_tls_private_key};

    use crate::guest_digest::ATTESTED_ENV_TEST_LOCK;

    const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\ncvm-test\n-----END PRIVATE KEY-----\n";

    fn launch_hex() -> String {
        "d".repeat(64)
    }

    fn set_attested(digest: &str) {
        std::env::set_var("OPENAPI_ATTESTED_LAUNCH_DIGEST", digest);
    }

    fn clear_attested() {
        std::env::remove_var("OPENAPI_ATTESTED_LAUNCH_DIGEST");
    }

    fn with_attested_env(f: impl FnOnce()) {
        let _guard = ATTESTED_ENV_TEST_LOCK.lock().unwrap();
        clear_attested();
        f();
        clear_attested();
    }

    #[test]
    fn cvm_sealer_roundtrip_via_trait() {
        let sealer = CvmSealer::new("ld1", "id1");
        let blob = sealer.seal_tls_key(KEY, None).unwrap();
        assert_eq!(blob.measurement, sealer.sealing_measurement());
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
    fn prod_unseal_requires_attested_launch_digest() {
        with_attested_env(|| {
            let launch = launch_hex();
            let sealer = CvmSealer::with_profile(&launch, "id-prod", true);
            assert!(sealer.seal_tls_key(KEY, None).is_err());

            set_attested(&launch);
            let sealer = CvmSealer::with_profile(&launch, "id-prod", true);
            let blob = sealer.seal_tls_key(KEY, None).unwrap();
            let plain = sealer.unseal_tls_key(&blob, None).unwrap();
            assert_eq!(plain, KEY);
        });
    }

    #[test]
    fn prod_unseal_rejects_launch_digest_mismatch() {
        with_attested_env(|| {
            let launch = launch_hex();
            set_attested(&launch);
            let blob = CvmSealer::with_profile(&launch, "id-prod", true)
                .seal_tls_key(KEY, None)
                .unwrap();
            let sealer = CvmSealer::with_profile("e".repeat(64), "id-prod", true);
            assert!(sealer.unseal_tls_key(&blob, None).is_err());
        });
    }

    #[test]
    fn prod_rejects_host_seal_root() {
        with_attested_env(|| {
            let launch = launch_hex();
            set_attested(&launch);
            let sealer = CvmSealer::with_profile(&launch, "id-prod", true);
            assert!(sealer.resolve_seal_root(Some(&[1u8; 32])).is_err());
        });
    }

    #[test]
    fn prod_derives_seal_root() {
        with_attested_env(|| {
            let launch = launch_hex();
            set_attested(&launch);
            let sealer = CvmSealer::with_profile(&launch, "id-prod", true);
            let root = sealer.resolve_seal_root(None).unwrap();
            assert!(root.is_some());
        });
    }
}
