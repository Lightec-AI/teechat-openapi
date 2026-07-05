use openapi_platform::{Measurement, Sealer};

#[derive(Debug, Clone)]
pub struct CvmSealer {
    launch_digest: String,
    image_digest: String,
}

impl CvmSealer {
    pub fn new(launch_digest: impl Into<String>, image_digest: impl Into<String>) -> Self {
        Self {
            launch_digest: launch_digest.into(),
            image_digest: image_digest.into(),
        }
    }

    pub fn from_env(launch_digest: &str, image_digest: &str) -> Self {
        Self::new(launch_digest, image_digest)
    }
}

impl Sealer for CvmSealer {
    fn sealing_measurement(&self) -> Measurement {
        Measurement::LaunchDigest {
            launch_digest: self.launch_digest.clone(),
            image_digest: self.image_digest.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openapi_platform::{seal_tls_private_key, unseal_tls_private_key};

    const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\ncvm-test\n-----END PRIVATE KEY-----\n";

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
}
