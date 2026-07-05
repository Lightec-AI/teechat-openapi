use openapi_platform::{Measurement, Sealer};

#[derive(Debug, Clone)]
pub struct SgxSealer {
    mrenclave: String,
}

impl SgxSealer {
    pub fn new(mrenclave: impl Into<String>) -> Self {
        Self {
            mrenclave: mrenclave.into(),
        }
    }
}

impl Sealer for SgxSealer {
    fn sealing_measurement(&self) -> Measurement {
        Measurement::Mrenclave {
            value: self.mrenclave.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nsgx-test\n-----END PRIVATE KEY-----\n";

    #[test]
    fn sgx_sealer_roundtrip() {
        let sealer = SgxSealer::new("mrenclave-deadbeef");
        let blob = sealer.seal_tls_key(KEY, None).unwrap();
        match blob.measurement {
            Measurement::Mrenclave { ref value } => assert_eq!(value, "mrenclave-deadbeef"),
            _ => panic!("expected mrenclave"),
        }
        assert_eq!(sealer.unseal_tls_key(&blob, None).unwrap(), KEY);
    }

    #[test]
    fn sgx_sealer_wrong_enclave_fails() {
        let a = SgxSealer::new("enclave-a");
        let b = SgxSealer::new("enclave-b");
        let blob = a.seal_tls_key(KEY, None).unwrap();
        assert!(b.unseal_tls_key(&blob, None).is_err());
    }

    #[test]
    fn sgx_sealer_with_seal_root() {
        let sealer = SgxSealer::new("mr-root");
        let root = [0x55u8; 32];
        let blob = sealer.seal_tls_key(KEY, Some(&root)).unwrap();
        assert_eq!(sealer.unseal_tls_key(&blob, Some(&root)).unwrap(), KEY);
    }
}
