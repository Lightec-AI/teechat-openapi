//! SGX sealing: Fortanix EGETKEY (`seal_version` 2) inside enclave; HKDF stub on host builds.

#[cfg(not(target_env = "sgx"))]
use openapi_platform::{
    derive_seal_key, seal_tls_private_key, unseal_tls_private_key, SEAL_VERSION,
};
use openapi_platform::{
    Measurement, PlatformError, SealedTlsKeyBlob, Sealer, SEAL_VERSION, SEAL_VERSION_SGX_EGETKEY,
};
#[cfg(target_env = "sgx")]
use openapi_platform::unseal_tls_private_key;

/// 16-byte EGETKEY label for TLS key sealing (Fortanix sealing API).
pub const SGX_TLS_SEAL_LABEL: [u8; 16] = *b"teechat-tls-seal";
/// 16-byte EGETKEY label for prod seal-root mixing inside enclave.
pub const SGX_SEAL_ROOT_LABEL: [u8; 16] = *b"teechat-sgx-seal";

#[derive(Debug, Clone)]
pub struct SgxSealer {
    mrenclave: String,
}

impl SgxSealer {
    /// Build sealer from explicit MRENCLAVE (host dev / tests).
    pub fn new(mrenclave: impl Into<String>) -> Self {
        Self {
            mrenclave: mrenclave.into(),
        }
    }

    /// Read MRENCLAVE from `Report::for_self()` (SGX enclave) or env fallback (host).
    pub fn from_runtime() -> Result<Self, PlatformError> {
        Ok(Self::new(local_mrenclave_hex()?))
    }

    pub fn mrenclave(&self) -> &str {
        &self.mrenclave
    }

    /// Fail closed if blob MRENCLAVE does not match this enclave.
    pub fn verify_blob_measurement(&self, blob: &SealedTlsKeyBlob) -> Result<(), PlatformError> {
        let expected = self.sealing_measurement();
        if blob.measurement != expected {
            return Err(PlatformError::Seal(format!(
                "sealed blob mrenclave mismatch: blob={:?} runtime={expected:?}",
                blob.measurement
            )));
        }
        Ok(())
    }

    /// Prod seal root: EGETKEY-derived inside enclave; dev may use host HKDF root.
    pub fn resolve_seal_root(
        &self,
        host_supplied: Option<&[u8; 32]>,
        prod: bool,
    ) -> Result<Option<[u8; 32]>, PlatformError> {
        if prod {
            if host_supplied.is_some() {
                return Err(PlatformError::Seal(
                    "OPENAPI_SEAL_ROOT_HEX must not be host-supplied in prod".into(),
                ));
            }
            #[cfg(target_env = "sgx")]
            {
                return Ok(Some(derive_prod_seal_root()?));
            }
            #[cfg(not(target_env = "sgx"))]
            {
                // Host CI: deterministic stand-in for prod seal root when profile=prod in tests.
                let binding = format!("sgx-prod-seal-root|{}", self.mrenclave);
                return Ok(Some(derive_seal_key(&binding, None)));
            }
        }
        Ok(host_supplied.copied())
    }
}

impl Sealer for SgxSealer {
    fn sealing_measurement(&self) -> Measurement {
        Measurement::Mrenclave {
            value: self.mrenclave.clone(),
        }
    }

    fn seal_tls_key(
        &self,
        key_pem: &[u8],
        seal_root: Option<&[u8; 32]>,
    ) -> Result<SealedTlsKeyBlob, PlatformError> {
        #[cfg(target_env = "sgx")]
        {
            let _ = seal_root;
            return hw_seal_tls_private_key(&self.sealing_measurement(), key_pem);
        }
        #[cfg(not(target_env = "sgx"))]
        {
            seal_tls_private_key(&self.sealing_measurement(), key_pem, seal_root)
        }
    }

    fn unseal_tls_key(
        &self,
        blob: &SealedTlsKeyBlob,
        seal_root: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>, PlatformError> {
        self.verify_blob_measurement(blob)?;
        match blob.seal_version {
            SEAL_VERSION_SGX_EGETKEY => {
                #[cfg(target_env = "sgx")]
                {
                    let _ = seal_root;
                    return hw_unseal_tls_private_key(blob);
                }
                #[cfg(not(target_env = "sgx"))]
                {
                    Err(PlatformError::Seal(
                        "seal_version 2 requires SGX enclave (EGETKEY)".into(),
                    ))
                }
            }
            SEAL_VERSION => unseal_tls_private_key(blob, &self.sealing_measurement(), seal_root),
            other => Err(PlatformError::Seal(format!(
                "unsupported seal_version {other}"
            ))),
        }
    }
}

/// MRENCLAVE hex from enclave report, or `OPENAPI_MRENCLAVE` on host builds.
pub fn local_mrenclave_hex() -> Result<String, PlatformError> {
    #[cfg(target_env = "sgx")]
    {
        use sgx_isa::Report;
        return Ok(hex::encode(Report::for_self().mrenclave));
    }
    #[cfg(not(target_env = "sgx"))]
    {
        std::env::var("OPENAPI_MRENCLAVE").map_err(|_| {
            PlatformError::Attestation(
                "OPENAPI_MRENCLAVE required on host build (no Report::for_self)".into(),
            )
        })
    }
}

#[cfg(target_env = "sgx")]
mod hw {
    use super::*;
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use hkdf::Hkdf;
    use openapi_platform::{measurement_binding_label, SEAL_AAD};
    use rand::{random, RngCore};
    use sgx_isa::{
        Attributes, AttributesFlags, ErrorCode, Keyname, Keypolicy, Keyrequest, Miscselect, Report,
    };
    use sha2::Sha256;

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
    pub struct SealDataWire {
        pub rand_b64: String,
        pub isvsvn: u16,
        pub cpusvn_b64: String,
        pub attributes: [u64; 2],
        pub miscselect: u32,
    }

    pub struct SealData {
        pub rand: [u8; 16],
        pub isvsvn: u16,
        pub cpusvn: [u8; 16],
        pub attributes: Attributes,
        pub miscselect: Miscselect,
    }

    impl SealData {
        fn to_wire(&self) -> SealDataWire {
            SealDataWire {
                rand_b64: URL_SAFE_NO_PAD.encode(self.rand),
                isvsvn: self.isvsvn,
                cpusvn_b64: URL_SAFE_NO_PAD.encode(self.cpusvn),
                attributes: [self.attributes.flags.bits(), self.attributes.xfrm],
                miscselect: self.miscselect.bits(),
            }
        }

        fn from_wire(w: &SealDataWire) -> Result<Self, PlatformError> {
            let rand = decode_fixed::<16>(&w.rand_b64, "seal_data.rand")?;
            let cpusvn = decode_fixed::<16>(&w.cpusvn_b64, "seal_data.cpusvn")?;
            Ok(Self {
                rand,
                isvsvn: w.isvsvn,
                cpusvn,
                attributes: Attributes {
                    flags: AttributesFlags::from_bits_truncate(w.attributes[0]),
                    xfrm: w.attributes[1],
                },
                miscselect: Miscselect::from_bits_truncate(w.miscselect),
            })
        }
    }

    fn decode_fixed<const N: usize>(b64: &str, field: &str) -> Result<[u8; N], PlatformError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| PlatformError::Seal(format!("{field} decode: {e}")))?;
        bytes.as_slice().try_into().map_err(|_| {
            PlatformError::Seal(format!("{field} must be {N} bytes"))
        })
    }

    fn egetkey(label: [u8; 16], seal_data: &SealData) -> Result<[u8; 16], ErrorCode> {
        let mut keyid = [0u8; 32];
        keyid[..16].copy_from_slice(&label);
        keyid[16..].copy_from_slice(&seal_data.rand);

        Keyrequest {
            keyname: Keyname::Seal as _,
            keypolicy: Keypolicy::MRENCLAVE,
            isvsvn: seal_data.isvsvn,
            cpusvn: seal_data.cpusvn,
            attributemask: [!0; 2],
            keyid,
            miscmask: !0,
            ..Default::default()
        }
        .egetkey()
    }

    pub fn seal_key(label: [u8; 16]) -> Result<([u8; 16], SealData), PlatformError> {
        let report = Report::for_self();
        let seal_data = SealData {
            rand: random(),
            isvsvn: report.isvsvn,
            cpusvn: report.cpusvn,
            attributes: report.attributes,
            miscselect: report.miscselect,
        };
        let key = egetkey(label, &seal_data)
            .map_err(|e| PlatformError::Seal(format!("EGETKEY seal: {e:?}")))?;
        Ok((key, seal_data))
    }

    pub fn unseal_key(label: [u8; 16], seal_data: &SealData) -> Result<[u8; 16], PlatformError> {
        let report = Report::for_self();
        if report.attributes != seal_data.attributes || report.miscselect != seal_data.miscselect {
            return Err(PlatformError::Seal(
                "seal_data attributes mismatch with current enclave".into(),
            ));
        }
        egetkey(label, seal_data)
            .map_err(|e| PlatformError::Seal(format!("EGETKEY unseal: {e:?}")))
    }

    fn aad_for(binding: &str) -> Vec<u8> {
        let mut aad = SEAL_AAD.to_vec();
        aad.extend_from_slice(binding.as_bytes());
        aad
    }

    fn expand_egetkey_to_aes256(seal_key: &[u8; 16], binding: &str) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(seal_key.as_slice()), binding.as_bytes());
        let mut okm = [0u8; 32];
        hk.expand(b"teechat-openapi-sgx-aes-v1", &mut okm)
            .expect("hkdf expand");
        okm
    }

    pub fn seal_tls_private_key(
        measurement: &Measurement,
        key_pem: &[u8],
    ) -> Result<SealedTlsKeyBlob, PlatformError> {
        if key_pem.is_empty() {
            return Err(PlatformError::Seal("empty tls key".into()));
        }
        let (seal_key, seal_data) = seal_key(SGX_TLS_SEAL_LABEL)?;
        let binding = measurement_binding_label(measurement);
        let aes_key = expand_egetkey_to_aes256(&seal_key, &binding);

        let cipher = Aes256Gcm::new_from_slice(&aes_key)
            .map_err(|e| PlatformError::Seal(format!("cipher init: {e}")))?;
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: key_pem,
                    aad: &aad_for(&binding),
                },
            )
            .map_err(|e| PlatformError::Seal(format!("encrypt: {e}")))?;

        let wire = seal_data.to_wire();
        let seal_data_json = serde_json::to_vec(&wire)
            .map_err(|e| PlatformError::Seal(format!("encode seal_data: {e}")))?;

        Ok(SealedTlsKeyBlob {
            seal_version: SEAL_VERSION_SGX_EGETKEY,
            measurement: measurement.clone(),
            nonce_b64: URL_SAFE_NO_PAD.encode(nonce_bytes),
            ciphertext_b64: URL_SAFE_NO_PAD.encode(ciphertext),
            seal_data_b64: Some(URL_SAFE_NO_PAD.encode(seal_data_json)),
        })
    }

    pub fn unseal_tls_private_key(blob: &SealedTlsKeyBlob) -> Result<Vec<u8>, PlatformError> {
        let seal_data_b64 = blob.seal_data_b64.as_ref().ok_or_else(|| {
            PlatformError::Seal("missing seal_data_b64 for seal_version 2".into())
        })?;
        let seal_data_json = URL_SAFE_NO_PAD
            .decode(seal_data_b64)
            .map_err(|e| PlatformError::Seal(format!("seal_data decode: {e}")))?;
        let wire: hw::SealDataWire = serde_json::from_slice(&seal_data_json)
            .map_err(|e| PlatformError::Seal(format!("seal_data parse: {e}")))?;
        let seal_data = SealData::from_wire(&wire)?;

        let binding = measurement_binding_label(&blob.measurement);
        let seal_key = unseal_key(SGX_TLS_SEAL_LABEL, &seal_data)?;
        let aes_key = expand_egetkey_to_aes256(&seal_key, &binding);

        let cipher = Aes256Gcm::new_from_slice(&aes_key)
            .map_err(|e| PlatformError::Seal(format!("cipher init: {e}")))?;
        let nonce_bytes = URL_SAFE_NO_PAD
            .decode(&blob.nonce_b64)
            .map_err(|e| PlatformError::Seal(format!("nonce decode: {e}")))?;
        if nonce_bytes.len() != 12 {
            return Err(PlatformError::Seal("invalid nonce length".into()));
        }
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&blob.ciphertext_b64)
            .map_err(|e| PlatformError::Seal(format!("ciphertext decode: {e}")))?;

        let plaintext = cipher
            .decrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: &ciphertext,
                    aad: &aad_for(&binding),
                },
            )
            .map_err(|_| {
                PlatformError::Seal(
                    "decrypt failed (wrong enclave, tampered blob, or TCB downgrade)".into(),
                )
            })?;
        if plaintext.is_empty() {
            return Err(PlatformError::Seal("empty tls key after unseal".into()));
        }
        Ok(plaintext)
    }

    const SEAL_ROOT_LABEL_B: [u8; 16] = *b"teechat-sgx-root";

    fn deterministic_seal_key(label: [u8; 16]) -> Result<[u8; 16], PlatformError> {
        let report = Report::for_self();
        let seal_data = SealData {
            rand: [0u8; 16],
            isvsvn: report.isvsvn,
            cpusvn: report.cpusvn,
            attributes: report.attributes,
            miscselect: report.miscselect,
        };
        egetkey(label, &seal_data)
            .map_err(|e| PlatformError::Seal(format!("EGETKEY seal root: {e:?}")))
    }

    pub fn derive_prod_seal_root() -> Result<[u8; 32], PlatformError> {
        let k1 = deterministic_seal_key(SGX_SEAL_ROOT_LABEL)?;
        let k2 = deterministic_seal_key(SEAL_ROOT_LABEL_B)?;
        let mut root = [0u8; 32];
        root[..16].copy_from_slice(&k1);
        root[16..].copy_from_slice(&k2);
        Ok(root)
    }
}

#[cfg(target_env = "sgx")]
use hw::{
    derive_prod_seal_root, seal_tls_private_key as hw_seal_tls_private_key,
    unseal_tls_private_key as hw_unseal_tls_private_key,
};

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nsgx-test\n-----END PRIVATE KEY-----\n";

    #[test]
    fn sgx_sealer_roundtrip_hkdf_stub() {
        let sealer = SgxSealer::new("mrenclave-deadbeef");
        let blob = sealer.seal_tls_key(KEY, None).unwrap();
        assert_eq!(blob.seal_version, SEAL_VERSION);
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
    fn sgx_verify_blob_measurement_mismatch() {
        let sealer = SgxSealer::new("enclave-a");
        let other = SgxSealer::new("enclave-b");
        let blob = sealer.seal_tls_key(KEY, None).unwrap();
        assert!(sealer.verify_blob_measurement(&blob).is_ok());
        assert!(other.verify_blob_measurement(&blob).is_err());
    }

    #[test]
    fn sgx_sealer_with_dev_seal_root() {
        let sealer = SgxSealer::new("mr-root");
        let root = [0x55u8; 32];
        let blob = sealer.seal_tls_key(KEY, Some(&root)).unwrap();
        assert_eq!(sealer.unseal_tls_key(&blob, Some(&root)).unwrap(), KEY);
    }

    #[test]
    fn prod_resolve_seal_root_rejects_host() {
        let sealer = SgxSealer::new("mr-prod");
        let host = [1u8; 32];
        assert!(sealer.resolve_seal_root(Some(&host), true).is_err());
    }

    #[test]
    fn prod_resolve_seal_root_derives_on_host_stub() {
        let sealer = SgxSealer::new("mr-prod");
        let root = sealer.resolve_seal_root(None, true).unwrap();
        assert!(root.is_some());
        assert_eq!(root, sealer.resolve_seal_root(None, true).unwrap());
    }

    #[test]
    fn local_mrenclave_requires_env_on_host() {
        std::env::remove_var("OPENAPI_MRENCLAVE");
        assert!(local_mrenclave_hex().is_err());
        std::env::set_var("OPENAPI_MRENCLAVE", "abc");
        assert_eq!(local_mrenclave_hex().unwrap(), "abc");
        std::env::remove_var("OPENAPI_MRENCLAVE");
    }
}
