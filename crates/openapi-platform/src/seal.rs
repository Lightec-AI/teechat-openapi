use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{Measurement, PlatformError};

pub const SEAL_AAD: &[u8] = b"teechat-openapi-tls-key-v1";
pub const SEAL_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedTlsKeyBlob {
    pub seal_version: u32,
    pub measurement: Measurement,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

pub fn measurement_binding_label(measurement: &Measurement) -> String {
    match measurement {
        Measurement::Mrenclave { value } => format!("mrenclave:{value}"),
        Measurement::LaunchDigest {
            launch_digest,
            image_digest,
        } => format!("launch_digest:{launch_digest}|image_digest:{image_digest}"),
    }
}

pub fn derive_seal_key(binding: &str, seal_root: Option<&[u8; 32]>) -> [u8; 32] {
    let ikm = match seal_root {
        Some(root) => {
            let mut v = Vec::with_capacity(root.len() + binding.len());
            v.extend_from_slice(root);
            v.extend_from_slice(binding.as_bytes());
            v
        }
        None => binding.as_bytes().to_vec(),
    };
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"teechat-openapi-edge-seal-v1", &mut okm)
        .expect("hkdf expand");
    okm
}

fn aad_for(binding: &str) -> Vec<u8> {
    let mut aad = SEAL_AAD.to_vec();
    aad.extend_from_slice(binding.as_bytes());
    aad
}

pub fn seal_tls_private_key(
    measurement: &Measurement,
    key_pem: &[u8],
    seal_root: Option<&[u8; 32]>,
) -> Result<SealedTlsKeyBlob, PlatformError> {
    if key_pem.is_empty() {
        return Err(PlatformError::Seal("empty tls key".into()));
    }

    let binding = measurement_binding_label(measurement);
    let seal_key = derive_seal_key(&binding, seal_root);
    let cipher = Aes256Gcm::new_from_slice(&seal_key)
        .map_err(|e| PlatformError::Seal(format!("cipher init: {e}")))?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, aes_gcm::aead::Payload {
            msg: key_pem,
            aad: &aad_for(&binding),
        })
        .map_err(|e| PlatformError::Seal(format!("encrypt: {e}")))?;

    Ok(SealedTlsKeyBlob {
        seal_version: SEAL_VERSION,
        measurement: measurement.clone(),
        nonce_b64: URL_SAFE_NO_PAD.encode(nonce_bytes),
        ciphertext_b64: URL_SAFE_NO_PAD.encode(ciphertext),
    })
}

pub fn unseal_tls_private_key(
    blob: &SealedTlsKeyBlob,
    expected_measurement: &Measurement,
    seal_root: Option<&[u8; 32]>,
) -> Result<Vec<u8>, PlatformError> {
    if blob.seal_version != SEAL_VERSION {
        return Err(PlatformError::Seal(format!(
            "unsupported seal_version {}",
            blob.seal_version
        )));
    }

    if blob.measurement != *expected_measurement {
        return Err(PlatformError::Seal(
            "sealed blob measurement mismatch".into(),
        ));
    }

    let binding = measurement_binding_label(expected_measurement);
    let seal_key = derive_seal_key(&binding, seal_root);
    let cipher = Aes256Gcm::new_from_slice(&seal_key)
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
        .map_err(|_| PlatformError::Seal("decrypt failed (wrong measurement or tampered blob)".into()))?;

    if plaintext.is_empty() {
        return Err(PlatformError::Seal("empty tls key after unseal".into()));
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch_measurement() -> Measurement {
        Measurement::LaunchDigest {
            launch_digest: "launch-abc".into(),
            image_digest: "image-def".into(),
        }
    }

    fn mrenclave_measurement() -> Measurement {
        Measurement::Mrenclave {
            value: "cafebabe".into(),
        }
    }

    const KEY_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\ntest-key-material\n-----END PRIVATE KEY-----\n";
    const SEAL_ROOT: [u8; 32] = [0x42u8; 32];

    #[test]
    fn measurement_binding_labels_are_stable() {
        assert_eq!(
            measurement_binding_label(&launch_measurement()),
            "launch_digest:launch-abc|image_digest:image-def"
        );
        assert_eq!(
            measurement_binding_label(&mrenclave_measurement()),
            "mrenclave:cafebabe"
        );
    }

    #[test]
    fn seal_unseal_roundtrip_without_seal_root() {
        let m = launch_measurement();
        let blob = seal_tls_private_key(&m, KEY_PEM, None).unwrap();
        let plain = unseal_tls_private_key(&blob, &m, None).unwrap();
        assert_eq!(plain, KEY_PEM);
    }

    #[test]
    fn seal_unseal_roundtrip_with_seal_root() {
        let m = mrenclave_measurement();
        let blob = seal_tls_private_key(&m, KEY_PEM, Some(&SEAL_ROOT)).unwrap();
        let plain = unseal_tls_private_key(&blob, &m, Some(&SEAL_ROOT)).unwrap();
        assert_eq!(plain, KEY_PEM);
    }

    #[test]
    fn wrong_measurement_rejected() {
        let m = launch_measurement();
        let blob = seal_tls_private_key(&m, KEY_PEM, None).unwrap();
        let other = Measurement::LaunchDigest {
            launch_digest: "other".into(),
            image_digest: "image-def".into(),
        };
        assert!(unseal_tls_private_key(&blob, &other, None).is_err());
    }

    #[test]
    fn wrong_seal_root_rejected() {
        let m = launch_measurement();
        let blob = seal_tls_private_key(&m, KEY_PEM, Some(&SEAL_ROOT)).unwrap();
        let wrong_root = [0x01u8; 32];
        assert!(unseal_tls_private_key(&blob, &m, Some(&wrong_root)).is_err());
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let m = launch_measurement();
        let mut blob = seal_tls_private_key(&m, KEY_PEM, None).unwrap();
        let mut bytes = URL_SAFE_NO_PAD.decode(&blob.ciphertext_b64).unwrap();
        bytes[0] ^= 0x01;
        blob.ciphertext_b64 = URL_SAFE_NO_PAD.encode(bytes);
        assert!(unseal_tls_private_key(&blob, &m, None).is_err());
    }

    #[test]
    fn tampered_nonce_rejected() {
        let m = launch_measurement();
        let mut blob = seal_tls_private_key(&m, KEY_PEM, None).unwrap();
        blob.nonce_b64 = URL_SAFE_NO_PAD.encode([0u8; 12]);
        assert!(unseal_tls_private_key(&blob, &m, None).is_err());
    }

    #[test]
    fn unsupported_seal_version_rejected() {
        let m = launch_measurement();
        let mut blob = seal_tls_private_key(&m, KEY_PEM, None).unwrap();
        blob.seal_version = 99;
        assert!(unseal_tls_private_key(&blob, &m, None).is_err());
    }

    #[test]
    fn blob_json_roundtrip() {
        let m = launch_measurement();
        let blob = seal_tls_private_key(&m, KEY_PEM, Some(&SEAL_ROOT)).unwrap();
        let json = serde_json::to_string(&blob).unwrap();
        let parsed: SealedTlsKeyBlob = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, blob);
        let plain = unseal_tls_private_key(&parsed, &m, Some(&SEAL_ROOT)).unwrap();
        assert_eq!(plain, KEY_PEM);
    }

    #[test]
    fn empty_key_rejected_on_seal() {
        let m = launch_measurement();
        assert!(seal_tls_private_key(&m, b"", None).is_err());
    }

    #[test]
    fn derive_seal_key_differs_with_and_without_root() {
        let binding = measurement_binding_label(&launch_measurement());
        let a = derive_seal_key(&binding, None);
        let b = derive_seal_key(&binding, Some(&SEAL_ROOT));
        assert_ne!(a, b);
    }
}
