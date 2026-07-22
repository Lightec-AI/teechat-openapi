//! TLS private-key sealing helpers.
//!
//! - **`seal_version` 1** — measurement-labeled HKDF + AES-GCM (dev / CVM legacy).
//! - **`seal_version` 2** — Intel SGX `EGETKEY` (see `openapi-platform-sgx`).
//! - **`seal_version` 3** — AMD-SP via public crate `attested-mtls-snp-seal`.
//!
//! See repo `SECURITY.md`.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{Measurement, PlatformError};

/// Re-export AMD-SP seal types from the public TCB (`attested-mtls-snp-seal`).
pub use attested_mtls_snp_seal::{
    AmdSpSealMeta, AMD_SP_GFS_GUEST_POLICY_MEASUREMENT, SEAL_AAD_V3, SEAL_VERSION_SNP_AMD_SP,
};

pub const SEAL_AAD: &[u8] = b"teechat-openapi-tls-key-v1";
/// HKDF + AES-GCM bound to a measurement label (dev / CVM legacy).
pub const SEAL_VERSION: u32 = 1;
/// Fortanix EGETKEY + AES-GCM (SGX hardware sealing).
pub const SEAL_VERSION_SGX_EGETKEY: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedTlsKeyBlob {
    pub seal_version: u32,
    pub measurement: Measurement,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
    /// Fortanix `SealData` (URL-safe base64). Required for `seal_version` 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_data_b64: Option<String>,
    /// AMD-SP derive request parameters. Required for `seal_version` 3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amd_sp: Option<AmdSpSealMeta>,
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

/// Prod CVM seal root derived inside guest from attested launch + image digests.
pub fn derive_cvm_seal_root(attested_launch_digest: &str, image_digest: &str) -> [u8; 32] {
    let binding = format!("cvm-seal-root|launch:{attested_launch_digest}|image:{image_digest}");
    derive_seal_key(&binding, None)
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
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: key_pem,
                aad: &aad_for(&binding),
            },
        )
        .map_err(|e| PlatformError::Seal(format!("encrypt: {e}")))?;

    Ok(SealedTlsKeyBlob {
        seal_version: SEAL_VERSION,
        measurement: measurement.clone(),
        nonce_b64: URL_SAFE_NO_PAD.encode(nonce_bytes),
        ciphertext_b64: URL_SAFE_NO_PAD.encode(ciphertext),
        seal_data_b64: None,
        amd_sp: None,
    })
}

pub fn unseal_tls_private_key(
    blob: &SealedTlsKeyBlob,
    expected_measurement: &Measurement,
    seal_root: Option<&[u8; 32]>,
) -> Result<Vec<u8>, PlatformError> {
    if blob.seal_version != SEAL_VERSION {
        return Err(PlatformError::Seal(format!(
            "unsupported seal_version {} for HKDF unseal (expected {SEAL_VERSION})",
            blob.seal_version
        )));
    }
    if blob.seal_data_b64.is_some() {
        return Err(PlatformError::Seal(
            "seal_data_b64 present — use SGX hardware unseal (seal_version 2)".into(),
        ));
    }
    if blob.amd_sp.is_some() {
        return Err(PlatformError::Seal(
            "amd_sp present — use AMD-SP unseal (seal_version 3)".into(),
        ));
    }

    if blob.measurement != *expected_measurement {
        return Err(PlatformError::Seal(
            "sealed blob measurement mismatch".into(),
        ));
    }

    let binding = measurement_binding_label(expected_measurement);
    let seal_key = derive_seal_key(&binding, seal_root);
    aes_gcm_decrypt(
        &seal_key,
        &blob.nonce_b64,
        &blob.ciphertext_b64,
        &aad_for(&binding),
    )
}

fn to_snp_measurement(
    m: &Measurement,
) -> Result<attested_mtls_snp_seal::Measurement, PlatformError> {
    match m {
        Measurement::LaunchDigest {
            launch_digest,
            image_digest,
        } => Ok(attested_mtls_snp_seal::Measurement::launch_digest(
            launch_digest,
            image_digest,
        )),
        Measurement::Mrenclave { .. } => Err(PlatformError::Seal(
            "AMD-SP seal requires launch_digest measurement".into(),
        )),
    }
}

fn from_snp_blob(blob: attested_mtls_snp_seal::SealedTlsKeyBlob) -> SealedTlsKeyBlob {
    let measurement = match blob.measurement {
        attested_mtls_snp_seal::Measurement::LaunchDigest {
            launch_digest,
            image_digest,
        } => Measurement::LaunchDigest {
            launch_digest,
            image_digest,
        },
    };
    SealedTlsKeyBlob {
        seal_version: blob.seal_version,
        measurement,
        nonce_b64: blob.nonce_b64,
        ciphertext_b64: blob.ciphertext_b64,
        seal_data_b64: None,
        amd_sp: Some(blob.amd_sp),
    }
}

fn to_snp_blob(
    blob: &SealedTlsKeyBlob,
) -> Result<attested_mtls_snp_seal::SealedTlsKeyBlob, PlatformError> {
    let amd_sp = blob
        .amd_sp
        .clone()
        .ok_or_else(|| PlatformError::Seal("amd_sp metadata required for seal_version 3".into()))?;
    Ok(attested_mtls_snp_seal::SealedTlsKeyBlob {
        seal_version: blob.seal_version,
        measurement: to_snp_measurement(&blob.measurement)?,
        nonce_b64: blob.nonce_b64.clone(),
        ciphertext_b64: blob.ciphertext_b64.clone(),
        amd_sp,
    })
}

/// Seal with an AMD-SP derived key (`seal_version` 3) via `attested-mtls-snp-seal`.
pub fn seal_tls_private_key_amd_sp(
    measurement: &Measurement,
    key_pem: &[u8],
    amd_sp_derived_key: &[u8; 32],
    amd_sp: &AmdSpSealMeta,
) -> Result<SealedTlsKeyBlob, PlatformError> {
    let snp_m = to_snp_measurement(measurement)?;
    let blob =
        attested_mtls_snp_seal::seal_tls_private_key(&snp_m, key_pem, amd_sp_derived_key, amd_sp)
            .map_err(|e| PlatformError::Seal(e.to_string()))?;
    Ok(from_snp_blob(blob))
}

/// Unseal a `seal_version` 3 blob using a freshly derived AMD-SP key.
pub fn unseal_tls_private_key_amd_sp(
    blob: &SealedTlsKeyBlob,
    expected_measurement: &Measurement,
    amd_sp_derived_key: &[u8; 32],
) -> Result<Vec<u8>, PlatformError> {
    if blob.seal_data_b64.is_some() {
        return Err(PlatformError::Seal(
            "seal_data_b64 present — not an AMD-SP blob".into(),
        ));
    }
    let snp_blob = to_snp_blob(blob)?;
    let snp_m = to_snp_measurement(expected_measurement)?;
    attested_mtls_snp_seal::unseal_tls_private_key(&snp_blob, &snp_m, amd_sp_derived_key)
        .map_err(|e| PlatformError::Seal(e.to_string()))
}

fn aes_gcm_decrypt(
    seal_key: &[u8; 32],
    nonce_b64: &str,
    ciphertext_b64: &str,
    aad: &[u8],
) -> Result<Vec<u8>, PlatformError> {
    let cipher = Aes256Gcm::new_from_slice(seal_key)
        .map_err(|e| PlatformError::Seal(format!("cipher init: {e}")))?;

    let nonce_bytes = URL_SAFE_NO_PAD
        .decode(nonce_b64)
        .map_err(|e| PlatformError::Seal(format!("nonce decode: {e}")))?;
    if nonce_bytes.len() != 12 {
        return Err(PlatformError::Seal("invalid nonce length".into()));
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = URL_SAFE_NO_PAD
        .decode(ciphertext_b64)
        .map_err(|e| PlatformError::Seal(format!("ciphertext decode: {e}")))?;

    let plaintext = cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map_err(|_| {
            PlatformError::Seal(
                "decrypt failed (wrong measurement, AMD-SP key, or tampered blob)".into(),
            )
        })?;

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

    const KEY_PEM: &[u8] =
        b"-----BEGIN PRIVATE KEY-----\ntest-key-material\n-----END PRIVATE KEY-----\n";
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

    #[test]
    fn derive_cvm_seal_root_is_stable() {
        let a = derive_cvm_seal_root("launch-a", "image-b");
        let b = derive_cvm_seal_root("launch-a", "image-b");
        assert_eq!(a, b);
        assert_ne!(a, derive_cvm_seal_root("launch-x", "image-b"));
    }

    #[test]
    fn hkdf_unseal_rejects_sgx_blob_version() {
        let m = mrenclave_measurement();
        let mut blob = seal_tls_private_key(&m, KEY_PEM, None).unwrap();
        blob.seal_version = SEAL_VERSION_SGX_EGETKEY;
        blob.seal_data_b64 = Some("AAAA".into());
        assert!(unseal_tls_private_key(&blob, &m, None).is_err());
    }

    #[test]
    fn amd_sp_seal_unseal_roundtrip() {
        let m = launch_measurement();
        let amd_key = [0x7au8; 32];
        let meta = AmdSpSealMeta::teechat_default();
        let blob = seal_tls_private_key_amd_sp(&m, KEY_PEM, &amd_key, &meta).unwrap();
        assert_eq!(blob.seal_version, SEAL_VERSION_SNP_AMD_SP);
        assert_eq!(blob.amd_sp.as_ref(), Some(&meta));
        let plain = unseal_tls_private_key_amd_sp(&blob, &m, &amd_key).unwrap();
        assert_eq!(plain, KEY_PEM);
    }

    #[test]
    fn amd_sp_wrong_key_rejected() {
        let m = launch_measurement();
        let meta = AmdSpSealMeta::teechat_default();
        let blob = seal_tls_private_key_amd_sp(&m, KEY_PEM, &[0x7au8; 32], &meta).unwrap();
        assert!(unseal_tls_private_key_amd_sp(&blob, &m, &[0x7bu8; 32]).is_err());
    }

    #[test]
    fn amd_sp_wrong_measurement_rejected() {
        let m = launch_measurement();
        let meta = AmdSpSealMeta::teechat_default();
        let blob = seal_tls_private_key_amd_sp(&m, KEY_PEM, &[0x7au8; 32], &meta).unwrap();
        let other = Measurement::LaunchDigest {
            launch_digest: "other".into(),
            image_digest: "image-def".into(),
        };
        assert!(unseal_tls_private_key_amd_sp(&blob, &other, &[0x7au8; 32]).is_err());
    }

    #[test]
    fn v1_unseal_rejects_amd_sp_metadata() {
        let m = launch_measurement();
        let mut blob = seal_tls_private_key(&m, KEY_PEM, None).unwrap();
        blob.amd_sp = Some(AmdSpSealMeta::teechat_default());
        assert!(unseal_tls_private_key(&blob, &m, None).is_err());
    }

    #[test]
    fn teechat_default_gfs_is_policy_and_measurement() {
        let meta = AmdSpSealMeta::teechat_default();
        assert_eq!(meta.guest_field_select, AMD_SP_GFS_GUEST_POLICY_MEASUREMENT);
        assert_eq!(meta.root_key, "vcek");
        assert_eq!(meta.msg_version, 1);
    }

    /// Regression: OpenAPI wrapper must unseal blobs produced by the public crate.
    #[test]
    fn interoperable_with_attested_mtls_snp_seal() {
        let m = launch_measurement();
        let amd_key = [0x9cu8; 32];
        let meta = AmdSpSealMeta::teechat_default();
        let snp_m = attested_mtls_snp_seal::Measurement::launch_digest("launch-abc", "image-def");
        let snp_blob =
            attested_mtls_snp_seal::seal_tls_private_key(&snp_m, KEY_PEM, &amd_key, &meta).unwrap();
        let openapi_blob = from_snp_blob(snp_blob);
        let plain = unseal_tls_private_key_amd_sp(&openapi_blob, &m, &amd_key).unwrap();
        assert_eq!(plain, KEY_PEM);

        let openapi_sealed = seal_tls_private_key_amd_sp(&m, KEY_PEM, &amd_key, &meta).unwrap();
        let snp_again = to_snp_blob(&openapi_sealed).unwrap();
        let plain2 =
            attested_mtls_snp_seal::unseal_tls_private_key(&snp_again, &snp_m, &amd_key).unwrap();
        assert_eq!(plain2, KEY_PEM);
    }
}
