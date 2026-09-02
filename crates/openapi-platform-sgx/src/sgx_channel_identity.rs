//! Ephemeral seal-sync admin client credentials without rcgen/ring.
//!
//! `attested-mtls-seal-sync::generate_ephemeral_channel_identity` uses rcgen, which
//! signs via ring ECDSA and triggers `#UD` (`exception_vector: 6`) inside Fortanix EDP
//! even when ring SystemRandom is patched. Pure RustCrypto matches the ACME leaf path.

use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use attested_mtls_seal_sync::ChannelTlsIdentity;
use p256::ecdsa::{DerSignature, SigningKey};
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rand_core::OsRng;
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::EncodePem;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

/// Mint a fresh self-signed P-256 client credential for seal-sync v3 import.
pub fn generate_ephemeral_channel_identity() -> Result<ChannelTlsIdentity> {
    let signing_key = SigningKey::random(&mut OsRng);
    let subject =
        Name::from_str("CN=seal-sync-importer").context("seal-sync ephemeral cert subject")?;
    let issuer = subject.clone();
    let profile = Profile::Leaf {
        issuer,
        enable_key_agreement: false,
        enable_key_encipherment: false,
    };
    let serial_number = SerialNumber::from(rand::random::<u32>());
    let validity = Validity::from_now(Duration::from_secs(3600))
        .context("seal-sync ephemeral cert validity")?;
    let pub_key_der = signing_key
        .verifying_key()
        .to_public_key_der()
        .context("seal-sync ephemeral public key der")?;
    let pub_key = SubjectPublicKeyInfoOwned::try_from(pub_key_der.as_bytes())
        .context("seal-sync ephemeral public key spki")?;
    let builder = CertificateBuilder::new(
        profile,
        serial_number,
        validity,
        subject,
        pub_key,
        &signing_key,
    )
    .context("seal-sync ephemeral cert builder")?;
    let cert = builder
        .build::<DerSignature>()
        .context("seal-sync ephemeral cert sign")?;
    let cert_pem = cert
        .to_pem(LineEnding::LF)
        .context("seal-sync ephemeral cert pem")?;
    let key_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("seal-sync ephemeral key pem")?
        .to_string();
    let spki_sha256 = attested_mtls::spki_sha256_hex(&cert_pem)
        .map_err(|e| anyhow::anyhow!("seal-sync ephemeral spki: {e}"))?;
    Ok(ChannelTlsIdentity {
        cert_pem,
        key_pem,
        spki_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_identity_has_stable_spki() {
        let identity = generate_ephemeral_channel_identity().unwrap();
        assert_eq!(identity.spki_sha256.len(), 64);
        assert_eq!(
            identity.spki_sha256,
            attested_mtls::spki_sha256_hex(&identity.cert_pem).unwrap()
        );
        assert_ne!(
            generate_ephemeral_channel_identity().unwrap().spki_sha256,
            identity.spki_sha256
        );
    }
}
