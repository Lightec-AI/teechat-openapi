use std::fs::File;
use std::io::{BufReader, Cursor};
use std::path::Path;
use std::sync::Arc;

use openapi_platform::{PlatformError, Sealer, SealedTlsKeyBlob};
use rustls::pki_types::CertificateDer;
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_path: String,
}

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls: {0}")]
    Rustls(String),
    #[error("seal: {0}")]
    Seal(#[from] PlatformError),
}

impl TlsConfig {
    pub fn new(cert_path: impl Into<String>) -> Self {
        Self {
            cert_path: cert_path.into(),
        }
    }

    /// Load TLS server config from certificate PEM on disk and private key PEM bytes.
    pub fn load_server_config_from_key_pem(
        &self,
        key_pem: &[u8],
    ) -> Result<Arc<ServerConfig>, TlsError> {
        load_server_config_from_pem_paths(&self.cert_path, key_pem)
    }

    /// Unseal a measurement-bound TLS key blob and build rustls server config.
    pub fn load_server_config_from_sealed(
        &self,
        sealer: &impl Sealer,
        sealed_path: &Path,
        seal_root: Option<&[u8; 32]>,
    ) -> Result<Arc<ServerConfig>, TlsError> {
        let key_pem = sealer.unseal_tls_key_from_file(sealed_path, seal_root)?;
        self.load_server_config_from_key_pem(&key_pem)
    }

    /// Dev-only: load plaintext private key from filesystem path.
    pub fn load_server_config_from_plain_key_path(
        cert_path: &str,
        key_path: &str,
    ) -> Result<Arc<ServerConfig>, TlsError> {
        let key_pem = std::fs::read(key_path)?;
        load_server_config_from_pem_paths(cert_path, &key_pem)
    }

    pub fn cert_spki_sha256_hex(&self) -> Result<String, TlsError> {
        spki_sha256_hex_from_cert_path(Path::new(&self.cert_path))
    }
}

pub fn load_server_config_from_pem_paths(
    cert_path: &str,
    key_pem: &[u8],
) -> Result<Arc<ServerConfig>, TlsError> {
    let cert_file = File::open(cert_path)?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::Rustls(e.to_string()))?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(Cursor::new(key_pem)))
        .map_err(|e| TlsError::Rustls(e.to_string()))?
        .ok_or_else(|| TlsError::Rustls("missing private key".into()))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| TlsError::Rustls(e.to_string()))?;
    Ok(Arc::new(config))
}

pub fn spki_sha256_hex_from_cert_path(path: &Path) -> Result<String, TlsError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::Rustls(e.to_string()))?;
    let cert = certs
        .first()
        .ok_or_else(|| TlsError::Rustls("no certificate found".into()))?;
    let digest = Sha256::digest(cert.as_ref());
    Ok(hex::encode(digest))
}

pub fn seal_tls_key_file(
    sealer: &impl Sealer,
    plain_key_path: &Path,
    sealed_out_path: &Path,
    seal_root: Option<&[u8; 32]>,
) -> Result<SealedTlsKeyBlob, TlsError> {
    let key_pem = std::fs::read(plain_key_path)?;
    let blob = sealer.seal_tls_key(&key_pem, seal_root)?;
    let json = serde_json::to_vec_pretty(&blob).map_err(|e| TlsError::Rustls(e.to_string()))?;
    std::fs::write(sealed_out_path, json)?;
    Ok(blob)
}

pub struct TlsAcceptor {
    config: Arc<ServerConfig>,
}

impl TlsAcceptor {
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self { config }
    }

    pub fn accept(
        &self,
        stream: std::net::TcpStream,
    ) -> Result<StreamOwned<ServerConnection, std::net::TcpStream>, TlsError> {
        let conn = ServerConnection::new(Arc::clone(&self.config))
            .map_err(|e| TlsError::Rustls(e.to_string()))?;
        Ok(StreamOwned::new(conn, stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::CvmSealer;
    use rcgen::{CertificateParams, KeyPair, SanType};
    use std::net::{TcpListener, TcpStream};

    fn setup_crypto() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    fn write_test_cert_and_key(dir: &Path) -> (String, String, Vec<u8>) {
        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .subject_alt_names
            .push(SanType::DnsName("localhost".try_into().unwrap()));
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem().into_bytes();

        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();
        (
            cert_path.to_string_lossy().into_owned(),
            key_path.to_string_lossy().into_owned(),
            key_pem,
        )
    }

    #[test]
    fn load_server_config_from_key_pem_bytes() {
        setup_crypto();
        let dir = std::env::temp_dir().join(format!("tls-key-bytes-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_path, _key_path, key_pem) = write_test_cert_and_key(&dir);

        let cfg = TlsConfig::new(&cert_path)
            .load_server_config_from_key_pem(&key_pem)
            .unwrap();
        assert!(Arc::strong_count(&cfg) >= 1);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn load_server_config_from_sealed_blob() {
        setup_crypto();
        let dir = std::env::temp_dir().join(format!("tls-sealed-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_path, key_path, key_pem) = write_test_cert_and_key(&dir);
        let sealed_path = dir.join("key.sealed.json");

        let sealer = CvmSealer::new("test-launch", "test-image");
        sealer
            .seal_tls_key_to_file(&key_pem, &sealed_path, None)
            .unwrap();

        let _sealed_cfg = TlsConfig::new(&cert_path)
            .load_server_config_from_sealed(&sealer, &sealed_path, None)
            .unwrap();

        // Plain key file can be removed — sealed path is sufficient
        std::fs::remove_file(key_path).unwrap();
        let _ = TlsConfig::new(&cert_path)
            .load_server_config_from_sealed(&sealer, &sealed_path, None)
            .unwrap();

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn sealed_key_wrong_measurement_fails_at_load() {
        setup_crypto();
        let dir = std::env::temp_dir().join(format!("tls-sealed-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_path, _key_path, key_pem) = write_test_cert_and_key(&dir);
        let sealed_path = dir.join("key.sealed.json");

        CvmSealer::new("ld-good", "id-good")
            .seal_tls_key_to_file(&key_pem, &sealed_path, None)
            .unwrap();

        let wrong_sealer = CvmSealer::new("ld-bad", "id-good");
        assert!(TlsConfig::new(&cert_path)
            .load_server_config_from_sealed(&wrong_sealer, &sealed_path, None)
            .is_err());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn tls_acceptor_accepts_connection() {
        setup_crypto();
        let dir = std::env::temp_dir().join(format!("tls-accept-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_path, _key_path, key_pem) = write_test_cert_and_key(&dir);
        let sealed_path = dir.join("key.sealed.json");
        let sealer = CvmSealer::new("ld-acc", "id-acc");
        sealer
            .seal_tls_key_to_file(&key_pem, &sealed_path, None)
            .unwrap();

        let config = TlsConfig::new(&cert_path)
            .load_server_config_from_sealed(&sealer, &sealed_path, None)
            .unwrap();
        let acceptor = TlsAcceptor::new(config);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let _ = acceptor.accept(stream);
            }
        });

        let _stream = TcpStream::connect(addr);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn seal_tls_key_file_helper() {
        let dir = std::env::temp_dir().join(format!("tls-seal-helper-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (_cert_path, key_path, key_pem) = write_test_cert_and_key(&dir);
        let sealed_path = dir.join("out.sealed.json");
        let sealer = CvmSealer::new("ld-h", "id-h");

        let blob = seal_tls_key_file(
            &sealer,
            Path::new(&key_path),
            &sealed_path,
            None,
        )
        .unwrap();
        assert_eq!(blob.measurement, sealer.sealing_measurement());
        let unsealed = sealer.unseal_tls_key_from_file(&sealed_path, None).unwrap();
        assert_eq!(unsealed, key_pem);

        let _ = std::fs::remove_dir_all(dir);
    }
}
