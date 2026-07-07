use std::fs::File;
use std::io::{BufReader, Cursor};
use std::path::Path;
use std::sync::Arc;

use openapi_platform::{PlatformError, Sealer, SealedTlsKeyBlob};
use openapi_platform::tls::build_server_tls_config;
use rustls::pki_types::CertificateDer;
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::seal::SgxSealer;

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

    pub fn install_crypto_provider() -> Result<(), TlsError> {
        #[cfg(not(target_env = "sgx"))]
        {
            rustls::crypto::aws_lc_rs::default_provider()
                .install_default()
                .map_err(|_| TlsError::Rustls("install aws-lc provider".into()))?;
        }
        #[cfg(target_env = "sgx")]
        {
            rustls::crypto::ring::default_provider()
                .install_default()
                .map_err(|_| TlsError::Rustls("install ring provider".into()))?;
        }
        Ok(())
    }

    pub fn load_server_config_from_key_pem(
        &self,
        key_pem: &[u8],
    ) -> Result<Arc<ServerConfig>, TlsError> {
        load_server_config_from_pem_paths(&self.cert_path, key_pem)
    }

    pub fn load_server_config_from_sealed(
        &self,
        sealer: &SgxSealer,
        sealed_path: &Path,
        seal_root: Option<&[u8; 32]>,
    ) -> Result<Arc<ServerConfig>, TlsError> {
        let key_pem = sealer.unseal_tls_key_from_file(sealed_path, seal_root)?;
        self.load_server_config_from_key_pem(&key_pem)
    }

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

    build_server_tls_config(certs, key).map_err(|e| TlsError::Rustls(e.to_string()))
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
    Ok(hex::encode(Sha256::digest(cert.as_ref())))
}

pub fn seal_tls_key_file(
    sealer: &SgxSealer,
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

#[cfg(all(test, not(target_env = "sgx")))]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair, SanType};

    fn write_test_cert_and_key(dir: &Path) -> (String, Vec<u8>) {
        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        params
            .subject_alt_names
            .push(SanType::DnsName("localhost".try_into().unwrap()));
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_path = dir.join("cert.pem");
        std::fs::write(&cert_path, cert.pem()).unwrap();
        (cert_path.to_string_lossy().into_owned(), key_pair.serialize_pem().into_bytes())
    }

    #[test]
    fn sealed_tls_roundtrip() {
        TlsConfig::install_crypto_provider().unwrap();
        let dir = std::env::temp_dir().join(format!("sgx-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_path, key_pem) = write_test_cert_and_key(&dir);
        let sealed_path = dir.join("key.sealed.json");
        let sealer = SgxSealer::new("mr-test");
        sealer.seal_tls_key_to_file(&key_pem, &sealed_path, None).unwrap();
        let _ = TlsConfig::new(&cert_path)
            .load_server_config_from_sealed(&sealer, &sealed_path, None)
            .unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }
}
