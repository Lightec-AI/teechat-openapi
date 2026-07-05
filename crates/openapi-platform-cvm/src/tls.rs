use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls: {0}")]
    Rustls(String),
}

impl TlsConfig {
    pub fn load_server_config(&self) -> Result<Arc<ServerConfig>, TlsError> {
        let cert_file = File::open(&self.cert_path)?;
        let key_file = File::open(&self.key_path)?;
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| TlsError::Rustls(e.to_string()))?;
        let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
            .map_err(|e| TlsError::Rustls(e.to_string()))?
            .ok_or_else(|| TlsError::Rustls("missing private key".into()))?;

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| TlsError::Rustls(e.to_string()))?;
        Ok(Arc::new(config))
    }

    pub fn cert_spki_sha256_hex(&self) -> Result<String, TlsError> {
        spki_sha256_hex_from_cert_path(Path::new(&self.cert_path))
    }
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
    // SubjectPublicKeyInfo is the DER cert's SPKI section; hash full cert DER for stable binding in MVP.
    let digest = Sha256::digest(cert.as_ref());
    Ok(hex::encode(digest))
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
