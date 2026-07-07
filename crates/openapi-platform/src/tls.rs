//! Server TLS policy for the openapi edge (rustls).
//!
//! **TLS 1.3 only** — no TLS 1.2 fallback. Matches gateway production posture and
//! reduces legacy cipher / downgrade exposure on the prompt path.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::version::TLS13;
use rustls::ServerConfig;

/// Build a rustls server config that negotiates **TLS 1.3 only**.
pub fn build_server_tls_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, rustls::Error> {
    let config = ServerConfig::builder_with_protocol_versions(&[&TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_server_tls_config_ok() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());

        let cfg = build_server_tls_config(vec![cert_der], key_der).unwrap();
        assert!(Arc::strong_count(&cfg) >= 1);
    }
}
