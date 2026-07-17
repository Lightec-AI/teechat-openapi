//! Extract SHA-256(SPKI) of the TLS leaf presented by the OpenAPI edge.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use sha2::{Digest, Sha256};

use crate::error::{AttestError, Result};

#[derive(Debug, Clone)]
pub struct PeerTlsIdentity {
    /// SHA-256 of DER SubjectPublicKeyInfo (contract field).
    pub spki_sha256_hex: String,
    /// SHA-256 of the full leaf certificate DER (legacy edge bug compatibility).
    pub cert_sha256_hex: String,
}

fn ensure_crypto_provider() {
    // Safe if already installed; needed when both aws-lc-rs and ring appear in the graph.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Connect with rustls and return leaf SPKI + cert digests.
pub fn fetch_peer_tls_identity(host: &str, port: u16) -> Result<PeerTlsIdentity> {
    ensure_crypto_provider();
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| AttestError::Tls(format!("server name: {e}")))?;
    let sock = TcpStream::connect((host, port))
        .map_err(|e| AttestError::Tls(format!("tcp {host}:{port}: {e}")))?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(20)))
        .ok();
    sock.set_write_timeout(Some(std::time::Duration::from_secs(20)))
        .ok();
    let conn = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| AttestError::Tls(e.to_string()))?;
    let mut tls = StreamOwned::new(conn, sock);
    let req = format!("GET /healthz HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    tls.write_all(req.as_bytes())
        .map_err(|e| AttestError::Tls(format!("write: {e}")))?;
    let mut _buf = [0u8; 256];
    let _ = tls.read(&mut _buf);

    let certs = tls
        .conn
        .peer_certificates()
        .ok_or_else(|| AttestError::Tls("no peer certificates".into()))?;
    let leaf = certs
        .first()
        .ok_or_else(|| AttestError::Tls("empty peer chain".into()))?;
    identity_from_cert_der(leaf.as_ref())
}

/// Connect with rustls, read the peer leaf certificate, return lowercase hex SHA-256(SPKI DER).
pub fn fetch_peer_spki_sha256(host: &str, port: u16) -> Result<String> {
    Ok(fetch_peer_tls_identity(host, port)?.spki_sha256_hex)
}

pub fn identity_from_cert_der(cert_der: &[u8]) -> Result<PeerTlsIdentity> {
    Ok(PeerTlsIdentity {
        spki_sha256_hex: spki_sha256_hex(cert_der)?,
        cert_sha256_hex: hex::encode(Sha256::digest(cert_der)),
    })
}

/// Parse X.509 DER leaf and hash SubjectPublicKeyInfo.
pub fn spki_sha256_hex(cert_der: &[u8]) -> Result<String> {
    let spki = extract_spki_der(cert_der)?;
    Ok(hex::encode(Sha256::digest(spki)))
}

fn extract_spki_der(cert_der: &[u8]) -> Result<&[u8]> {
    let (tag, cert_body, _) = read_tlv(cert_der)?;
    if tag != 0x30 {
        return Err(AttestError::Tls("cert not SEQUENCE".into()));
    }
    let (tag, tbs, _) = read_tlv(cert_body)?;
    if tag != 0x30 {
        return Err(AttestError::Tls("tbs not SEQUENCE".into()));
    }
    let mut rest = tbs;
    // optional [0] EXPLICIT Version
    if rest.first() == Some(&0xa0) {
        let (_, _, r) = read_tlv(rest)?;
        rest = r;
    }
    // serialNumber, signature, issuer, validity, subject — then subjectPublicKeyInfo
    for _ in 0..5 {
        let (_, _, r) = read_tlv(rest)?;
        rest = r;
    }
    let content_off = der_header_len(rest)?;
    let (_, body, _) = read_tlv(rest)?;
    Ok(&rest[..content_off + body.len()])
}

fn der_header_len(input: &[u8]) -> Result<usize> {
    if input.len() < 2 {
        return Err(AttestError::Tls("der short".into()));
    }
    let len_byte = input[1];
    if len_byte & 0x80 == 0 {
        Ok(2)
    } else {
        Ok(2 + (len_byte & 0x7f) as usize)
    }
}

fn read_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    if input.len() < 2 {
        return Err(AttestError::Tls("der truncated".into()));
    }
    let tag = input[0];
    let len_byte = input[1];
    let (hdr, len) = if len_byte & 0x80 == 0 {
        (2usize, len_byte as usize)
    } else {
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > 4 || input.len() < 2 + n {
            return Err(AttestError::Tls("der length".into()));
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | input[2 + i] as usize;
        }
        (2 + n, len)
    };
    if input.len() < hdr + len {
        return Err(AttestError::Tls("der out of range".into()));
    }
    Ok((tag, &input[hdr..hdr + len], &input[hdr + len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_spki_from_minimal_self_signed_shape() {
        // Not a full crypto cert — just enough ASN.1 nesting for the walker.
        // SEQUENCE {
        //   SEQUENCE { // tbs
        //     INTEGER 1, // serial
        //     SEQUENCE {}, // sig alg
        //     SEQUENCE {}, // issuer
        //     SEQUENCE {}, // validity
        //     SEQUENCE {}, // subject
        //     SEQUENCE { INTEGER 42 } // spki (fake)
        //   }
        //   SEQUENCE {}, // sig alg
        //   BIT STRING
        // }
        let spki = [0x30, 0x03, 0x02, 0x01, 0x2a];
        let mut tbs = Vec::new();
        tbs.extend_from_slice(&[0x02, 0x01, 0x01]); // serial
        for _ in 0..4 {
            tbs.extend_from_slice(&[0x30, 0x00]);
        }
        tbs.extend_from_slice(&spki);
        let mut cert_body = Vec::new();
        cert_body.push(0x30);
        cert_body.push(tbs.len() as u8);
        cert_body.extend_from_slice(&tbs);
        cert_body.extend_from_slice(&[0x30, 0x00]); // outer sig alg
        cert_body.extend_from_slice(&[0x03, 0x01, 0x00]); // bit string
        let mut cert = Vec::new();
        cert.push(0x30);
        cert.push(cert_body.len() as u8);
        cert.extend_from_slice(&cert_body);
        let extracted = extract_spki_der(&cert).unwrap();
        assert_eq!(extracted, &spki);
    }
}
