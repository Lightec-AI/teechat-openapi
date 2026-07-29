//! Talk to host `openapi-ceremony-helper` for DNS, ACME HTTP-01, and artifacts.
//!
//! Fortanix EDP enclaves can TCP to IPs but cannot resolve DNS or write host
//! files. The helper owns webroot + artifact storage; the enclave never sends
//! a TLS private key PEM to the helper (only sealed JSON + public cert).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};

use openapi_platform::PlatformError;
use serde::Deserialize;

use crate::upstream::HttpEndpoint;

/// Default helper listen URL (must match `openapi-ceremony-helper`).
pub const DEFAULT_CEREMONY_HELPER_URL: &str = "http://127.0.0.1:18501";

#[derive(Debug, Clone)]
pub struct CeremonyHelperClient {
    endpoint: HttpEndpoint,
}

#[derive(Debug, Deserialize)]
struct DnsResponse {
    addrs: Vec<String>,
}

impl CeremonyHelperClient {
    pub fn from_url(url: &str) -> Result<Self, PlatformError> {
        let endpoint = crate::upstream::parse_http_base_url(url).map_err(|e| {
            PlatformError::Attestation(format!("OPENAPI_CEREMONY_HELPER_URL: {e}"))
        })?;
        Ok(Self { endpoint })
    }

    pub fn from_env() -> Result<Self, PlatformError> {
        let url = std::env::var("OPENAPI_CEREMONY_HELPER_URL")
            .unwrap_or_else(|_| DEFAULT_CEREMONY_HELPER_URL.to_string());
        Self::from_url(&url)
    }

    fn connect(&self) -> Result<TcpStream, PlatformError> {
        let addr = format!("{}:{}", self.endpoint.host, self.endpoint.port);
        TcpStream::connect(&addr).map_err(|e| {
            PlatformError::Attestation(format!(
                "ceremony helper connect {addr}: {e} (is openapi-ceremony-helper running?)"
            ))
        })
    }

    fn http_exchange(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        content_type: &str,
    ) -> Result<Vec<u8>, PlatformError> {
        let mut stream = self.connect()?;
        let request = if let Some(body) = body {
            format!(
                "{method} {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                self.endpoint.host,
                body.len()
            )
        } else {
            format!(
                "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                self.endpoint.host
            )
        };
        stream
            .write_all(request.as_bytes())
            .map_err(|e| PlatformError::Attestation(format!("ceremony helper write: {e}")))?;
        if let Some(body) = body {
            stream.write_all(body).map_err(|e| {
                PlatformError::Attestation(format!("ceremony helper write body: {e}"))
            })?;
        }
        stream
            .flush()
            .map_err(|e| PlatformError::Attestation(format!("ceremony helper flush: {e}")))?;

        let mut resp = Vec::new();
        stream
            .read_to_end(&mut resp)
            .map_err(|e| PlatformError::Attestation(format!("ceremony helper read: {e}")))?;
        parse_http_body(&resp)
    }

    /// Resolve `host` via helper `GET /dns` (returns first usable `SocketAddr`).
    pub fn resolve_dns(&self, host: &str, port: u16) -> Result<SocketAddr, PlatformError> {
        let path = format!("/dns?host={host}");
        let body = self.http_exchange("GET", &path, None, "application/octet-stream")?;
        let parsed: DnsResponse = serde_json::from_slice(&body).map_err(|e| {
            PlatformError::Attestation(format!("ceremony helper dns json: {e}"))
        })?;
        let first = parsed
            .addrs
            .first()
            .ok_or_else(|| PlatformError::Attestation("ceremony helper dns: empty addrs".into()))?;
        // Helper resolves :443; rewrite port if the ACME transport asked for another.
        let mut addr: SocketAddr = first.parse().map_err(|e| {
            PlatformError::Attestation(format!("ceremony helper dns addr {first}: {e}"))
        })?;
        addr.set_port(port);
        Ok(addr)
    }

    pub fn place_challenge(&self, token: &str, key_authorization: &str) -> Result<(), PlatformError> {
        let path = format!("/acme-challenge/{token}");
        let _ = self.http_exchange(
            "PUT",
            &path,
            Some(key_authorization.as_bytes()),
            "text/plain",
        )?;
        Ok(())
    }

    pub fn clear_challenge(&self, token: &str) -> Result<(), PlatformError> {
        let path = format!("/acme-challenge/{token}");
        let _ = self.http_exchange("DELETE", &path, None, "application/octet-stream")?;
        Ok(())
    }

    pub fn put_artifact(&self, name: &str, body: &[u8]) -> Result<(), PlatformError> {
        let path = format!("/artifacts/{name}");
        let _ = self.http_exchange("PUT", &path, Some(body), "application/octet-stream")?;
        Ok(())
    }

    pub fn get_artifact(&self, name: &str) -> Result<Vec<u8>, PlatformError> {
        let path = format!("/artifacts/{name}");
        self.http_exchange("GET", &path, None, "application/octet-stream")
    }

    pub fn delete_artifact(&self, name: &str) -> Result<(), PlatformError> {
        let path = format!("/artifacts/{name}");
        let _ = self.http_exchange("DELETE", &path, None, "application/octet-stream")?;
        Ok(())
    }
}

fn parse_http_body(raw: &[u8]) -> Result<Vec<u8>, PlatformError> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| PlatformError::Attestation("ceremony helper: bad HTTP response".into()))?;
    let header = std::str::from_utf8(&raw[..split]).unwrap_or("");
    let status = header
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let body = raw[split + 4..].to_vec();
    if !(200..300).contains(&status) {
        let msg = String::from_utf8_lossy(&body);
        return Err(PlatformError::Attestation(format!(
            "ceremony helper HTTP {status}: {msg}"
        )));
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ok_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
        assert_eq!(parse_http_body(raw).unwrap(), b"abc");
    }

    #[test]
    fn parses_error() {
        let raw = b"HTTP/1.1 500 ERR\r\n\r\nboom";
        let err = parse_http_body(raw).unwrap_err().to_string();
        assert!(err.contains("500"));
    }
}
