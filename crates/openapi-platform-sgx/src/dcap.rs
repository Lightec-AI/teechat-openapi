//! Talk to host `openapi-dcap-helper` for QE Targetinfo + DCAP ECDSA quotes.
//!
//! Fortanix EDP enclaves have TCP usercalls but no Unix sockets to aesmd.
//! The helper (host) owns AESM; the enclave only generates REPORTs targeting QE.

use std::io::{Read, Write};
use std::net::TcpStream;

use openapi_platform::PlatformError;

use crate::upstream::HttpEndpoint;

/// Default helper listen address (must match `openapi-dcap-helper`).
pub const DEFAULT_DCAP_HELPER_URL: &str = "http://127.0.0.1:18500";

#[derive(Debug, Clone)]
pub struct DcapHelperClient {
    endpoint: HttpEndpoint,
}

impl DcapHelperClient {
    pub fn from_url(url: &str) -> Result<Self, PlatformError> {
        let endpoint = crate::upstream::parse_http_base_url(url).map_err(|e| {
            PlatformError::Attestation(format!("OPENAPI_DCAP_HELPER_URL: {e}"))
        })?;
        Ok(Self { endpoint })
    }

    pub fn from_env() -> Result<Self, PlatformError> {
        let url = std::env::var("OPENAPI_DCAP_HELPER_URL")
            .unwrap_or_else(|_| DEFAULT_DCAP_HELPER_URL.to_string());
        Self::from_url(&url)
    }

    fn connect(&self) -> Result<TcpStream, PlatformError> {
        let addr = format!("{}:{}", self.endpoint.host, self.endpoint.port);
        TcpStream::connect(&addr).map_err(|e| {
            PlatformError::Attestation(format!(
                "dcap helper connect {addr}: {e} (is openapi-dcap-helper running?)"
            ))
        })
    }

    fn http_exchange(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<Vec<u8>, PlatformError> {
        let mut stream = self.connect()?;
        let request = if let Some(body) = body {
            format!(
                "{method} {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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
            .map_err(|e| PlatformError::Attestation(format!("dcap helper write: {e}")))?;
        if let Some(body) = body {
            stream
                .write_all(body)
                .map_err(|e| PlatformError::Attestation(format!("dcap helper write body: {e}")))?;
        }
        stream
            .flush()
            .map_err(|e| PlatformError::Attestation(format!("dcap helper flush: {e}")))?;

        let mut resp = Vec::new();
        stream
            .read_to_end(&mut resp)
            .map_err(|e| PlatformError::Attestation(format!("dcap helper read: {e}")))?;
        parse_http_body(&resp)
    }

    /// Fetch QE `Targetinfo` bytes from the host helper.
    pub fn qe_targetinfo(&self) -> Result<Vec<u8>, PlatformError> {
        self.http_exchange("GET", "/qe-targetinfo", None)
    }

    /// Convert an enclave REPORT (targeting QE) into a DCAP ECDSA quote.
    pub fn quote_report(&self, report: &[u8]) -> Result<Vec<u8>, PlatformError> {
        self.http_exchange("POST", "/quote", Some(report))
    }
}

fn parse_http_body(raw: &[u8]) -> Result<Vec<u8>, PlatformError> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| PlatformError::Attestation("dcap helper: bad HTTP response".into()))?;
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
            "dcap helper HTTP {status}: {msg}"
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
