//! HTTPS transport over `TcpStream` + rustls with pluggable DNS resolution.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};

use httparse::EMPTY_HEADER;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use crate::types::Error;

static CRYPTO_INIT: OnceLock<()> = OnceLock::new();

/// Install the platform TLS crypto provider once (aws-lc-rs on host).
///
/// On SGX, ACME HTTPS uses `ClientConfig::builder_with_provider(rustls_rustcrypto)`
/// so ring ECDSA/KX is never selected (Fortanix EDP hits #UD on ring ECC).
pub(crate) fn ensure_crypto_provider() {
    CRYPTO_INIT.get_or_init(|| {
        #[cfg(not(target_env = "sgx"))]
        {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        }
        #[cfg(target_env = "sgx")]
        {
            // Prefer per-builder provider; install as fallback for any builder() paths.
            let _ = rustls_rustcrypto::provider().install_default();
        }
    });
}

/// Resolve an ACME server hostname to a TCP endpoint (pluggable for EDP without DNS).
pub trait DnsResolver: Send + Sync {
    /// Resolve `host:port` to a socket address.
    fn resolve(&self, host: &str, port: u16) -> Result<SocketAddr, Error>;
}

/// Standard resolver using `ToSocketAddrs` (host tests and CVM-like environments).
#[derive(Debug, Clone, Copy, Default)]
pub struct StdDnsResolver;

impl DnsResolver for StdDnsResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<SocketAddr, Error> {
        (host, port)
            .to_socket_addrs()
            .map_err(Error::HttpIo)?
            .next()
            .ok_or(Error::Str("no addresses resolved"))
    }
}

/// Resolver backed by a closure (tests, Fortanix EDP with pre-resolved IPs).
pub struct FnDnsResolver {
    f: Arc<dyn Fn(&str, u16) -> Result<SocketAddr, Error> + Send + Sync>,
}

impl FnDnsResolver {
    /// Wrap `f` as a [`DnsResolver`].
    pub fn new<F>(f: F) -> Self
    where
        F: Fn(&str, u16) -> Result<SocketAddr, Error> + Send + Sync + 'static,
    {
        Self { f: Arc::new(f) }
    }
}

impl DnsResolver for FnDnsResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<SocketAddr, Error> {
        (self.f)(host, port)
    }
}

/// Minimal HTTP/1.1 response from the ACME transport.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    headers: HashMap<String, String>,
    /// Response body (empty for HEAD).
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Case-insensitive header lookup.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    /// Deserialize a JSON response body.
    pub fn into_json<T: serde::de::DeserializeOwned>(self) -> Result<T, Error> {
        serde_json::from_slice(&self.body).map_err(Error::from)
    }
}

/// Blocking HTTPS client for ACME directory and JOSE POSTs.
pub struct HttpsTransport {
    resolver: Arc<dyn DnsResolver>,
    config: Arc<ClientConfig>,
}

impl HttpsTransport {
    /// Build a transport that trusts the public Web PKI roots (`webpki-roots`).
    pub fn new(resolver: Arc<dyn DnsResolver>) -> Self {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_roots(resolver, roots)
    }

    /// Build a transport with a custom root store (unit tests with ephemeral CA).
    pub fn with_roots(resolver: Arc<dyn DnsResolver>, roots: RootCertStore) -> Self {
        ensure_crypto_provider();
        let config = build_client_config(roots);
        Self {
            resolver,
            config: Arc::new(config),
        }
    }

    /// GET `url` (https only).
    pub fn get(&self, url: &str) -> Result<HttpResponse, Error> {
        self.request("GET", url, None, None)
    }

    /// HEAD `url` (https only).
    pub fn head(&self, url: &str) -> Result<HttpResponse, Error> {
        self.request("HEAD", url, None, None)
    }

    /// POST JSON to `url` with the given `Content-Type`.
    pub fn post_json(
        &self,
        url: &str,
        content_type: &str,
        body: &impl serde::Serialize,
    ) -> Result<HttpResponse, Error> {
        let bytes = serde_json::to_vec(body).map_err(Error::from)?;
        self.request("POST", url, Some(content_type), Some(&bytes))
    }

    fn request(
        &self,
        method: &str,
        url: &str,
        content_type: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, Error> {
        let (host, port, path) = parse_https_url(url)?;
        let addr = self.resolver.resolve(&host, port)?;

        let stream = TcpStream::connect(addr).map_err(Error::HttpIo)?;
        let server_name = ServerName::try_from(host.clone())
            .map_err(|_| Error::Str("invalid server name"))?;
        let conn = ClientConnection::new(Arc::clone(&self.config), server_name)
            .map_err(|e| Error::Http(e.to_string()))?;
        let mut tls = StreamOwned::new(conn, stream);

        tls.write_all(&build_request_bytes(
            method,
            &host,
            &path,
            content_type,
            body,
        ))
        .map_err(Error::HttpIo)?;
        tls.flush().map_err(Error::HttpIo)?;

        read_http_response(&mut tls, method == "HEAD")
    }
}

fn build_client_config(roots: RootCertStore) -> ClientConfig {
    #[cfg(not(target_env = "sgx"))]
    {
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    }
    #[cfg(target_env = "sgx")]
    {
        ClientConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
            .with_safe_default_protocol_versions()
            .expect("rustls-rustcrypto protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth()
    }
}

fn parse_https_url(url: &str) -> Result<(String, u16, String), Error> {
    let rest = url
        .strip_prefix("https://")
        .ok_or(Error::Str("URL must use HTTPS"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.chars().all(|c| c.is_ascii_digit()) => (
            h.to_owned(),
            p.parse::<u16>()
                .map_err(|_| Error::Str("invalid port in URL"))?,
        ),
        _ => (authority.to_owned(), 443),
    };
    Ok((host, port, path.to_owned()))
}

fn build_request_bytes(
    method: &str,
    host: &str,
    path: &str,
    content_type: Option<&str>,
    body: Option<&[u8]>,
) -> Vec<u8> {
    let header = match (content_type, body) {
        (Some(ct), Some(body)) => format!(
            "{method} {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: {ct}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n",
            body.len()
        ),
        _ => format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        ),
    };
    let mut out = header.into_bytes();
    if let Some(body) = body {
        out.extend_from_slice(body);
    }
    out
}

fn read_http_response<R: Read>(reader: &mut R, head_only: bool) -> Result<HttpResponse, Error> {
    let mut raw = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte).map_err(Error::HttpIo)?;
        if n == 0 {
            if raw.is_empty() {
                return Err(Error::Str("empty HTTP response"));
            }
            break;
        }
        raw.push(byte[0]);
        if raw.len() >= 4 && raw[raw.len() - 4..] == *b"\r\n\r\n" {
            break;
        }
        if raw.len() > 65536 {
            return Err(Error::Str("HTTP header block too large"));
        }
    }

    let mut headers = [EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    resp.parse(&raw)
        .map_err(|e| Error::Http(format!("parse response headers: {e}")))?;
    let status = resp
        .code
        .ok_or(Error::Str("missing HTTP status"))?;

    let mut header_map = HashMap::new();
    for h in resp.headers.iter() {
        let name = h.name.to_ascii_lowercase();
        let value = std::str::from_utf8(h.value)
            .map_err(|_| Error::Str("invalid header encoding"))?
            .to_owned();
        header_map.insert(name, value);
    }

    let mut body = Vec::new();
    if !head_only {
        if let Some(cl) = header_map.get("content-length") {
            let len: usize = cl
                .parse()
                .map_err(|_| Error::Str("invalid Content-Length"))?;
            body.resize(len, 0);
            if len > 0 {
                reader.read_exact(&mut body).map_err(Error::HttpIo)?;
            }
        } else if header_map.get("transfer-encoding") == Some(&"chunked".to_owned()) {
            read_chunked_body(reader, &mut body)?;
        } else {
            reader.read_to_end(&mut body).map_err(Error::HttpIo)?;
        }
    }

    Ok(HttpResponse {
        status,
        headers: header_map,
        body,
    })
}

fn read_chunked_body<R: Read>(reader: &mut R, out: &mut Vec<u8>) -> Result<(), Error> {
    loop {
        let size_line = read_line(reader)?;
        let size_str = size_line.split(';').next().unwrap_or("").trim();
        if size_str.is_empty() {
            continue;
        }
        let size =
            usize::from_str_radix(size_str, 16).map_err(|_| Error::Str("invalid chunk size"))?;
        if size == 0 {
            let _ = read_line(reader)?;
            break;
        }
        let start = out.len();
        out.resize(start + size, 0);
        reader
            .read_exact(&mut out[start..])
            .map_err(Error::HttpIo)?;
        let _ = read_line(reader)?;
    }
    Ok(())
}

fn read_line<R: Read>(reader: &mut R) -> Result<String, Error> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte).map_err(Error::HttpIo)?;
        if n == 0 {
            break;
        }
        line.push(byte[0]);
        if line.len() >= 2 && line[line.len() - 2..] == *b"\r\n" {
            line.truncate(line.len() - 2);
            break;
        }
        if line.len() > 8192 {
            return Err(Error::Str("header line too long"));
        }
    }
    String::from_utf8(line).map_err(|_| Error::Str("invalid header line encoding"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_https_urls() {
        let transport = HttpsTransport::new(Arc::new(StdDnsResolver));
        let err = transport.get("http://example.com/directory").unwrap_err();
        assert!(matches!(err, Error::Str("URL must use HTTPS")));
    }
}
