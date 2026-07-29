//! Host-side ACME HTTP-01 + artifact helper for Fortanix EDP enclaves.
//!
//! The enclave cannot resolve DNS or write to the host webroot / artifact dir.
//! This process listens on TCP (default `127.0.0.1:18501`) and exposes:
//!
//! - `GET /healthz`
//! - `GET /dns?host=NAME` → `{"addrs":["ip:443",...]}`
//! - `PUT|DELETE /acme-challenge/{token}` → `{WEBROOT}/.well-known/acme-challenge/{token}`
//! - `PUT|GET|DELETE /artifacts/{name}` → allowlisted artifact files
//!
//! The host must never receive a TLS private key PEM — only sealed JSON + public cert.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use tracing::{error, info, warn};

const DEFAULT_LISTEN: &str = "127.0.0.1:18501";
const DEFAULT_WEBROOT: &str = "/var/www/acme";
const DEFAULT_ARTIFACT_DIR: &str = "/var/lib/teechat-openapi/sgx";
const MAX_BODY: usize = 256 * 1024;

const ARTIFACT_ALLOWLIST: &[&str] = &[
    "account.json",
    "account.staging.json",
    "sealed-key.json",
    "tls.crt",
];

#[derive(Clone)]
struct HelperPaths {
    webroot: PathBuf,
    artifact_dir: PathBuf,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let listen = std::env::var("OPENAPI_CEREMONY_HELPER_LISTEN")
        .unwrap_or_else(|_| DEFAULT_LISTEN.to_string());
    let paths = HelperPaths {
        webroot: PathBuf::from(
            std::env::var("OPENAPI_ACME_WEBROOT").unwrap_or_else(|_| DEFAULT_WEBROOT.into()),
        ),
        artifact_dir: PathBuf::from(
            std::env::var("OPENAPI_ARTIFACT_DIR").unwrap_or_else(|_| DEFAULT_ARTIFACT_DIR.into()),
        ),
    };

    std::fs::create_dir_all(paths.webroot.join(".well-known/acme-challenge"))
        .with_context(|| format!("mkdir acme challenge under {}", paths.webroot.display()))?;
    std::fs::create_dir_all(&paths.artifact_dir)
        .with_context(|| format!("mkdir {}", paths.artifact_dir.display()))?;

    info!(
        listen = %listen,
        webroot = %paths.webroot.display(),
        artifact_dir = %paths.artifact_dir.display(),
        "openapi-ceremony-helper ready"
    );

    let listener = TcpListener::bind(&listen).with_context(|| format!("bind {listen}"))?;
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                if let Err(e) = handle_client(&paths, stream) {
                    warn!(error = %e, "request failed");
                }
            }
            Err(e) => error!(error = %e, "accept failed"),
        }
    }
    Ok(())
}

fn handle_client(paths: &HelperPaths, mut stream: TcpStream) -> Result<()> {
    // Do not use read_to_end: HTTP clients keep the socket open awaiting a
    // response, so EOF never arrives and both sides deadlock.
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(30)));
    let buf = read_http_request(&mut stream).context("read request")?;
    let req = String::from_utf8_lossy(&buf);
    let mut lines = req.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path_and_query = parts.next().unwrap_or("");

    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_and_query, None),
    };

    let result = dispatch(paths, method, path, query, &buf);
    let (status, body, content_type) = match result {
        Ok(r) => r,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("not found") {
                (404u16, msg.into_bytes(), "text/plain")
            } else if msg.contains("forbidden") || msg.contains("invalid") {
                (400u16, msg.into_bytes(), "text/plain")
            } else {
                (500u16, msg.into_bytes(), "text/plain")
            }
        }
    };

    write_response(&mut stream, status, content_type, &body)
}

fn dispatch(
    paths: &HelperPaths,
    method: &str,
    path: &str,
    query: Option<&str>,
    raw: &[u8],
) -> Result<(u16, Vec<u8>, &'static str)> {
    match (method, path) {
        ("GET", "/healthz") => Ok((200, b"ok".to_vec(), "text/plain")),
        ("GET", "/dns") => {
            let host = query_param(query, "host").ok_or_else(|| anyhow!("missing host query"))?;
            if host.is_empty() || host.contains('/') || host.contains("..") {
                bail!("invalid host");
            }
            let addrs = resolve_dns_addrs(&host)?;
            let body = serde_json::to_vec(&serde_json::json!({ "addrs": addrs }))?;
            Ok((200, body, "application/json"))
        }
        ("PUT", p) if p.starts_with("/acme-challenge/") => {
            let token = &p["/acme-challenge/".len()..];
            let path = challenge_file_path(&paths.webroot, token)?;
            let body = extract_body(raw)?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, &body)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
            }
            Ok((200, b"ok".to_vec(), "text/plain"))
        }
        ("DELETE", p) if p.starts_with("/acme-challenge/") => {
            let token = &p["/acme-challenge/".len()..];
            let path = challenge_file_path(&paths.webroot, token)?;
            let _ = std::fs::remove_file(&path);
            Ok((200, b"ok".to_vec(), "text/plain"))
        }
        ("PUT", p) if p.starts_with("/artifacts/") => {
            let name = &p["/artifacts/".len()..];
            let path = artifact_file_path(&paths.artifact_dir, name)?;
            let body = extract_body(raw)?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, &body)?;
            Ok((200, b"ok".to_vec(), "text/plain"))
        }
        ("GET", p) if p.starts_with("/artifacts/") => {
            let name = &p["/artifacts/".len()..];
            let path = artifact_file_path(&paths.artifact_dir, name)?;
            match std::fs::read(&path) {
                Ok(body) => Ok((200, body, "application/octet-stream")),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    Ok((404, b"not found".to_vec(), "text/plain"))
                }
                Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
            }
        }
        ("DELETE", p) if p.starts_with("/artifacts/") => {
            let name = &p["/artifacts/".len()..];
            let path = artifact_file_path(&paths.artifact_dir, name)?;
            let _ = std::fs::remove_file(&path);
            Ok((200, b"ok".to_vec(), "text/plain"))
        }
        _ => Ok((404, b"not found".to_vec(), "text/plain")),
    }
}

fn resolve_dns_addrs(host: &str) -> Result<Vec<String>> {
    let addrs: Vec<String> = (host, 443u16)
        .to_socket_addrs()
        .with_context(|| format!("resolve {host}:443"))?
        .map(|a| a.to_string())
        .collect();
    if addrs.is_empty() {
        bail!("no addresses for {host}");
    }
    Ok(addrs)
}

/// Reject path traversal / separators in ACME challenge tokens.
pub(crate) fn sanitize_challenge_token(token: &str) -> Result<&str> {
    if token.is_empty() {
        bail!("invalid challenge token: empty");
    }
    if token.contains("..") || token.contains('/') || token.contains('\\') {
        bail!("invalid challenge token: path traversal forbidden");
    }
    if token.contains('\0') {
        bail!("invalid challenge token");
    }
    Ok(token)
}

/// Allowlisted artifact basename only.
pub(crate) fn sanitize_artifact_name(name: &str) -> Result<&str> {
    if name.contains("..") || name.contains('/') || name.contains('\\') {
        bail!("forbidden artifact name");
    }
    if !ARTIFACT_ALLOWLIST.contains(&name) {
        bail!("forbidden artifact name: {name} not allowlisted");
    }
    Ok(name)
}

fn challenge_file_path(webroot: &Path, token: &str) -> Result<PathBuf> {
    let token = sanitize_challenge_token(token)?;
    Ok(webroot
        .join(".well-known")
        .join("acme-challenge")
        .join(token))
}

fn artifact_file_path(artifact_dir: &Path, name: &str) -> Result<PathBuf> {
    let name = sanitize_artifact_name(name)?;
    Ok(artifact_dir.join(name))
}

fn query_param<'a>(query: Option<&'a str>, key: &str) -> Option<&'a str> {
    let query = query?;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(v);
            }
        } else if pair == key {
            return Some("");
        }
    }
    None
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Error",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

fn read_http_request(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];
    let header_end = loop {
        let n = stream.read(&mut tmp).context("read")?;
        if n == 0 {
            bail!("client closed before complete HTTP request");
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 64 * 1024 {
            bail!("HTTP headers too large");
        }
    };

    let content_length = {
        let header = std::str::from_utf8(&buf[..header_end]).unwrap_or("");
        header
            .lines()
            .find_map(|line| {
                let (k, v) = line.split_once(':')?;
                if k.eq_ignore_ascii_case("content-length") {
                    v.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0)
    };

    if content_length > MAX_BODY {
        bail!("HTTP body too large");
    }

    while buf.len() < header_end + content_length {
        let n = stream.read(&mut tmp).context("read body")?;
        if n == 0 {
            bail!(
                "client closed before complete body (have {} need {})",
                buf.len().saturating_sub(header_end),
                content_length
            );
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > MAX_BODY + 64 * 1024 {
            bail!("HTTP body too large");
        }
    }
    Ok(buf)
}

fn extract_body(raw: &[u8]) -> Result<Vec<u8>> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("missing HTTP header terminator"))?;
    Ok(raw[split + 4..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn artifact_allowlist_accepts_known_names() {
        for name in ARTIFACT_ALLOWLIST {
            assert_eq!(sanitize_artifact_name(name).unwrap(), *name);
        }
    }

    #[test]
    fn artifact_allowlist_rejects_unknown_and_traversal() {
        assert!(sanitize_artifact_name("evil.pem").is_err());
        assert!(sanitize_artifact_name("../account.json").is_err());
        assert!(sanitize_artifact_name("foo/account.json").is_err());
        assert!(sanitize_artifact_name("account.json/../x").is_err());
        assert!(sanitize_artifact_name("sealed-key.json.bak").is_err());
    }

    #[test]
    fn challenge_token_rejects_traversal() {
        assert!(sanitize_challenge_token("..").is_err());
        assert!(sanitize_challenge_token("../etc/passwd").is_err());
        assert!(sanitize_challenge_token("a/b").is_err());
        assert!(sanitize_challenge_token(r"a\b").is_err());
        assert!(sanitize_challenge_token("").is_err());
        assert_eq!(sanitize_challenge_token("abc123_OK-token").unwrap(), "abc123_OK-token");
    }

    #[test]
    fn challenge_path_stays_under_webroot() {
        let webroot = PathBuf::from("/var/www/acme");
        let p = challenge_file_path(&webroot, "tok123").unwrap();
        assert_eq!(
            p,
            PathBuf::from("/var/www/acme/.well-known/acme-challenge/tok123")
        );
        assert!(challenge_file_path(&webroot, "../x").is_err());
    }

    #[test]
    fn challenge_write_read_roundtrip_via_helper() {
        let tmp = std::env::temp_dir().join(format!(
            "openapi-ceremony-helper-test-{}",
            std::process::id()
        ));
        let webroot = tmp.join("www");
        let artifact_dir = tmp.join("artifacts");
        std::fs::create_dir_all(webroot.join(".well-known/acme-challenge")).unwrap();
        std::fs::create_dir_all(&artifact_dir).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let paths = Arc::new(HelperPaths {
            webroot: webroot.clone(),
            artifact_dir: artifact_dir.clone(),
        });
        let paths_bg = Arc::clone(&paths);
        let _server = thread::spawn(move || {
            for _ in 0..8 {
                let (stream, _) = listener.accept().unwrap();
                let _ = handle_client(&paths_bg, stream);
            }
        });

        // PUT challenge
        http_exchange(
            addr,
            "PUT",
            "/acme-challenge/tok-roundtrip",
            Some(b"key-auth-value"),
        )
        .unwrap();
        let written =
            std::fs::read_to_string(webroot.join(".well-known/acme-challenge/tok-roundtrip"))
                .unwrap();
        assert_eq!(written, "key-auth-value");

        // PUT + GET artifact
        http_exchange(addr, "PUT", "/artifacts/tls.crt", Some(b"CERTPEM")).unwrap();
        let got = http_exchange(addr, "GET", "/artifacts/tls.crt", None).unwrap();
        assert_eq!(got, b"CERTPEM");

        // Reject traversal token
        let status = http_status(addr, "PUT", "/acme-challenge/../evil", Some(b"x")).unwrap();
        assert_eq!(status, 400);

        // Reject non-allowlisted artifact
        let status = http_status(addr, "PUT", "/artifacts/privkey.pem", Some(b"x")).unwrap();
        assert_eq!(status, 400);

        // DELETE challenge
        http_exchange(addr, "DELETE", "/acme-challenge/tok-roundtrip", None).unwrap();
        assert!(!webroot
            .join(".well-known/acme-challenge/tok-roundtrip")
            .exists());

        let _ = std::fs::remove_dir_all(tmp);
    }

    fn http_exchange(
        addr: std::net::SocketAddr,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let (status, body) = http_raw(addr, method, path, body)?;
        if !(200..300).contains(&status) {
            bail!("HTTP {status}: {}", String::from_utf8_lossy(&body));
        }
        Ok(body)
    }

    fn http_status(
        addr: std::net::SocketAddr,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<u16> {
        let (status, _) = http_raw(addr, method, path, body)?;
        Ok(status)
    }

    fn http_raw(
        addr: std::net::SocketAddr,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>)> {
        let mut stream = TcpStream::connect(addr)?;
        let req = if let Some(body) = body {
            format!(
                "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
        } else {
            format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        };
        stream.write_all(req.as_bytes())?;
        if let Some(body) = body {
            stream.write_all(body)?;
        }
        stream.flush()?;
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp)?;
        let split = resp
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| anyhow!("bad response"))?;
        let header = std::str::from_utf8(&resp[..split]).unwrap_or("");
        let status = header
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        Ok((status, resp[split + 4..].to_vec()))
    }
}
