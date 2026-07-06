//! Sync HTTP/1.1 upstream client over `TcpStream` (EDP-compatible; use IP:port URLs).

use std::io::{Read, Write};
use std::net::TcpStream;

use openapi_core::error::ApiError;
use openapi_core::handler::{HttpMethod, UpstreamForwarder, UpstreamResponse};
use openapi_core::models::{default_models, ModelsListResponse};
use openapi_core::upstream::decode_upstream_response;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpEndpoint {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct TcpHttpUpstream {
    endpoint: HttpEndpoint,
}

impl TcpHttpUpstream {
    pub fn new(base_url: &str) -> Result<Self, ApiError> {
        Ok(Self {
            endpoint: parse_http_base_url(base_url)?,
        })
    }

    fn connect(&self) -> Result<TcpStream, ApiError> {
        let addr = format!("{}:{}", self.endpoint.host, self.endpoint.port);
        TcpStream::connect(&addr).map_err(|e| ApiError::Upstream(format!("connect {addr}: {e}")))
    }

    fn request(&self, method: &str, path: &str, body: Option<&[u8]>) -> Result<(u16, String, Vec<u8>), ApiError> {
        let mut stream = self.connect()?;

        let request = if let Some(body) = body {
            format!(
                "{method} {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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
            .map_err(|e| ApiError::Upstream(e.to_string()))?;
        if let Some(body) = body {
            stream
                .write_all(body)
                .map_err(|e| ApiError::Upstream(e.to_string()))?;
        }
        stream.flush().map_err(|e| ApiError::Upstream(e.to_string()))?;

        read_http_response(&mut stream)
    }
}

impl UpstreamForwarder for TcpHttpUpstream {
    fn forward_v1(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<UpstreamResponse, ApiError> {
        let wants_stream = body.map(openapi_core::upstream::body_wants_stream).unwrap_or(false);
        let (status, content_type, bytes) = match method {
            HttpMethod::Get => self.request("GET", path, None)?,
            HttpMethod::Post => self.request("POST", path, body)?,
            HttpMethod::Other => return Err(ApiError::MethodNotAllowed),
        };
        decode_upstream_response(status, &content_type, bytes, wants_stream)
    }

    fn list_models(&self) -> Result<ModelsListResponse, ApiError> {
        match self.forward_v1(HttpMethod::Get, "/v1/models", None) {
            Ok(UpstreamResponse::Json(v)) => {
                serde_json::from_value(v).map_err(|e| ApiError::Upstream(e.to_string()))
            }
            Ok(_) => Err(ApiError::Upstream("unexpected models response".into())),
            Err(_) => Ok(default_models()),
        }
    }
}

pub fn parse_http_base_url(base_url: &str) -> Result<HttpEndpoint, ApiError> {
    let url = base_url.trim().trim_end_matches('/');
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| ApiError::BadRequest("upstream must be http://IP:port (no TLS, no DNS)".into()))?;
    let (host, port) = match rest.split_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().map_err(|e| ApiError::BadRequest(e.to_string()))?),
        None => return Err(ApiError::BadRequest("upstream must include explicit port".into())),
    };
    if host.is_empty() {
        return Err(ApiError::BadRequest("upstream host empty".into()));
    }
    Ok(HttpEndpoint { host, port })
}

fn read_http_response(stream: &mut TcpStream) -> Result<(u16, String, Vec<u8>), ApiError> {
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| ApiError::Upstream(e.to_string()))?;

    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| ApiError::Upstream("malformed upstream response".into()))?;
    let headers = String::from_utf8_lossy(&raw[..header_end]);
    let status_line = headers.lines().next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(502);
    let content_type = headers
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            if name.eq_ignore_ascii_case("content-type") {
                Some(value.trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();

    let body_start = header_end + 4;
    if let Some(cl_line) = headers.lines().find(|l| {
        l.to_ascii_lowercase().starts_with("content-length:")
    }) {
        let cl = cl_line
            .split_once(':')
            .map(|(_, v)| v.trim())
            .unwrap_or("");
        let len: usize = cl
            .parse()
            .map_err(|e| ApiError::Upstream(format!("content-length: {e}")))?;
        let end = body_start + len;
        if raw.len() >= end {
            return Ok((status, content_type, raw[body_start..end].to_vec()));
        }
    }

    Ok((status, content_type, raw[body_start..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    #[test]
    fn parse_http_base_url_ok() {
        let ep = parse_http_base_url("http://127.0.0.1:8000/").unwrap();
        assert_eq!(ep.host, "127.0.0.1");
        assert_eq!(ep.port, 8000);
    }

    #[test]
    fn parse_http_base_url_rejects_https() {
        assert!(parse_http_base_url("https://127.0.0.1:8000").is_err());
    }

    #[test]
    fn tcp_upstream_chat_roundtrip() {
        use std::net::Shutdown;
        use std::sync::mpsc;

        fn read_http_request(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
            let mut raw = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                let n = stream.read(&mut tmp)?;
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&tmp[..n]);
                let Some(header_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
                    continue;
                };
                let headers = &raw[..header_end];
                let body_start = header_end + 4;
                let cl = headers
                    .split(|&b| b == b'\n')
                    .find_map(|line| {
                        let line = line.strip_suffix(b"\r").unwrap_or(line);
                        let line_str = std::str::from_utf8(line).ok()?;
                        let (name, value) = line_str.split_once(':')?;
                        if name.eq_ignore_ascii_case("content-length") {
                            value.trim().parse::<usize>().ok()
                        } else {
                            None
                        }
                    });
                if let Some(len) = cl {
                    if raw.len() >= body_start + len {
                        return Ok(raw);
                    }
                } else if !raw.is_empty() {
                    return Ok(raw);
                }
            }
            Ok(raw)
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            ready_tx.send(()).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream).expect("read request");
            assert!(request.starts_with(b"POST /v1/chat/completions"));
            let body = r#"{"id":"x","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":2}}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(resp.as_bytes()).unwrap();
            stream.flush().unwrap();
            let _ = stream.shutdown(Shutdown::Write);
        });

        ready_rx.recv().unwrap();

        let base = format!("http://{}:{}", addr.ip(), addr.port());
        let upstream = TcpHttpUpstream::new(&base).unwrap();
        let resp = upstream
            .forward_v1(
                HttpMethod::Post,
                "/v1/chat/completions",
                Some(br#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#),
            )
            .unwrap();
        match resp {
            UpstreamResponse::Json(v) => assert_eq!(v["id"], "x"),
            _ => panic!("expected json"),
        }
        server.join().unwrap();
    }

    #[test]
    fn read_http_response_body_unit() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok(mut stream) = TcpStream::connect(addr) {
                let (_, _, body) = read_http_response(&mut stream).unwrap();
                assert_eq!(body, br#"{"ok":true}"#);
            }
        });
        if let Ok((mut stream, _)) = listener.accept() {
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{\"ok\":true}")
                .unwrap();
        }
    }
}
