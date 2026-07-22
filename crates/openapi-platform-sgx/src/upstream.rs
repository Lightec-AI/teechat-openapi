//! Sync HTTP/1.1 upstream client over `TcpStream` (EDP-compatible; use IP:port URLs).

use std::io::Write;
use std::net::TcpStream;

use openapi_core::error::ApiError;
use openapi_core::handler::{HttpMethod, StreamForwardResult, UpstreamForwarder, UpstreamResponse};
use openapi_core::http1_body::{copy_body, read_error_body, read_response_headers};
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

    fn write_request(
        &self,
        stream: &mut TcpStream,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<(), ApiError> {
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
        stream
            .flush()
            .map_err(|e| ApiError::Upstream(e.to_string()))
    }
}

impl UpstreamForwarder for TcpHttpUpstream {
    fn forward_v1(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<UpstreamResponse, ApiError> {
        let wants_stream = body
            .map(openapi_core::upstream::body_wants_stream)
            .unwrap_or(false);
        let mut stream = self.connect()?;
        match method {
            HttpMethod::Get => self.write_request(&mut stream, "GET", path, None)?,
            HttpMethod::Post => self.write_request(&mut stream, "POST", path, body)?,
            HttpMethod::Other => return Err(ApiError::MethodNotAllowed),
        }
        let (status, _headers, framing) = read_response_headers(&mut stream)?;
        let mut buf = [0u8; 8192];
        if !(200..300).contains(&status) {
            let err = read_error_body(&mut stream, &framing, &mut buf)?;
            return Err(ApiError::Upstream(format!(
                "upstream status {status}: {err}"
            )));
        }
        let mut body_out = Vec::new();
        copy_body(&mut stream, &framing, &mut body_out, &mut buf)?;
        let content_type = content_type_from_headers(&_headers);
        decode_upstream_response(status, &content_type, body_out, wants_stream)
    }

    fn forward_v1_stream(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&[u8]>,
        out: &mut dyn Write,
    ) -> Result<StreamForwardResult, ApiError> {
        let mut stream = self.connect()?;
        match method {
            HttpMethod::Get => self.write_request(&mut stream, "GET", path, None)?,
            HttpMethod::Post => self.write_request(&mut stream, "POST", path, body)?,
            HttpMethod::Other => return Err(ApiError::MethodNotAllowed),
        }
        let (status, headers, framing) = read_response_headers(&mut stream)?;
        let content_type = content_type_from_headers(&headers);
        let mut buf = [0u8; 8192];
        if !(200..300).contains(&status) {
            let err = read_error_body(&mut stream, &framing, &mut buf)?;
            return Err(ApiError::Upstream(format!(
                "upstream status {status}: {err}"
            )));
        }
        let bytes_written = copy_body(&mut stream, &framing, out, &mut buf)?;
        Ok(StreamForwardResult {
            status,
            content_type,
            bytes_written,
        })
    }
}

fn content_type_from_headers(headers: &str) -> String {
    headers
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            if name.eq_ignore_ascii_case("content-type") {
                Some(value.trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default()
}

pub fn parse_http_base_url(base_url: &str) -> Result<HttpEndpoint, ApiError> {
    let url = base_url.trim().trim_end_matches('/');
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        ApiError::BadRequest("upstream must be http://IP:port (no TLS, no DNS)".into())
    })?;
    let (host, port) = match rest.split_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>()
                .map_err(|e| ApiError::BadRequest(e.to_string()))?,
        ),
        None => {
            return Err(ApiError::BadRequest(
                "upstream must include explicit port".into(),
            ))
        }
    };
    if host.is_empty() {
        return Err(ApiError::BadRequest("upstream host empty".into()));
    }
    Ok(HttpEndpoint { host, port })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
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
                let cl = headers.split(|&b| b == b'\n').find_map(|line| {
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
            let body =
                r#"{"id":"x","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":2}}"#;
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
    fn forward_v1_stream_sse() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (hold_tx, hold_rx) = mpsc::channel::<()>();
        let server = thread::spawn(move || {
            ready_tx.send(()).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = stream.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let body = b"data: {\"t\":1}\n\n";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(resp.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
            stream.flush().unwrap();
            // Keep socket open until the client finishes reading (avoid RST on drop).
            let _ = hold_rx.recv();
        });

        ready_rx.recv().unwrap();
        let base = format!("http://{}:{}", addr.ip(), addr.port());
        let upstream = TcpHttpUpstream::new(&base).unwrap();
        let mut out = Vec::new();
        upstream
            .forward_v1_stream(
                HttpMethod::Post,
                "/v1/chat/completions",
                Some(br#"{"model":"m","messages":[{"role":"user","content":"hi"}],"stream":true}"#),
                &mut out,
            )
            .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("data: {\"t\":1}"));
        let _ = hold_tx.send(());
        server.join().unwrap();
    }
}
