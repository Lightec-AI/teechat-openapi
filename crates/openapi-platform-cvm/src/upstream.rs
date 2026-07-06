use std::io::Write;

use openapi_core::error::ApiError;
use openapi_core::handler::{HttpMethod, StreamForwardResult, UpstreamForwarder, UpstreamResponse};
use openapi_core::upstream::decode_upstream_response;

#[derive(Debug, Clone)]
pub struct UreqUpstream {
    base_url: String,
    agent: ureq::Agent,
}

impl UreqUpstream {
    pub fn new(base_url: impl Into<String>) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        Self {
            base_url,
            agent: ureq::Agent::new(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

impl UpstreamForwarder for UreqUpstream {
    fn forward_v1(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<UpstreamResponse, ApiError> {
        let wants_stream = body.map(body_wants_stream).unwrap_or(false);
        let url = self.url(path);

        match method {
            HttpMethod::Get => {
                let response = self
                    .agent
                    .get(&url)
                    .call()
                    .map_err(|e| ApiError::Upstream(e.to_string()))?;
                let status = response.status();
                let content_type = response
                    .header("Content-Type")
                    .unwrap_or("")
                    .to_string();
                let bytes = response
                    .into_string()
                    .map_err(|e| ApiError::Upstream(e.to_string()))?
                    .into_bytes();
                decode_upstream_response(status, &content_type, bytes, false)
            }
            HttpMethod::Post => {
                let body = body.unwrap_or(&[]);
                let response = self
                    .agent
                    .post(&url)
                    .set("Content-Type", "application/json")
                    .send_bytes(body)
                    .map_err(|e| ApiError::Upstream(e.to_string()))?;
                let status = response.status();
                let content_type = response
                    .header("Content-Type")
                    .unwrap_or("")
                    .to_string();
                let bytes = response
                    .into_string()
                    .map_err(|e| ApiError::Upstream(e.to_string()))?
                    .into_bytes();
                decode_upstream_response(status, &content_type, bytes, wants_stream)
            }
            HttpMethod::Other => Err(ApiError::MethodNotAllowed),
        }
    }

    fn forward_v1_stream(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&[u8]>,
        out: &mut dyn Write,
    ) -> Result<StreamForwardResult, ApiError> {
        let url = self.url(path);
        let response = match method {
            HttpMethod::Get => self.agent.get(&url).call(),
            HttpMethod::Post => self
                .agent
                .post(&url)
                .set("Content-Type", "application/json")
                .send_bytes(body.unwrap_or(&[])),
            HttpMethod::Other => return Err(ApiError::MethodNotAllowed),
        }
        .map_err(|e| ApiError::Upstream(e.to_string()))?;

        let status = response.status();
        let content_type = response
            .header("Content-Type")
            .unwrap_or("text/event-stream")
            .to_string();
        if !(200..300).contains(&status) {
            let err = response
                .into_string()
                .map_err(|e| ApiError::Upstream(e.to_string()))?;
            return Err(ApiError::Upstream(format!("upstream status {status}: {err}")));
        }

        let mut reader = response.into_reader();
        let bytes_written = std::io::copy(&mut reader, out)
            .map_err(|e| ApiError::Upstream(e.to_string()))?;
        Ok(StreamForwardResult {
            status,
            content_type,
            bytes_written,
        })
    }
}

fn body_wants_stream(body: &[u8]) -> bool {
    openapi_core::upstream::body_wants_stream(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn url_joins_paths() {
        let u = UreqUpstream::new("http://engine:8000");
        assert_eq!(u.url("/v1/models"), "http://engine:8000/v1/models");
    }

    #[test]
    fn forward_v1_stream_pipes_incrementally() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
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
            let sse = b"data: {\"t\":1}\n\n";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                sse.len()
            );
            stream.write_all(resp.as_bytes()).unwrap();
            stream.write_all(sse).unwrap();
            stream.flush().unwrap();
        });

        ready_rx.recv().unwrap();
        let upstream = UreqUpstream::new(format!("http://{}:{}", addr.ip(), addr.port()));
        let req_body = br#"{"model":"m","messages":[{"role":"user","content":"hi"}],"stream":true}"#;
        let mut out = Vec::new();
        upstream
            .forward_v1_stream(
                HttpMethod::Post,
                "/v1/chat/completions",
                Some(req_body),
                &mut out,
            )
            .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("data: {\"t\":1}"));
        server.join().unwrap();
    }
}
