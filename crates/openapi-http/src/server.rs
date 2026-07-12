use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use openapi_core::handler::{App, AppResponse, HttpMethod, UpstreamForwarder};
use openapi_core::ApiError;
use openapi_platform::AttestationPlatform;
use thiserror::Error;

use crate::request::ParsedRequest;
use crate::response::{build_error_response, build_json_response, build_sse_response};
use crate::streaming::{write_sse_stream_headers, write_sse_usage_trailer, ChunkedWriter};

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("server: {0}")]
    Other(String),
}

pub struct Server {
    listener: TcpListener,
}

impl Server {
    pub fn bind(addr: &str) -> Result<Self, ServerError> {
        let listener = TcpListener::bind(addr)?;
        Ok(Self { listener })
    }

    pub fn local_addr(&self) -> Result<std::net::SocketAddr, ServerError> {
        Ok(self.listener.local_addr()?)
    }

    pub fn run<U, P>(&self, app: Arc<App<U, P>>) -> Result<(), ServerError>
    where
        U: UpstreamForwarder + 'static,
        P: AttestationPlatform + 'static,
    {
        for stream in self.listener.incoming() {
            let stream = stream?;
            let app = Arc::clone(&app);
            std::thread::spawn(move || {
                let _ = handle_connection(stream, app);
            });
        }
        Ok(())
    }
}

pub struct ConnectionHandler;

pub fn handle_connection<U, P>(
    mut stream: TcpStream,
    app: Arc<App<U, P>>,
) -> Result<(), ServerError>
where
    U: UpstreamForwarder,
    P: AttestationPlatform,
{
    let client_ip = stream.peer_addr().ok().map(|addr| addr.ip().to_string());
    stream.set_read_timeout(Some(std::time::Duration::from_secs(120)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(120)))?;

    let mut buffer = vec![0u8; 1024 * 256];
    let mut total = 0usize;
    loop {
        let n = stream.read(&mut buffer[total..])?;
        if n == 0 {
            return Ok(());
        }
        total += n;
        match ParsedRequest::parse(&buffer[..total]) {
            Ok(Some(req)) => {
                dispatch_to_writer(
                    &app,
                    req.method.as_str(),
                    &req.path,
                    req.headers.get("authorization").map(String::as_str),
                    &req.body,
                    client_ip.as_deref(),
                    &mut stream,
                )?;
                stream.flush()?;
                return Ok(());
            }
            Ok(None) => {
                if total >= buffer.len() {
                    let err = build_error_response(ApiError::PayloadTooLarge);
                    stream.write_all(&err)?;
                    return Ok(());
                }
                continue;
            }
            Err(_) => {
                let err = build_error_response(ApiError::BadRequest("malformed request".into()));
                stream.write_all(&err)?;
                return Ok(());
            }
        }
    }
}

pub fn dispatch_request<U, P>(
    app: &App<U, P>,
    method: &str,
    path: &str,
    authorization: Option<&str>,
    body: &[u8],
) -> Vec<u8>
where
    U: UpstreamForwarder,
    P: AttestationPlatform,
{
    dispatch_request_from(app, method, path, authorization, body, None)
}

pub fn dispatch_request_from<U, P>(
    app: &App<U, P>,
    method: &str,
    path: &str,
    authorization: Option<&str>,
    body: &[u8],
    client_ip: Option<&str>,
) -> Vec<u8>
where
    U: UpstreamForwarder,
    P: AttestationPlatform,
{
    let mut buf = Vec::new();
    if let Err(e) = dispatch_to_writer(app, method, path, authorization, body, client_ip, &mut buf)
    {
        return build_error_response(ApiError::Internal(e.to_string()));
    }
    buf
}

pub fn dispatch_to_writer<U, P, W: Write + ?Sized>(
    app: &App<U, P>,
    method: &str,
    path: &str,
    authorization: Option<&str>,
    body: &[u8],
    client_ip: Option<&str>,
    out: &mut W,
) -> Result<(), ServerError>
where
    U: UpstreamForwarder,
    P: AttestationPlatform,
{
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let http_method = HttpMethod::parse(method);
    match app.handle_from(
        http_method.clone(),
        path,
        authorization,
        body,
        now_ms,
        client_ip,
    ) {
        Ok(AppResponse::Json(body)) => {
            let bytes = serde_json::to_vec(&body).unwrap_or_default();
            out.write_all(&build_json_response(200, &bytes, None))
                .map_err(ServerError::Io)?;
        }
        Ok(AppResponse::JsonWithUsage { body, usage }) => {
            let bytes = serde_json::to_vec(&body).unwrap_or_default();
            out.write_all(&build_json_response(200, &bytes, Some(&usage)))
                .map_err(ServerError::Io)?;
        }
        Ok(AppResponse::SseStream {
            upstream_body,
            usage,
        }) => {
            out.write_all(&build_sse_response(&upstream_body, &usage))
                .map_err(ServerError::Io)?;
        }
        Ok(AppResponse::SsePassthrough {
            method,
            path,
            body,
            usage,
        }) => {
            write_sse_stream_headers(out, &usage).map_err(|e| ServerError::Other(e.to_string()))?;
            out.flush().map_err(ServerError::Io)?;
            let mut chunked = ChunkedWriter::new(out);
            app.execute_sse_passthrough(method, &path, &body, &mut chunked)
                .map_err(|e| ServerError::Other(e.to_string()))?;
            chunked.flush().map_err(ServerError::Io)?;
            write_sse_usage_trailer(chunked.inner, &usage)
                .map_err(|e| ServerError::Other(e.to_string()))?;
        }
        Err(err) => {
            out.write_all(&build_error_response(err))
                .map_err(ServerError::Io)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openapi_core::auth::Authenticator;
    use openapi_core::remote_auth::EdgeAuthenticator;
    use openapi_core::catalog::{hash_api_key, sign_test_catalog, KeyCatalog, KeyRecord};
    use openapi_core::config::Config;
    use openapi_core::handler::{HttpMethod, UpstreamResponse};
    use openapi_core::limits::Limits;
    use openapi_core::usage::UsageSigner;
    use openapi_platform::{
        AttestationChallengeResponse, AttestationPlatform, EdgeIdentity, Measurement,
        PlatformError, QuoteFormat, REPORT_DATA_LEN,
    };
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::time::Duration;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    struct TestUpstream;
    impl UpstreamForwarder for TestUpstream {
        fn forward_v1(
            &self,
            _method: HttpMethod,
            _path: &str,
            _body: Option<&[u8]>,
        ) -> Result<UpstreamResponse, ApiError> {
            Ok(UpstreamResponse::Json(serde_json::json!({
                "choices": [],
                "usage": {"prompt_tokens": 1, "completion_tokens": 2}
            })))
        }
    }

    struct TestPlatform;
    impl AttestationPlatform for TestPlatform {
        fn identity(&self) -> &EdgeIdentity {
            panic!("unused")
        }
        fn challenge(&self, nonce: &[u8]) -> Result<AttestationChallengeResponse, PlatformError> {
            fn hex32(b: u8) -> String {
                hex::encode([b; 32])
            }
            let edge = EdgeIdentity {
                build_version: "t".into(),
                code_hash: hex32(0x11),
                measurement: Measurement::Mrenclave {
                    value: hex32(0xaa),
                },
                tls_cert_spki_sha256: hex32(0xbb),
            };
            let rd = openapi_platform::build_report_data_v1(nonce, &edge)?;
            let mut report = vec![0u8; 320 + REPORT_DATA_LEN];
            report[320..384].copy_from_slice(&rd);
            AttestationChallengeResponse::new(edge, nonce, QuoteFormat::SgxReport, &report)
                .map_err(Into::into)
        }
    }

    fn test_app() -> Arc<App<TestUpstream, TestPlatform>> {
        let api_key = "sk-teechat-http";
        let mut csprng = OsRng;
        let signing = SigningKey::generate(&mut csprng);
        let verify = signing.verifying_key();
        let record = KeyRecord {
            key_id: "k".into(),
            key_hash_hex: hash_api_key(api_key),
            revoked: false,
        };
        let signed = sign_test_catalog(vec![record], &signing);
        let catalog = KeyCatalog::from_signed(signed, verify).unwrap();
        Arc::new(App::new(
            Config::default(),
            Limits::default(),
            EdgeAuthenticator::from_catalog(Authenticator::new(catalog)),
            TestUpstream,
            TestPlatform,
            UsageSigner::from_seed([9u8; 32]),
        ))
    }

    struct StreamingUpstream {
        delay: Duration,
    }

    impl UpstreamForwarder for StreamingUpstream {
        fn forward_v1(
            &self,
            _method: HttpMethod,
            _path: &str,
            _body: Option<&[u8]>,
        ) -> Result<UpstreamResponse, ApiError> {
            Err(ApiError::Upstream("use stream".into()))
        }

        fn forward_v1_stream(
            &self,
            _method: HttpMethod,
            _path: &str,
            _body: Option<&[u8]>,
            out: &mut dyn std::io::Write,
        ) -> Result<openapi_core::StreamForwardResult, ApiError> {
            out.write_all(b"data: {\"chunk\":1}\n\n")
                .map_err(|e| ApiError::Upstream(e.to_string()))?;
            out.flush().map_err(|e| ApiError::Upstream(e.to_string()))?;
            std::thread::sleep(self.delay);
            // Split UTF-8 emoji across writes — edge must not decode/re-encode text.
            out.write_all(b"data: {\"content\":\"")
                .map_err(|e| ApiError::Upstream(e.to_string()))?;
            out.write_all("💡".as_bytes())
                .map_err(|e| ApiError::Upstream(e.to_string()))?;
            out.write_all(b"\"}\n\n")
                .map_err(|e| ApiError::Upstream(e.to_string()))?;
            out.write_all(b"data: [DONE]\n\n")
                .map_err(|e| ApiError::Upstream(e.to_string()))?;
            Ok(openapi_core::StreamForwardResult {
                status: 200,
                content_type: "text/event-stream".into(),
                bytes_written: 0,
            })
        }
    }

    fn streaming_test_app(delay: Duration) -> Arc<App<StreamingUpstream, TestPlatform>> {
        let api_key = "sk-teechat-http";
        let mut csprng = OsRng;
        let signing = SigningKey::generate(&mut csprng);
        let verify = signing.verifying_key();
        let record = KeyRecord {
            key_id: "k".into(),
            key_hash_hex: hash_api_key(api_key),
            revoked: false,
        };
        let signed = sign_test_catalog(vec![record], &signing);
        let catalog = KeyCatalog::from_signed(signed, verify).unwrap();
        Arc::new(App::new(
            Config::default(),
            Limits::default(),
            EdgeAuthenticator::from_catalog(Authenticator::new(catalog)),
            StreamingUpstream { delay },
            TestPlatform,
            UsageSigner::from_seed([9u8; 32]),
        ))
    }

    #[test]
    fn integration_streaming_sse_passthrough() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let app = streaming_test_app(Duration::from_millis(50));
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let _ = handle_connection(stream, app);
            }
        });

        let body = r#"{"model":"m","messages":[{"role":"user","content":"hi"}],"stream":true}"#;
        let req = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer sk-teechat-http\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );

        let mut stream = std::net::TcpStream::connect(addr).unwrap();
        stream.write_all(req.as_bytes()).unwrap();
        stream.flush().unwrap();

        let mut full = Vec::new();
        stream.read_to_end(&mut full).unwrap();
        let text = String::from_utf8_lossy(&full);
        assert!(text.contains("Transfer-Encoding: chunked"), "got: {text}");
        assert!(text.contains("Cache-Control: no-cache, no-transform"));
        assert!(text.contains("X-Accel-Buffering: no"));
        assert!(text.contains("\"chunk\":1"));
        assert!(text.contains("💡"));
        assert!(!text.contains('\u{FFFD}'));
        assert!(text.contains("[DONE]"));
        assert!(text.contains("teechat_usage"));
    }

    #[test]
    fn integration_healthz() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let app = test_app();
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let _ = handle_connection(stream, app);
            }
        });

        let mut stream = std::net::TcpStream::connect(addr).unwrap();
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).unwrap();
        assert!(resp.contains("200"));
        assert!(resp.contains("\"status\":\"ok\""));
    }
}
