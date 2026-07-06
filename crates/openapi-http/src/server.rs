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
                let response = dispatch(&app, req.method.as_str(), &req.path, req.headers.get("authorization").map(String::as_str), &req.body);
                stream.write_all(&response)?;
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
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let http_method = HttpMethod::parse(method);
    match app.handle(http_method, path, authorization, body, now_ms) {
        Ok(AppResponse::Json(body)) => {
            let bytes = serde_json::to_vec(&body).unwrap_or_default();
            build_json_response(200, &bytes, None)
        }
        Ok(AppResponse::JsonWithUsage { body, usage }) => {
            let bytes = serde_json::to_vec(&body).unwrap_or_default();
            build_json_response(200, &bytes, Some(&usage))
        }
        Ok(AppResponse::SseStream {
            upstream_body,
            usage,
        }) => build_sse_response(&upstream_body, &usage),
        Err(err) => build_error_response(err),
    }
}

fn dispatch<U, P>(
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
    dispatch_request(app, method, path, authorization, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openapi_core::auth::Authenticator;
    use openapi_core::catalog::{hash_api_key, sign_test_catalog, KeyCatalog, KeyRecord};
    use openapi_core::config::Config;
    use openapi_core::handler::{HttpMethod, UpstreamResponse};
    use openapi_core::limits::Limits;
    use openapi_core::usage::UsageSigner;
    use openapi_platform::{AttestationChallengeResponse, AttestationPlatform, EdgeIdentity, Measurement, PlatformError};
    use base64::Engine;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
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
            Ok(AttestationChallengeResponse {
                edge: EdgeIdentity {
                    build_version: "t".into(),
                    code_hash: "c".into(),
                    measurement: Measurement::Mrenclave { value: "m".into() },
                    tls_cert_spki_sha256: "s".into(),
                },
                challenge_nonce_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce),
                quote_b64: None,
            })
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
            Authenticator::new(catalog),
            TestUpstream,
            TestPlatform,
            UsageSigner::from_seed([9u8; 32]),
        ))
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
