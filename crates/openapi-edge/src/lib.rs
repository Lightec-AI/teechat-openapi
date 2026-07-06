//! Shared edge HTTP server loop (plain TCP + optional TLS).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use anyhow::Context;
use openapi_core::App;
use openapi_core::UpstreamForwarder;
use openapi_http::{dispatch_request, handle_connection, ParsedRequest};
use openapi_platform::AttestationPlatform;
use tracing::{info, warn};

pub trait ReadWriteConn: Read + Write + Send {}

impl<T: Read + Write + Send> ReadWriteConn for T {}

/// Run the edge listener until process exit. Spawns one thread per connection.
pub fn run_edge_server<U, P, F>(
    listen_addr: &str,
    app: Arc<App<U, P>>,
    tls: Option<F>,
) -> anyhow::Result<()>
where
    U: UpstreamForwarder + 'static,
    P: AttestationPlatform + 'static,
    F: Fn(std::net::TcpStream) -> Option<Box<dyn ReadWriteConn>> + Send + Sync + 'static,
{
    let listener = TcpListener::bind(listen_addr).context("bind listen addr")?;
    info!(addr = ?listener.local_addr()?, "edge listening");

    let tls = tls.map(Arc::new);

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "accept failed");
                continue;
            }
        };
        let app = Arc::clone(&app);
        let tls = tls.clone();
        std::thread::spawn(move || {
            if let Some(accept_tls) = tls.as_ref() {
                match accept_tls(stream) {
                    Some(mut conn) => serve_connection(&app, &mut *conn),
                    None => warn!("tls accept failed"),
                }
            } else {
                let _ = handle_connection(stream, app);
            }
        });
    }

    Ok(())
}

pub fn serve_connection<U, P>(app: &Arc<App<U, P>>, conn: &mut (impl Read + Write + ?Sized))
where
    U: UpstreamForwarder,
    P: AttestationPlatform,
{
    let mut buffer = vec![0u8; 1024 * 256];
    let mut total = 0usize;
    loop {
        let n = match conn.read(&mut buffer[total..]) {
            Ok(0) => return,
            Ok(n) => n,
            Err(e) => {
                warn!(error = %e, "connection read");
                return;
            }
        };
        total += n;
        match ParsedRequest::parse(&buffer[..total]) {
            Ok(Some(req)) => {
                let response = dispatch_request(
                    app,
                    &req.method,
                    &req.path,
                    req.headers.get("authorization").map(String::as_str),
                    &req.body,
                );
                let _ = conn.write_all(&response);
                let _ = conn.flush();
                return;
            }
            Ok(None) => {
                if total >= buffer.len() {
                    return;
                }
                continue;
            }
            Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::SigningKey;
    use openapi_core::auth::Authenticator;
    use openapi_core::catalog::{hash_api_key, sign_test_catalog, KeyCatalog, KeyRecord};
    use openapi_core::config::Config;
    use openapi_core::handler::UpstreamResponse;
    use openapi_core::limits::Limits;
    use openapi_core::usage::UsageSigner;
    use openapi_core::{ApiError, UpstreamForwarder};
    use openapi_platform::{AttestationChallengeResponse, Measurement, PlatformError};
    use rand::rngs::OsRng;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    struct TestUpstream;
    impl UpstreamForwarder for TestUpstream {
        fn forward_v1(
            &self,
            _method: openapi_core::HttpMethod,
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
        fn identity(&self) -> &openapi_platform::EdgeIdentity {
            panic!("unused")
        }
        fn challenge(&self, nonce: &[u8]) -> Result<AttestationChallengeResponse, PlatformError> {
            Ok(AttestationChallengeResponse {
                edge: openapi_platform::EdgeIdentity {
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
        let api_key = "sk-teechat-edge";
        let mut csprng = OsRng;
        let signing = SigningKey::generate(&mut csprng);
        let signed = sign_test_catalog(
            vec![KeyRecord {
                key_id: "k".into(),
                key_hash_hex: hash_api_key(api_key),
                revoked: false,
            }],
            &signing,
        );
        let catalog = KeyCatalog::from_signed(signed, signing.verifying_key()).unwrap();
        Arc::new(App::new(
            Config::default(),
            Limits::default(),
            Authenticator::new(catalog),
            TestUpstream,
            TestPlatform,
            UsageSigner::from_seed([5u8; 32]),
        ))
    }

    #[test]
    fn run_edge_server_plain_healthz() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let app = test_app();
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let _ = handle_connection(stream, app);
            }
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).unwrap();
        assert!(resp.contains("200"));
    }
}
