//! Shared edge HTTP server loop (plain TCP + optional TLS).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Mutex};
use std::thread::Builder;

use anyhow::Context;
use openapi_core::handler::{App, UpstreamForwarder};
use openapi_http::{dispatch_to_writer, handle_connection, ParsedRequest};
use openapi_platform::AttestationPlatform;
use tracing::{info, warn};

pub trait ReadWriteConn: Read + Write + Send {}

impl<T: Read + Write + Send> ReadWriteConn for T {}

/// Default accept-worker count. On Fortanix EDP each worker needs a TCS
/// (`ftxsgx-elf2sgxs --threads`); keep this below `SGX_THREADS` (build default 16).
fn accept_worker_count() -> usize {
    std::env::var("OPENAPI_ACCEPT_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(if cfg!(target_env = "sgx") { 8 } else { 32 })
}

fn handle_stream<U, P, F>(stream: TcpStream, app: &Arc<App<U, P>>, tls: &Option<Arc<F>>)
where
    U: UpstreamForwarder,
    P: AttestationPlatform,
    F: Fn(TcpStream) -> Option<Box<dyn ReadWriteConn>> + Send + Sync,
{
    if let Some(accept_tls) = tls.as_ref() {
        match accept_tls(stream) {
            Some(mut conn) => serve_connection(app, conn.as_mut()),
            None => warn!("tls accept failed"),
        }
    } else {
        let _ = handle_connection(stream, Arc::clone(app));
    }
}

/// Run the edge listener until process exit.
///
/// Uses a **bounded worker pool** (`OPENAPI_ACCEPT_WORKERS`) instead of
/// unbounded `thread::spawn` per connection. On Fortanix EDP, exhausting TCSes
/// makes `thread::spawn` panic; `Builder::spawn` returns `Err` and we fall back
/// to serving on the accept thread.
pub fn run_edge_server<U, P, F>(
    listen_addr: &str,
    app: Arc<App<U, P>>,
    tls: Option<F>,
) -> anyhow::Result<()>
where
    U: UpstreamForwarder + 'static,
    P: AttestationPlatform + 'static,
    F: Fn(TcpStream) -> Option<Box<dyn ReadWriteConn>> + Send + Sync + 'static,
{
    let listener = TcpListener::bind(listen_addr).context("bind listen addr")?;
    let local = listener.local_addr()?;
    let tls = tls.map(Arc::new);

    let want = accept_worker_count();
    let (tx, rx) = sync_channel::<TcpStream>(want);
    let rx = Arc::new(Mutex::new(rx));
    let mut live = 0usize;

    for i in 0..want {
        let rx = Arc::clone(&rx);
        let app = Arc::clone(&app);
        let tls = tls.clone();
        // Never use thread::spawn — it panics when Fortanix is out of TCSes.
        match Builder::new()
            .name(format!("edge-accept-{i}"))
            .spawn(move || {
                loop {
                    let stream = {
                        let guard = match rx.lock() {
                            Ok(g) => g,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        match guard.recv() {
                            Ok(s) => s,
                            Err(_) => return, // sender dropped
                        }
                    };
                    handle_stream(stream, &app, &tls);
                }
            }) {
            Ok(_) => live += 1,
            Err(e) => {
                warn!(
                    error = %e,
                    spawned = live,
                    requested = want,
                    "accept worker spawn failed (likely no free SGX TCS); stopping pool growth"
                );
                break;
            }
        }
    }

    if live == 0 {
        info!(addr = ?local, mode = "serial", "edge listening (no accept workers)");
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "accept failed");
                    continue;
                }
            };
            handle_stream(stream, &app, &tls);
        }
    } else {
        info!(addr = ?local, accept_workers = live, "edge listening");
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "accept failed");
                    continue;
                }
            };
            // Back-pressure when all workers are busy (does not spawn more threads).
            if tx.send(stream).is_err() {
                warn!("accept workers gone; shutting down listener");
                break;
            }
        }
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
                if dispatch_to_writer(
                    app,
                    &req.method,
                    &req.path,
                    req.headers.get("authorization").map(String::as_str),
                    &req.body,
                    conn,
                )
                .is_err()
                {
                    return;
                }
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
    use openapi_core::remote_auth::EdgeAuthenticator;
    use openapi_core::usage::UsageSigner;
    use openapi_core::{ApiError, UpstreamForwarder};
    use openapi_platform::{AttestationChallengeResponse, Measurement, PlatformError};
    use rand::rngs::OsRng;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::thread::Builder;

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
            EdgeAuthenticator::from_catalog(Authenticator::new(catalog)),
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
        Builder::new()
            .spawn(move || {
                if let Ok((stream, _)) = listener.accept() {
                    let _ = handle_connection(stream, app);
                }
            })
            .unwrap();
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).unwrap();
        assert!(resp.contains("200"));
    }
}
