//! Shared edge HTTP server loop (plain TCP + optional TLS).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{sync_channel, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::Builder;
use std::time::Duration;

use anyhow::Context;
use openapi_core::error::ApiError;
use openapi_core::handler::{App, UpstreamForwarder};
use openapi_http::{build_error_response, dispatch_to_writer, handle_connection, ParsedRequest};
use openapi_platform::AttestationPlatform;
use tracing::{info, warn};

pub trait ReadWriteConn: Read + Write + Send {}

impl<T: Read + Write + Send> ReadWriteConn for T {}

/// Default accept-worker count ≈ **max concurrent streaming sessions**.
/// Each worker holds one TCP/TLS connection for the full prompt→stream lifetime
/// (often minutes: TTFT + token stream). Size ops to peak concurrent users, not
/// SYNs/sec.
///
/// CVM default **512**: roughly “hundreds of concurrent chats” on a typical
/// guest; raise with `OPENAPI_ACCEPT_WORKERS` for denser nodes.
/// SGX default **8**: hard-limited by enclave TCSes (`ftxsgx-elf2sgxs --threads`,
/// keep below build `SGX_THREADS`); raise TCS at image build to scale SGX — or
/// treat SGX as lower-concurrency / lab until async demux exists.
fn accept_worker_count() -> usize {
    std::env::var("OPENAPI_ACCEPT_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(if cfg!(target_env = "sgx") { 8 } else { 512 })
}

/// Max sockets waiting for a free worker. Full queue → immediate drop (load shed).
/// Keep small vs workers: backlog should not warehouse attackers; shed and free.
fn accept_queue_depth(workers: usize) -> usize {
    std::env::var("OPENAPI_ACCEPT_QUEUE")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or((workers / 4).max(2))
}

/// Idle gap between socket reads/writes during **TLS handshake + HTTP request
/// arrival only**. Valid clients send Authorization + JSON body promptly; we can
/// parse the API key as soon as headers land and reject bad keys immediately.
/// Attestation challenge POSTs are tiny — request is complete in well under this,
/// then timeouts are cleared so the quote itself may take a few seconds.
/// Default **3s** (not a full RTT budget): cut slowloris without waiting 15s.
fn conn_idle_timeout() -> Duration {
    let secs = std::env::var("OPENAPI_CONN_IDLE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(3);
    Duration::from_secs(secs)
}

fn apply_idle_timeouts(stream: &TcpStream, idle: Duration) {
    let _ = stream.set_read_timeout(Some(idle));
    let _ = stream.set_write_timeout(Some(idle));
}

/// Clear request-arrival idle so multi-minute streams / slow clients are not cut.
/// TLS wraps the socket; we keep a `try_clone` handle (same kernel fd) to clear
/// SO_RCVTIMEO / SO_SNDTIMEO after the HTTP request is fully parsed (IDLE-001).
fn clear_idle_timeouts(stream: &TcpStream) {
    let _ = stream.set_read_timeout(None);
    let _ = stream.set_write_timeout(None);
}

/// Cap short-lived 429 responder threads so shed storms cannot unbounded-spawn.
fn shed_worker_slots() -> u32 {
    std::env::var("OPENAPI_SHED_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(8)
}

fn write_429(conn: &mut (impl Write + ?Sized)) {
    let bytes = build_error_response(ApiError::RateLimited);
    let _ = conn.write_all(&bytes);
    let _ = conn.flush();
}

/// Reply **429 Too Many Requests** (TLS handshake if configured), then close.
fn respond_429_and_close<F>(stream: TcpStream, tls: &Option<Arc<F>>)
where
    F: Fn(TcpStream) -> Option<Box<dyn ReadWriteConn>> + Send + Sync,
{
    apply_idle_timeouts(&stream, Duration::from_secs(2));
    if let Some(accept_tls) = tls.as_ref() {
        match accept_tls(stream) {
            Some(mut conn) => write_429(conn.as_mut()),
            None => {}
        }
    } else {
        let mut stream = stream;
        write_429(&mut stream);
    }
}

struct ShedPermit {
    counter: Arc<AtomicU32>,
}

impl Drop for ShedPermit {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_acquire_shed(counter: &Arc<AtomicU32>, max: u32) -> Option<ShedPermit> {
    loop {
        let cur = counter.load(Ordering::Acquire);
        if cur >= max {
            return None;
        }
        if counter
            .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Some(ShedPermit {
                counter: Arc::clone(counter),
            });
        }
    }
}

fn spawn_shed_429<F>(
    stream: TcpStream,
    tls: Option<Arc<F>>,
    shed_inflight: &Arc<AtomicU32>,
    shed_max: u32,
    reason: &'static str,
) where
    F: Fn(TcpStream) -> Option<Box<dyn ReadWriteConn>> + Send + Sync + 'static,
{
    let ip = stream
        .peer_addr()
        .ok()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|| "unknown".into());
    let Some(permit) = try_acquire_shed(shed_inflight, shed_max) else {
        warn!(%ip, reason, "shed workers saturated; closing without 429");
        drop(stream);
        return;
    };
    // Never use thread::spawn on Fortanix — Builder returns Err when no TCS.
    if let Err(e) = Builder::new().name("edge-shed-429".into()).spawn(move || {
        let _permit = permit;
        warn!(%ip, reason, "responding 429 (capacity)");
        respond_429_and_close(stream, &tls);
    }) {
        warn!(%reason, error = %e, "shed spawn failed; closing");
    }
}

fn handle_stream<U, P, F>(stream: TcpStream, app: &Arc<App<U, P>>, tls: &Option<Arc<F>>)
where
    U: UpstreamForwarder,
    P: AttestationPlatform,
    F: Fn(TcpStream) -> Option<Box<dyn ReadWriteConn>> + Send + Sync,
{
    let idle = conn_idle_timeout();
    let client_ip = stream.peer_addr().ok().map(|a| a.ip().to_string());
    if let Some(accept_tls) = tls.as_ref() {
        // Cap before TLS handshake so floods do not pay crypto CPU — but if over
        // limit we still TLS + 429 so clients see a clean HTTP status.
        let _ip_permit = match app.try_acquire_ip_conn(client_ip.as_deref()) {
            Ok(p) => p,
            Err(_) => {
                warn!(
                    ip = client_ip.as_deref().unwrap_or("unknown"),
                    "per-IP connection limit; 429"
                );
                respond_429_and_close(stream, tls);
                return;
            }
        };
        // Clone before TLS takes ownership so we can clear socket idle after parse.
        let idle_socket = match stream.try_clone() {
            Ok(c) => {
                apply_idle_timeouts(&stream, idle);
                Some(c)
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "tcp try_clone for idle control failed; applying arrival idle without clear handle"
                );
                apply_idle_timeouts(&stream, idle);
                None
            }
        };
        match accept_tls(stream) {
            Some(mut conn) => serve_connection(
                app,
                conn.as_mut(),
                client_ip.as_deref(),
                idle_socket.as_ref(),
            ),
            None => warn!(
                ip = client_ip.as_deref().unwrap_or("unknown"),
                "tls accept failed"
            ),
        }
    } else {
        // handle_connection acquires the IP conn slot itself (429 on limit).
        let _ = handle_connection(stream, Arc::clone(app));
    }
}

/// Run the edge listener until process exit.
///
/// Uses a **bounded worker pool** (`OPENAPI_ACCEPT_WORKERS`) instead of
/// unbounded `thread::spawn` per connection. When the accept queue is full,
/// clients get **HTTP 429** (via a small shed-worker set) instead of a hard RST.
///
/// On Fortanix EDP, exhausting TCSes makes `thread::spawn` panic; `Builder::spawn`
/// returns `Err` and we fall back to serving on the accept thread.
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
    let queue = accept_queue_depth(want);
    let idle = conn_idle_timeout();
    let shed_max = shed_worker_slots();
    let shed_inflight = Arc::new(AtomicU32::new(0));
    let (tx, rx) = sync_channel::<TcpStream>(queue);
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
        info!(
            addr = ?local,
            mode = "serial",
            idle_secs = idle.as_secs(),
            "edge listening (no accept workers)"
        );
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
        info!(
            addr = ?local,
            accept_workers = live,
            accept_queue = queue,
            shed_workers = shed_max,
            idle_secs = idle.as_secs(),
            "edge listening (bounded pool; 429 when saturated)"
        );
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "accept failed");
                    continue;
                }
            };
            match tx.try_send(stream) {
                Ok(()) => {}
                Err(TrySendError::Full(stream)) => {
                    spawn_shed_429(
                        stream,
                        tls.clone(),
                        &shed_inflight,
                        shed_max,
                        "accept queue full",
                    );
                }
                Err(TrySendError::Disconnected(_)) => {
                    warn!("accept workers gone; shutting down listener");
                    break;
                }
            }
        }
    }

    Ok(())
}

/// Receive buffer = `max_body_bytes` + header slack. A hard 256 KiB cap (older
/// TLS path) silently closed WorkBuddy long-chat POSTs → client `502 socket hang up`
/// with no F′/L0 traffic.
fn request_recv_capacity(max_body_bytes: usize) -> usize {
    max_body_bytes.saturating_add(64 * 1024).max(256 * 1024)
}

pub fn serve_connection<U, P>(
    app: &Arc<App<U, P>>,
    conn: &mut (impl Read + Write + ?Sized),
    client_ip: Option<&str>,
    idle_socket: Option<&TcpStream>,
) where
    U: UpstreamForwarder,
    P: AttestationPlatform,
{
    let mut buffer = vec![0u8; request_recv_capacity(app.config().max_body_bytes)];
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
                // Request complete — clear arrival idle (same as plain `handle_connection`).
                // TLS `StreamOwned` does not expose set_*_timeout; use the pre-accept
                // `try_clone` of the underlying TcpStream (IDLE-001).
                if let Some(sock) = idle_socket {
                    clear_idle_timeouts(sock);
                }
                if dispatch_to_writer(
                    app,
                    &req.method,
                    &req.path,
                    req.headers.get("authorization").map(String::as_str),
                    &req.body,
                    client_ip,
                    req.headers
                        .get("x-teechat-challenge-bench")
                        .map(String::as_str),
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
                    let _ = conn.write_all(&build_error_response(ApiError::PayloadTooLarge));
                    let _ = conn.flush();
                    return;
                }
                continue;
            }
            Err(_) => {
                let _ = conn.write_all(&build_error_response(ApiError::BadRequest(
                    "malformed request".into(),
                )));
                let _ = conn.flush();
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use openapi_core::auth::Authenticator;
    use openapi_core::catalog::{hash_api_key, sign_test_catalog, KeyCatalog, KeyRecord};
    use openapi_core::config::Config;
    use openapi_core::handler::UpstreamResponse;
    use openapi_core::limits::Limits;
    use openapi_core::remote_auth::EdgeAuthenticator;
    use openapi_core::usage::UsageSigner;
    use openapi_core::{ApiError, UpstreamForwarder};
    use openapi_platform::{
        AttestationChallengeResponse, Measurement, PlatformError, QuoteFormat, REPORT_DATA_LEN,
    };
    use rand::rngs::OsRng;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::thread::Builder;
    use std::time::Duration;

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
            fn hex32(b: u8) -> String {
                hex::encode([b; 32])
            }
            let edge = openapi_platform::EdgeIdentity {
                build_version: "t".into(),
                code_hash: hex32(0x11),
                measurement: Measurement::Mrenclave { value: hex32(0xaa) },
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
        test_app_with(Limits::default())
    }

    fn test_app_with(limits: Limits) -> Arc<App<TestUpstream, TestPlatform>> {
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
            limits,
            EdgeAuthenticator::from_catalog(Authenticator::new(catalog)),
            TestUpstream,
            TestPlatform,
            UsageSigner::from_seed([5u8; 32]),
        ))
    }

    fn wait_for_listen(addr: std::net::SocketAddr) {
        for _ in 0..80 {
            if TcpStream::connect_timeout(&addr, Duration::from_millis(25)).is_ok() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("server did not accept within timeout");
    }

    fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
        let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).unwrap();
        let mut resp = String::new();
        let _ = stream.read_to_string(&mut resp);
        resp
    }

    #[test]
    fn shed_slot_acquire_releases_on_drop() {
        let c = Arc::new(AtomicU32::new(0));
        let a = try_acquire_shed(&c, 1).expect("first");
        assert!(try_acquire_shed(&c, 1).is_none());
        drop(a);
        assert!(try_acquire_shed(&c, 1).is_some());
    }

    #[test]
    fn respond_429_plain_is_http_429() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        Builder::new()
            .spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                let none_tls: Option<Arc<fn(TcpStream) -> Option<Box<dyn ReadWriteConn>>>> = None;
                respond_429_and_close(stream, &none_tls);
            })
            .unwrap();
        let resp = http_get(addr, "/anything");
        assert!(resp.contains("HTTP/1.1 429"), "got: {resp}");
        assert!(resp.contains("rate_limit_exceeded"));
        assert!(resp.contains("Retry-After: 1"));
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
        let resp = http_get(addr, "/healthz");
        assert!(resp.contains("200"), "got: {resp}");
    }

    #[test]
    fn serve_connection_clears_idle_timeouts_after_request() {
        // Simulate TLS ownership of the socket: serve over the owned stream while
        // clearing via a try_clone handle (IDLE-001).
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let app = test_app();
        let cleared = Arc::new(AtomicUsize::new(0));
        let cleared_c = Arc::clone(&cleared);
        Builder::new()
            .spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                let idle_sock = stream.try_clone().unwrap();
                apply_idle_timeouts(&stream, Duration::from_secs(1));
                assert_eq!(stream.read_timeout().unwrap(), Some(Duration::from_secs(1)));
                let mut owned = stream;
                serve_connection(&app, &mut owned, None, Some(&idle_sock));
                assert_eq!(
                    idle_sock.read_timeout().unwrap(),
                    None,
                    "idle must clear after ParsedRequest"
                );
                assert_eq!(idle_sock.write_timeout().unwrap(), None);
                cleared_c.store(1, Ordering::SeqCst);
            })
            .unwrap();

        let resp = http_get(addr, "/healthz");
        assert!(resp.contains("200"), "got: {resp}");
        for _ in 0..50 {
            if cleared.load(Ordering::SeqCst) == 1 {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("server thread did not finish clear assertion");
    }

    #[test]
    fn saturated_queue_returns_http_429() {
        std::env::set_var("OPENAPI_ACCEPT_WORKERS", "1");
        std::env::set_var("OPENAPI_ACCEPT_QUEUE", "1");
        std::env::set_var("OPENAPI_CONN_IDLE_SECS", "30");
        std::env::set_var("OPENAPI_SHED_WORKERS", "4");

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let app = test_app();
        let listen = format!("{addr}");
        Builder::new()
            .spawn(move || {
                let _ = run_edge_server(
                    &listen,
                    app,
                    None::<fn(TcpStream) -> Option<Box<dyn ReadWriteConn>>>,
                );
            })
            .unwrap();
        wait_for_listen(addr);

        // Occupy the single worker + one queued slot with incomplete requests.
        let mut holders = Vec::new();
        for _ in 0..2 {
            let s = TcpStream::connect_timeout(&addr, Duration::from_secs(1)).unwrap();
            let _ = s.set_read_timeout(Some(Duration::from_millis(200)));
            holders.push(s);
            thread::sleep(Duration::from_millis(30));
        }

        let mut got_429 = false;
        for _ in 0..10 {
            let resp = http_get(addr, "/healthz");
            if resp.contains("HTTP/1.1 429") {
                got_429 = true;
                assert!(resp.contains("rate_limit_exceeded"));
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        drop(holders);
        std::env::remove_var("OPENAPI_ACCEPT_WORKERS");
        std::env::remove_var("OPENAPI_ACCEPT_QUEUE");
        std::env::remove_var("OPENAPI_CONN_IDLE_SECS");
        std::env::remove_var("OPENAPI_SHED_WORKERS");
        assert!(got_429, "expected HTTP 429 while pool saturated");
    }

    #[test]
    fn per_ip_connection_limit_returns_429() {
        std::env::set_var("OPENAPI_ACCEPT_WORKERS", "4");
        std::env::set_var("OPENAPI_ACCEPT_QUEUE", "4");
        std::env::set_var("OPENAPI_CONN_IDLE_SECS", "30");

        let mut limits = Limits::default();
        limits.ip_max_connections = 1;
        let app = test_app_with(limits);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let listen = format!("{addr}");
        Builder::new()
            .spawn(move || {
                let _ = run_edge_server(
                    &listen,
                    app,
                    None::<fn(TcpStream) -> Option<Box<dyn ReadWriteConn>>>,
                );
            })
            .unwrap();
        wait_for_listen(addr);

        let holder = TcpStream::connect_timeout(&addr, Duration::from_secs(1)).unwrap();
        // Give the worker time to accept and acquire the IP slot.
        thread::sleep(Duration::from_millis(50));

        let resp = http_get(addr, "/healthz");
        drop(holder);
        std::env::remove_var("OPENAPI_ACCEPT_WORKERS");
        std::env::remove_var("OPENAPI_ACCEPT_QUEUE");
        std::env::remove_var("OPENAPI_CONN_IDLE_SECS");
        assert!(
            resp.contains("HTTP/1.1 429"),
            "second conn from same IP should 429, got: {resp}"
        );
    }

    #[test]
    fn saturated_queue_sheds_without_blocking_accept() {
        std::env::set_var("OPENAPI_ACCEPT_WORKERS", "1");
        std::env::set_var("OPENAPI_ACCEPT_QUEUE", "1");
        std::env::set_var("OPENAPI_CONN_IDLE_SECS", "2");

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let app = test_app();
        let listen = format!("{addr}");
        let started = Arc::new(AtomicUsize::new(0));
        let started_c = Arc::clone(&started);
        Builder::new()
            .spawn(move || {
                started_c.store(1, Ordering::SeqCst);
                let _ = run_edge_server(
                    &listen,
                    app,
                    None::<fn(TcpStream) -> Option<Box<dyn ReadWriteConn>>>,
                );
            })
            .unwrap();

        for _ in 0..50 {
            if started.load(Ordering::SeqCst) == 1 {
                if TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
                    break;
                }
            }
            thread::sleep(Duration::from_millis(10));
        }

        let mut holders = Vec::new();
        for _ in 0..4 {
            if let Ok(s) = TcpStream::connect(addr) {
                let _ = s.set_read_timeout(Some(Duration::from_millis(200)));
                holders.push(s);
            }
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(4);
        let mut ok = false;
        while std::time::Instant::now() < deadline {
            let resp = http_get(addr, "/healthz");
            // After idle cut, capacity returns — 200; while full, 429 is also fine for liveness.
            if resp.contains("200") || resp.contains("429") {
                ok = true;
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        drop(holders);
        std::env::remove_var("OPENAPI_ACCEPT_WORKERS");
        std::env::remove_var("OPENAPI_ACCEPT_QUEUE");
        std::env::remove_var("OPENAPI_CONN_IDLE_SECS");
        assert!(ok, "healthz/429 should succeed without hang");
    }
}
