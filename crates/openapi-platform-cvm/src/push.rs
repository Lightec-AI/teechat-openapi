use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use openapi_core::authz::SignedRevocation;
use openapi_core::remote_auth::RemoteAuthenticator;
use tracing::{info, warn};

/// Deprecated: D6-pull replaced inbound push. Kept for reference until deleted.
#[allow(dead_code)]
pub fn spawn_push_listener(
    listen_addr: String,
    remote: Arc<RemoteAuthenticator>,
) -> std::io::Result<()> {
    std::thread::spawn(move || {
        let listener = match TcpListener::bind(&listen_addr) {
            Ok(l) => l,
            Err(e) => {
                warn!(error = %e, addr = %listen_addr, "push listener bind failed");
                return;
            }
        };
        info!(addr = %listen_addr, "openapi push listener started");
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let remote = Arc::clone(&remote);
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 64 * 1024];
                let mut total = 0usize;
                loop {
                    let Ok(n) = stream.read(&mut buf[total..]) else { break };
                    if n == 0 {
                        break;
                    }
                    total += n;
                    if total >= buf.len() {
                        break;
                    }
                    let Ok(body) = std::str::from_utf8(&buf[..total]) else { continue };
                    if !body.contains("\r\n\r\n") {
                        continue;
                    }
                    let body_start = body.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
                    let json_part = &body[body_start..];
                    if json_part.is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<SignedRevocation>(json_part) {
                        Ok(revocation) => {
                            if let Err(e) = remote.apply_revocation(&revocation) {
                                warn!(error = %e, "push revocation rejected");
                                let _ = stream.write_all(b"HTTP/1.1 401 Unauthorized\r\n\r\n");
                            } else {
                                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n");
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "push json parse failed");
                            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
                        }
                    }
                    let _ = stream.flush();
                    break;
                }
            });
        }
    });
    Ok(())
}
