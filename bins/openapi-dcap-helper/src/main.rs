//! Host-side DCAP ECDSA quote helper for Fortanix EDP enclaves.
//!
//! Enclaves cannot talk to `/var/run/aesmd/aesm.socket` directly. This process
//! listens on TCP (default `127.0.0.1:18500`) and proxies AESM ECDSA quoting:
//!
//! - `GET /qe-targetinfo` → raw QE `Targetinfo` bytes
//! - `POST /quote` (body = SGX REPORT) → DCAP ECDSA quote bytes
//!
//! AESM/QE remain the trust boundary; a malicious helper can only refuse to
//! quote — it cannot forge Intel ECDSA quotes for arbitrary reports.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;

use aesm_client::AesmClient;
use anyhow::{anyhow, bail, Context, Result};
use tracing::{error, info, warn};

const DEFAULT_LISTEN: &str = "127.0.0.1:18500";
const SGX_QL_ALG_ECDSA_P256: u32 = 2;
const ALGORITHM_OFFSET: usize = 154;
const QUOTE_NONCE_LEN: usize = 16;

struct QuoteState {
    client: AesmClient,
    ecdsa_key_id: Vec<u8>,
}

impl QuoteState {
    fn new() -> Result<Self> {
        let client = AesmClient::new();
        client
            .try_connect()
            .context("AESM connect (/var/run/aesmd/aesm.socket)")?;
        let key_ids = client
            .get_supported_att_key_ids()
            .context("get_supported_att_key_ids")?;
        let ecdsa_key_id = key_ids
            .into_iter()
            .find(|id| algorithm_id(id) == SGX_QL_ALG_ECDSA_P256)
            .ok_or_else(|| anyhow!("AESM has no ECDSA_P256 attestation key id"))?;
        Ok(Self {
            client,
            ecdsa_key_id,
        })
    }

    fn target_info(&self) -> Result<Vec<u8>> {
        let qi = self
            .client
            .init_quote_ex(self.ecdsa_key_id.clone())
            .context("init_quote_ex (needs PCCS/PCS + platform registration)")?;
        Ok(qi.target_info().to_vec())
    }

    fn quote(&self, report: Vec<u8>) -> Result<Vec<u8>> {
        if report.len() < sgx_isa::Report::UNPADDED_SIZE {
            bail!(
                "REPORT too short: {} < {}",
                report.len(),
                sgx_isa::Report::UNPADDED_SIZE
            );
        }
        let res = self
            .client
            .get_quote_ex(
                self.ecdsa_key_id.clone(),
                report,
                None,
                vec![0u8; QUOTE_NONCE_LEN],
            )
            .context("get_quote_ex")?;
        Ok(res.quote().to_vec())
    }
}

fn algorithm_id(key_id: &[u8]) -> u32 {
    if key_id.len() < ALGORITHM_OFFSET + 4 {
        return 0;
    }
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&key_id[ALGORITHM_OFFSET..ALGORITHM_OFFSET + 4]);
    u32::from_le_bytes(bytes)
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let listen = std::env::var("OPENAPI_DCAP_HELPER_LISTEN")
        .unwrap_or_else(|_| DEFAULT_LISTEN.to_string());

    let state = QuoteState::new().context("initialize AESM ECDSA quoting")?;
    // Warm QE target info once so cold PCCS failures surface at startup.
    let ti = state.target_info().context("warm init_quote_ex")?;
    info!(
        listen = %listen,
        target_info_len = ti.len(),
        "openapi-dcap-helper ready (ECDSA)"
    );

    let state = Mutex::new(state);
    let listener = TcpListener::bind(&listen).with_context(|| format!("bind {listen}"))?;
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                if let Err(e) = handle_client(&state, stream) {
                    warn!(error = %e, "request failed");
                }
            }
            Err(e) => error!(error = %e, "accept failed"),
        }
    }
    Ok(())
}

fn handle_client(state: &Mutex<QuoteState>, mut stream: TcpStream) -> Result<()> {
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .context("read request")?;
    let req = String::from_utf8_lossy(&buf);
    let mut lines = req.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    let (status, body, content_type) = match (method, path) {
        ("GET", "/healthz") => (200u16, b"ok".to_vec(), "text/plain"),
        ("GET", "/qe-targetinfo") => {
            let ti = state.lock().unwrap().target_info()?;
            (200, ti, "application/octet-stream")
        }
        ("POST", "/quote") => {
            let report = extract_body(&buf)?;
            let quote = state.lock().unwrap().quote(report)?;
            (200, quote, "application/octet-stream")
        }
        _ => (
            404,
            b"not found".to_vec(),
            "text/plain",
        ),
    };

    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "Error",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(&body)?;
    stream.flush()?;
    Ok(())
}

fn extract_body(raw: &[u8]) -> Result<Vec<u8>> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("missing HTTP header terminator"))?;
    Ok(raw[split + 4..].to_vec())
}
