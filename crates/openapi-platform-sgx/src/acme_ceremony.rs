//! Option A SGX ACME ceremony: HTTP-01 inside the enclave, seal with EGETKEY.
//!
//! Private key PEM never leaves enclave memory except as an MRENCLAVE-sealed
//! JSON blob written to the host helper artifact store.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{bail, Context};
use openapi_acme_sync::{
    provision_http01, AcmeTransport, DnsResolver, Error as AcmeError, Http01ChallengeSink,
    HttpResponse, LetsEncrypt, ProvisionRequest,
};
use openapi_platform::{load_edge_profile, SealedTlsKeyBlob, Sealer};
use tracing::info;
use zeroize::Zeroize;

use crate::ceremony_helper::CeremonyHelperClient;
use crate::seal::SgxSealer;
use crate::tls::{spki_sha256_hex_from_cert_bytes, TlsConfig};

/// ACME ceremony mode (same binary as the edge server).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcmeMode {
    Issue,
    Renew,
}

impl AcmeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issue => "issue",
            Self::Renew => "renew",
        }
    }
}

/// DNS resolver that calls host `openapi-ceremony-helper` `/dns`.
///
/// Kept for host unit tests; production EDP ACME uses [`HelperHttpsRelayTransport`].
pub struct HelperDnsResolver {
    client: CeremonyHelperClient,
}

impl HelperDnsResolver {
    pub fn new(client: CeremonyHelperClient) -> Self {
        Self { client }
    }
}

impl DnsResolver for HelperDnsResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<SocketAddr, AcmeError> {
        self.client
            .resolve_dns(host, port)
            .map_err(|e| AcmeError::Http(e.to_string()))
    }
}

/// ACME HTTPS via host helper `/https-relay` (EDP production path).
///
/// The enclave still owns ACME account key + leaf keygen/JOSE/CSR/seal; the host
/// only performs the TLS client I/O to Let's Encrypt / ZeroSSL.
pub struct HelperHttpsRelayTransport {
    client: CeremonyHelperClient,
}

impl HelperHttpsRelayTransport {
    pub fn new(client: CeremonyHelperClient) -> Self {
        Self { client }
    }
}

impl AcmeTransport for HelperHttpsRelayTransport {
    fn request(
        &self,
        method: &str,
        url: &str,
        content_type: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, AcmeError> {
        let (status, headers, body) = self
            .client
            .https_relay(method, url, content_type, body)
            .map_err(|e| AcmeError::Http(e.to_string()))?;
        Ok(HttpResponse::new(status, headers, body))
    }
}

/// HTTP-01 sink that publishes challenge files via the host helper.
pub struct HelperChallengeSink {
    client: CeremonyHelperClient,
}

impl HelperChallengeSink {
    pub fn new(client: CeremonyHelperClient) -> Self {
        Self { client }
    }
}

impl Http01ChallengeSink for HelperChallengeSink {
    fn place(&self, token: &str, key_authorization: &str) -> Result<(), AcmeError> {
        self.client
            .place_challenge(token, key_authorization)
            .map_err(|e| AcmeError::Http(e.to_string()))
    }

    fn clear(&self, token: &str) -> Result<(), AcmeError> {
        self.client
            .clear_challenge(token)
            .map_err(|e| AcmeError::Http(e.to_string()))
    }
}

/// Fail closed on host-supplied plaintext key / seal-root for prod ACME.
///
/// Staging Let's Encrypt is allowed under `OPENAPI_PROFILE=dev` (lab).
/// Production Let's Encrypt requires `OPENAPI_PROFILE=prod`.
pub fn assert_acme_ceremony_policy(staging: bool) -> anyhow::Result<()> {
    let profile = load_edge_profile();
    if staging {
        if profile.is_prod() {
            bail!("staging Let's Encrypt forbidden when OPENAPI_PROFILE=prod (use prod LE)");
        }
    } else if !profile.is_prod() {
        bail!("production Let's Encrypt requires OPENAPI_PROFILE=prod (lab: set OPENAPI_ACME_STAGING=1 with OPENAPI_PROFILE=dev)");
    }

    if profile.is_prod() {
        if std::env::var("OPENAPI_TLS_KEY_PATH")
            .ok()
            .filter(|s| !s.is_empty())
            .is_some()
        {
            bail!("OPENAPI_TLS_KEY_PATH must not be set during prod ACME ceremony");
        }
        if std::env::var("OPENAPI_SEAL_ROOT_HEX")
            .ok()
            .filter(|s| !s.is_empty())
            .is_some()
        {
            bail!("OPENAPI_SEAL_ROOT_HEX must not be set during prod ACME ceremony");
        }
    }
    Ok(())
}

fn account_artifact_name(staging: bool) -> &'static str {
    if staging {
        "account.staging.json"
    } else {
        "account.json"
    }
}

/// Run Option A ACME issue/renew inside the enclave (or host test stub).
pub fn run_acme_ceremony(mode: AcmeMode) -> anyhow::Result<()> {
    TlsConfig::install_crypto_provider().context("tls crypto provider")?;

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let staging = std::env::var("OPENAPI_ACME_STAGING")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    assert_acme_ceremony_policy(staging)?;

    let domain = std::env::var("OPENAPI_ACME_DOMAIN")
        .or_else(|_| std::env::var("OPENAPI_ACME_CERT_NAME"))
        .context("OPENAPI_ACME_DOMAIN or OPENAPI_ACME_CERT_NAME required")?;
    let email = std::env::var("OPENAPI_ACME_EMAIL").ok().filter(|s| !s.is_empty());

    let helper = CeremonyHelperClient::from_env().context("ceremony helper client")?;
    let directory_url = if staging {
        LetsEncrypt::Staging.url()
    } else {
        LetsEncrypt::Production.url()
    }
    .to_owned();

    let account_name = account_artifact_name(staging);
    let account_credentials_json = match helper.get_artifact(account_name) {
        Ok(bytes) => Some(
            String::from_utf8(bytes).context("account credentials artifact is not UTF-8")?,
        ),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("404") || msg.contains("not found") || msg.contains("No such file") {
                None
            } else {
                return Err(e).context("load account credentials artifact");
            }
        }
    };

    let sealer = SgxSealer::from_runtime().context("SgxSealer::from_runtime")?;
    let prod = load_edge_profile().is_prod();
    let seal_root = sealer
        .resolve_seal_root(None, prod)
        .context("resolve seal root")?;

    // Renew: unseal the existing leaf key and CSR with it (stable SPKI across renewals).
    // Issue: mint a new leaf key.
    let (existing_private_key_pem, prior_spki) = match mode {
        AcmeMode::Renew => {
            let sealed = helper
                .get_artifact("sealed-key.json")
                .context("renew requires sealed-key.json (run issue first)")?;
            let blob: SealedTlsKeyBlob = serde_json::from_slice(&sealed)
                .context("parse sealed-key.json")?;
            let pem_bytes = sealer
                .unseal_tls_key(&blob, seal_root.as_ref())
                .context("unseal existing leaf key for renew")?;
            let pem = String::from_utf8(pem_bytes).context("sealed leaf key is not UTF-8 PEM")?;
            let prior_cert = helper
                .get_artifact("tls.crt")
                .context("renew requires tls.crt (run issue first)")?;
            let spki = spki_sha256_hex_from_cert_bytes(&prior_cert)
                .map_err(|e| anyhow::anyhow!("prior tls.crt SPKI: {e}"))?;
            (Some(pem), Some(spki))
        }
        AcmeMode::Issue => (None, None),
    };

    info!(
        mode = mode.as_str(),
        %domain,
        staging,
        has_account = account_credentials_json.is_some(),
        reuse_leaf = existing_private_key_pem.is_some(),
        "starting SGX Option A ACME ceremony"
    );

    let transport: Arc<dyn AcmeTransport> =
        Arc::new(HelperHttpsRelayTransport::new(helper.clone()));
    let sink = HelperChallengeSink::new(helper.clone());
    let req = ProvisionRequest {
        domain: domain.clone(),
        directory_url,
        email,
        account_credentials_json,
        existing_private_key_pem,
    };

    let mut outcome = provision_http01(transport, &sink, req)
        .map_err(|e| anyhow::anyhow!("ACME provision: {e}"))?;

    if let Some(expected) = prior_spki {
        let got = spki_sha256_hex_from_cert_bytes(outcome.certificate_chain_pem.as_bytes())
            .map_err(|e| anyhow::anyhow!("new cert SPKI: {e}"))?;
        if got != expected {
            outcome.private_key_pem.zeroize();
            bail!(
                "renew changed leaf SPKI ({expected} → {got}); refusing to overwrite sealed key"
            );
        }
    }

    // Persist account for renew (contains ACME account key — not the TLS leaf key).
    helper
        .put_artifact(account_name, outcome.account_credentials_json.as_bytes())
        .context("store account credentials artifact")?;

    let blob = sealer
        .seal_tls_key(outcome.private_key_pem.as_bytes(), seal_root.as_ref())
        .context("seal TLS private key (EGETKEY / host stub)")?;

    // Wipe plaintext key before any further helper I/O.
    outcome.private_key_pem.zeroize();

    let sealed_json =
        serde_json::to_vec_pretty(&blob).context("encode sealed-key.json")?;
    helper
        .put_artifact("sealed-key.json", &sealed_json)
        .context("store sealed-key.json")?;
    helper
        .put_artifact("tls.crt", outcome.certificate_chain_pem.as_bytes())
        .context("store tls.crt")?;

    let spki = spki_sha256_hex_from_cert_bytes(outcome.certificate_chain_pem.as_bytes())
        .unwrap_or_else(|_| "unknown".into());
    info!(
        mode = mode.as_str(),
        %domain,
        mrenclave = %sealer.mrenclave(),
        seal_version = blob.seal_version,
        spki_sha256 = %spki,
        "SGX ACME ceremony complete (sealed-key.json + tls.crt on helper)"
    );
    Ok(())
}

/// Seal ACME outcome in memory and return sealed JSON + cert PEM (host tests).
pub fn seal_from_acme_outcome(
    sealer: &SgxSealer,
    private_key_pem: &mut String,
    certificate_chain_pem: &str,
    seal_root: Option<&[u8; 32]>,
) -> anyhow::Result<(Vec<u8>, String)> {
    let blob = sealer
        .seal_tls_key(private_key_pem.as_bytes(), seal_root)
        .context("seal")?;
    private_key_pem.zeroize();
    let sealed_json = serde_json::to_vec_pretty(&blob)?;
    Ok((sealed_json, certificate_chain_pem.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony_helper::CeremonyHelperClient;
    use openapi_platform::Sealer;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::thread;

    static POLICY_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn policy_rejects_prod_staging() {
        let _g = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("OPENAPI_PROFILE", "prod");
        std::env::remove_var("OPENAPI_TLS_KEY_PATH");
        std::env::remove_var("OPENAPI_SEAL_ROOT_HEX");
        let err = assert_acme_ceremony_policy(true).unwrap_err().to_string();
        assert!(err.contains("staging"));
        std::env::remove_var("OPENAPI_PROFILE");
    }

    #[test]
    fn policy_rejects_prod_le_without_prod_profile() {
        let _g = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("OPENAPI_PROFILE", "dev");
        let err = assert_acme_ceremony_policy(false).unwrap_err().to_string();
        assert!(err.contains("OPENAPI_PROFILE=prod"));
        std::env::remove_var("OPENAPI_PROFILE");
    }

    #[test]
    fn policy_rejects_host_seal_root_in_prod() {
        let _g = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("OPENAPI_PROFILE", "prod");
        std::env::set_var("OPENAPI_SEAL_ROOT_HEX", "aa".repeat(32));
        std::env::remove_var("OPENAPI_TLS_KEY_PATH");
        let err = assert_acme_ceremony_policy(false).unwrap_err().to_string();
        assert!(err.contains("OPENAPI_SEAL_ROOT_HEX"));
        std::env::remove_var("OPENAPI_PROFILE");
        std::env::remove_var("OPENAPI_SEAL_ROOT_HEX");
    }

    #[test]
    fn policy_allows_lab_staging() {
        let _g = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("OPENAPI_PROFILE", "dev");
        std::env::remove_var("OPENAPI_TLS_KEY_PATH");
        std::env::remove_var("OPENAPI_SEAL_ROOT_HEX");
        assert_acme_ceremony_policy(true).unwrap();
        std::env::remove_var("OPENAPI_PROFILE");
    }

    #[test]
    fn seal_from_acme_memory_path_host_stub() {
        let sealer = SgxSealer::new("mr-acme-test");
        let mut key =
            String::from("-----BEGIN PRIVATE KEY-----\nacme\n-----END PRIVATE KEY-----\n");
        let cert = "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n";
        let (sealed, cert_out) =
            seal_from_acme_outcome(&sealer, &mut key, cert, None).unwrap();
        assert!(key.is_empty() || key.as_bytes().iter().all(|&b| b == 0));
        assert_eq!(cert_out, cert);
        let blob: openapi_platform::SealedTlsKeyBlob =
            serde_json::from_slice(&sealed).unwrap();
        // Host stub uses seal_version 1; must unseal with same sealer.
        let pem = sealer.unseal_tls_key(&blob, None).unwrap();
        assert!(std::str::from_utf8(&pem).unwrap().contains("PRIVATE KEY"));
    }

    #[test]
    fn helper_dns_and_challenge_against_fixture() {
        let tmp = std::env::temp_dir().join(format!(
            "sgx-acme-helper-fixture-{}",
            std::process::id()
        ));
        let webroot = tmp.join("www");
        let artifact_dir = tmp.join("art");
        std::fs::create_dir_all(webroot.join(".well-known/acme-challenge")).unwrap();
        std::fs::create_dir_all(&artifact_dir).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(FixtureState {
            webroot: webroot.clone(),
            artifact_dir: artifact_dir.clone(),
        });
        let state_bg = Arc::clone(&state);
        let _bg = thread::spawn(move || {
            for _ in 0..16 {
                let Ok((stream, _)) = listener.accept() else {
                    break;
                };
                let _ = fixture_handle(&state_bg, stream);
            }
        });

        let client =
            CeremonyHelperClient::from_url(&format!("http://{}", addr)).unwrap();

        // DNS: fixture returns 127.0.0.1:443
        let resolved = client.resolve_dns("example.test", 443).unwrap();
        assert_eq!(resolved.ip().to_string(), "127.0.0.1");
        assert_eq!(resolved.port(), 443);

        let dns = HelperDnsResolver::new(client.clone());
        let a = dns.resolve("example.test", 8443).unwrap();
        assert_eq!(a.port(), 8443);

        let sink = HelperChallengeSink::new(client.clone());
        sink.place("tok1", "auth1").unwrap();
        let path = webroot.join(".well-known/acme-challenge/tok1");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "auth1");
        sink.clear("tok1").unwrap();
        assert!(!path.exists());

        client.put_artifact("tls.crt", b"CERT").unwrap();
        assert_eq!(client.get_artifact("tls.crt").unwrap(), b"CERT");

        let relay = HelperHttpsRelayTransport::new(client.clone());
        let rsp = relay
            .request(
                "GET",
                "https://acme-staging-v02.api.letsencrypt.org/directory",
                None,
                None,
            )
            .unwrap();
        assert_eq!(rsp.status, 200);
        assert!(rsp.header("content-type").is_some() || !rsp.body.is_empty());
        let body = String::from_utf8_lossy(&rsp.body);
        assert!(body.contains("newNonce") || body.contains("relay-ok"));

        let _ = std::fs::remove_dir_all(tmp);
    }

    struct FixtureState {
        webroot: PathBuf,
        artifact_dir: PathBuf,
    }

    fn fixture_handle(state: &FixtureState, mut stream: TcpStream) -> anyhow::Result<()> {
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        let header_end = loop {
            let n = stream.read(&mut tmp)?;
            if n == 0 {
                break buf.len();
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
        };
        let cl = {
            let header = std::str::from_utf8(&buf[..header_end.min(buf.len())]).unwrap_or("");
            header
                .lines()
                .find_map(|line| {
                    let (k, v) = line.split_once(':')?;
                    if k.eq_ignore_ascii_case("content-length") {
                        v.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0)
        };
        while buf.len() < header_end + cl {
            let n = stream.read(&mut tmp)?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        let req = String::from_utf8_lossy(&buf);
        let request_line = req.lines().next().unwrap_or("");
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("").split('?').next().unwrap_or("");

        let (status, body) = if method == "GET" && path == "/dns" {
            (
                200u16,
                br#"{"addrs":["127.0.0.1:443"]}"#.to_vec(),
            )
        } else if method == "POST" && path == "/https-relay" {
            // Fixture does not call the public internet; echo a tiny ACME-like body.
            let resp = serde_json::json!({
                "status": 200u16,
                "headers": {
                    "content-type": "application/json",
                    "replay-nonce": "fixture-nonce"
                },
                "body_b64": base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    br#"{"newNonce":"https://example/new-nonce","relay-ok":true}"#,
                ),
            });
            (200, serde_json::to_vec(&resp).unwrap())
        } else if method == "PUT" && path.starts_with("/acme-challenge/") {
            let token = &path["/acme-challenge/".len()..];
            let p = state
                .webroot
                .join(".well-known/acme-challenge")
                .join(token);
            std::fs::write(&p, &buf[header_end..])?;
            (200, b"ok".to_vec())
        } else if method == "DELETE" && path.starts_with("/acme-challenge/") {
            let token = &path["/acme-challenge/".len()..];
            let p = state
                .webroot
                .join(".well-known/acme-challenge")
                .join(token);
            let _ = std::fs::remove_file(&p);
            (200, b"ok".to_vec())
        } else if method == "PUT" && path.starts_with("/artifacts/") {
            let name = &path["/artifacts/".len()..];
            std::fs::write(state.artifact_dir.join(name), &buf[header_end..])?;
            (200, b"ok".to_vec())
        } else if method == "GET" && path.starts_with("/artifacts/") {
            let name = &path["/artifacts/".len()..];
            let data = std::fs::read(state.artifact_dir.join(name))?;
            (200, data)
        } else {
            (404, b"not found".to_vec())
        };

        let header = format!(
            "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(header.as_bytes())?;
        stream.write_all(&body)?;
        stream.flush()?;
        Ok(())
    }
}
