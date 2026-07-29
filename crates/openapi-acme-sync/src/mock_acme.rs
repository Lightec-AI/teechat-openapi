//! Localhost HTTPS mock ACME directory for unit tests.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rcgen::{CertificateParams, DistinguishedName, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};

use crate::https::{ensure_crypto_provider, AcmeTransport, FnDnsResolver, HttpsTransport};
use crate::provision::{provision_http01, Http01ChallengeSink, MemoryChallengeSink, ProvisionRequest};
use crate::{Account, AccountCredentials, Error, NewAccount};

static NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Default)]
struct MockState {
    challenge_ready: bool,
    finalized: bool,
}

pub(crate) struct MockAcmeServer {
    pub base_url: String,
    pub cert_der: CertificateDer<'static>,
    _handle: JoinHandle<()>,
}

impl MockAcmeServer {
    pub(crate) fn start() -> Result<Self, Error> {
        ensure_crypto_provider();

        let key_pair = KeyPair::generate().map_err(|e| Error::Http(e.to_string()))?;
        let mut params = CertificateParams::new(vec!["localhost".into()])
            .map_err(|e| Error::Http(e.to_string()))?;
        params.distinguished_name = DistinguishedName::new();
        params
            .subject_alt_names
            .push(SanType::DnsName("localhost".try_into().map_err(|e| {
                Error::Http(format!("san: {e}"))
            })?));
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| Error::Http(e.to_string()))?;
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());

        let server_config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der.clone()], key_der)
                .map_err(|e| Error::Http(e.to_string()))?,
        );

        let listener = TcpListener::bind("127.0.0.1:0").map_err(Error::HttpIo)?;
        let port = listener.local_addr().map_err(Error::HttpIo)?.port();
        let base_url = format!("https://localhost:{port}");
        let base_url_for_thread = base_url.clone();
        let state = Arc::new(Mutex::new(MockState::default()));

        let handle = thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let cfg = Arc::clone(&server_config);
                let state = Arc::clone(&state);
                let base = base_url_for_thread.clone();
                let _ = serve_connection(stream, cfg, state, &base);
            }
        });

        thread::sleep(Duration::from_millis(50));

        Ok(Self {
            base_url,
            cert_der,
            _handle: handle,
        })
    }

    pub(crate) fn directory_url(&self) -> String {
        format!("{}/directory", self.base_url)
    }

    pub(crate) fn resolver(&self) -> Arc<FnDnsResolver> {
        let port: u16 = self
            .base_url
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse().ok())
            .expect("mock port");
        Arc::new(FnDnsResolver::new(move |host, _port| {
            if host == "localhost" {
                Ok(SocketAddr::from(([127, 0, 0, 1], port)))
            } else {
                Err(Error::Str("unknown host"))
            }
        }))
    }

    pub(crate) fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots
            .add(self.cert_der.clone())
            .expect("add mock root");
        roots
    }

    pub(crate) fn transport(&self) -> Arc<dyn AcmeTransport> {
        Arc::new(HttpsTransport::with_roots(self.resolver(), self.roots()))
    }
}

fn serve_connection(
    stream: TcpStream,
    config: Arc<ServerConfig>,
    state: Arc<Mutex<MockState>>,
    base_url: &str,
) -> Result<(), Error> {
    let conn = ServerConnection::new(config).map_err(|e| Error::Http(e.to_string()))?;
    let mut tls = StreamOwned::new(conn, stream);

    let request = read_http_request(&mut tls)?;
    let (method, path) = parse_request_line(&request)?;
    let response = route_request(method, path, state, base_url)?;
    tls.write_all(response.as_bytes()).map_err(Error::HttpIo)?;
    tls.flush().map_err(Error::HttpIo)?;
    Ok(())
}

fn read_http_request<R: Read>(reader: &mut R) -> Result<String, Error> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = reader.read(&mut tmp).map_err(Error::HttpIo)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 65536 {
            return Err(Error::Str("request too large"));
        }
    }
    if buf.is_empty() {
        return Err(Error::Str("empty request"));
    }
    String::from_utf8(buf).map_err(|_| Error::Str("invalid request encoding"))
}

fn parse_request_line(request: &str) -> Result<(&str, &str), Error> {
    let line = request.lines().next().ok_or(Error::Str("empty request"))?;
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or(Error::Str("missing method"))?;
    let path = parts.next().ok_or(Error::Str("missing path"))?;
    Ok((method, path))
}

fn route_request(
    method: &str,
    path: &str,
    state: Arc<Mutex<MockState>>,
    base_url: &str,
) -> Result<String, Error> {
    let nonce = format!("nonce-{}", NONCE.fetch_add(1, Ordering::Relaxed));
    match (method, path) {
        ("GET", "/directory") => Ok(json_response(
            200,
            &format!(
                r#"{{"newNonce":"{base_url}/new-nonce","newAccount":"{base_url}/new-account","newOrder":"{base_url}/new-order","revokeCert":"{base_url}/revoke-cert"}}"#
            ),
            None,
        )),
        ("HEAD", "/new-nonce") => Ok(empty_response(200, Some(&nonce), None)),
        ("POST", "/new-account") => Ok(empty_response(
            201,
            Some(&nonce),
            Some(&format!("{base_url}/account/1")),
        )),
        ("POST", "/new-order") => Ok(json_response(
            201,
            &format!(
                r#"{{"status":"pending","authorizations":["{base_url}/authz/1"],"finalize":"{base_url}/finalize","certificate":null}}"#
            ),
            Some(&format!("{base_url}/order/1")),
        )),
        ("GET", "/authz/1") | ("POST", "/authz/1") => Ok(json_response(
            200,
            &format!(
                r#"{{"identifier":{{"type":"dns","value":"example.test"}},"status":"pending","challenges":[{{"type":"http-01","url":"{base_url}/challenge/1","token":"tok123","status":"pending"}}]}}"#
            ),
            None,
        )),
        ("POST", "/challenge/1") => {
            state.lock().unwrap().challenge_ready = true;
            Ok(json_response(
                200,
                &format!(
                    r#"{{"type":"http-01","url":"{base_url}/challenge/1","token":"tok123","status":"processing"}}"#
                ),
                None,
            ))
        }
        ("POST", "/order/1") => {
            let st = state.lock().unwrap();
            if st.finalized {
                Ok(json_response(
                    200,
                    &format!(
                        r#"{{"status":"valid","authorizations":["{base_url}/authz/1"],"finalize":"{base_url}/finalize","certificate":"{base_url}/cert/1","error":null}}"#
                    ),
                    None,
                ))
            } else if st.challenge_ready {
                Ok(json_response(
                    200,
                    &format!(
                        r#"{{"status":"ready","authorizations":["{base_url}/authz/1"],"finalize":"{base_url}/finalize","certificate":null,"error":null}}"#
                    ),
                    None,
                ))
            } else {
                Ok(json_response(
                    200,
                    r#"{"status":"pending","authorizations":[],"finalize":"","certificate":null,"error":null}"#,
                    None,
                ))
            }
        }
        ("POST", "/finalize") => {
            state.lock().unwrap().finalized = true;
            Ok(json_response(
                200,
                &format!(
                    r#"{{"status":"processing","authorizations":["{base_url}/authz/1"],"finalize":"{base_url}/finalize","certificate":null,"error":null}}"#
                ),
                None,
            ))
        }
        ("POST", "/cert/1") => Ok(pem_response(
            200,
            "-----BEGIN CERTIFICATE-----\nMOCKCERT\n-----END CERTIFICATE-----\n",
        )),
        _ => Ok(empty_response(404, Some(&nonce), None)),
    }
}

fn json_response(status: u16, body: &str, location: Option<&str>) -> String {
    let nonce = format!("nonce-{}", NONCE.fetch_add(1, Ordering::Relaxed));
    let mut headers = format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nReplay-Nonce: {nonce}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(loc) = location {
        headers.push_str(&format!("Location: {loc}\r\n"));
    }
    format!("{headers}\r\n{body}")
}

fn pem_response(status: u16, body: &str) -> String {
    let nonce = format!("nonce-{}", NONCE.fetch_add(1, Ordering::Relaxed));
    format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: application/pem-certificate-chain\r\nReplay-Nonce: {nonce}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn empty_response(status: u16, nonce: Option<&str>, location: Option<&str>) -> String {
    let mut headers =
        format!("HTTP/1.1 {status} OK\r\nContent-Length: 0\r\nConnection: close\r\n");
    if let Some(n) = nonce {
        headers.push_str(&format!("Replay-Nonce: {n}\r\n"));
    }
    if let Some(loc) = location {
        headers.push_str(&format!("Location: {loc}\r\n"));
    }
    format!("{headers}\r\n")
}

#[test]
fn full_provision_http01_against_mock() -> Result<(), Error> {
    let server = MockAcmeServer::start()?;
    let sink = MemoryChallengeSink::new();
    let outcome = provision_http01(
        server.transport(),
        &sink,
        ProvisionRequest {
            domain: "example.test".into(),
            directory_url: server.directory_url(),
            email: Some("admin@example.test".into()),
            account_credentials_json: None,
            existing_private_key_pem: None,
        },
    )?;

    assert!(outcome.certificate_chain_pem.contains("MOCKCERT"));
    assert!(!outcome.private_key_pem.is_empty());
    assert!(outcome.account_credentials_json.contains("directory"));
    assert_eq!(sink.placed_tokens(), vec!["tok123"]);
    assert_eq!(sink.cleared_tokens(), vec!["tok123"]);
    assert!(sink.get("tok123").is_none());
    Ok(())
}

#[test]
fn renew_reuses_existing_leaf_key() -> Result<(), Error> {
    let server = MockAcmeServer::start()?;
    let sink = MemoryChallengeSink::new();
    let first = provision_http01(
        server.transport(),
        &sink,
        ProvisionRequest {
            domain: "example.test".into(),
            directory_url: server.directory_url(),
            email: Some("admin@example.test".into()),
            account_credentials_json: None,
            existing_private_key_pem: None,
        },
    )?;
    let leaf_pem = first.private_key_pem.clone();
    let account = first.account_credentials_json.clone();

    let second = provision_http01(
        server.transport(),
        &MemoryChallengeSink::new(),
        ProvisionRequest {
            domain: "example.test".into(),
            directory_url: server.directory_url(),
            email: None,
            account_credentials_json: Some(account),
            existing_private_key_pem: Some(leaf_pem.clone()),
        },
    )?;
    assert_eq!(second.private_key_pem, leaf_pem);
    assert!(second.certificate_chain_pem.contains("MOCKCERT"));
    Ok(())
}

#[test]
fn reject_non_https_directory_url() {
    let sink = MemoryChallengeSink::new();
    let err = provision_http01(
        Arc::new(HttpsTransport::with_std_dns()),
        &sink,
        ProvisionRequest {
            domain: "example.test".into(),
            directory_url: "http://example.test/directory".into(),
            email: None,
            account_credentials_json: None,
            existing_private_key_pem: None,
        },
    )
    .err()
    .expect("expected error");
    assert!(matches!(err, Error::Str("directory URL must use HTTPS")));
}

#[test]
fn challenge_sink_place_and_clear() -> Result<(), Error> {
    let sink = MemoryChallengeSink::new();
    sink.place("tok", "auth.val")?;
    assert_eq!(sink.get("tok").as_deref(), Some("auth.val"));
    sink.clear("tok")?;
    assert!(sink.get("tok").is_none());
    assert_eq!(sink.placed_tokens(), vec!["tok"]);
    assert_eq!(sink.cleared_tokens(), vec!["tok"]);
    Ok(())
}

#[test]
fn credentials_deserialize_roundtrip() -> Result<(), Error> {
    let server = MockAcmeServer::start()?;

    let (_account, credentials) = Account::create(
        &NewAccount {
            contact: &[],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        &server.directory_url(),
        None,
        server.transport(),
    )?;
    let json = serde_json::to_string(&credentials)?;
    let parsed: AccountCredentials = serde_json::from_str(&json)?;
    assert_eq!(parsed.id, credentials.id);
    assert_eq!(parsed.key_pkcs8, credentials.key_pkcs8);
    Ok(())
}
