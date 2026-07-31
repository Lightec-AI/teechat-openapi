//! HTTP-01 certificate provisioning orchestration.

use std::str::FromStr;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use p256::ecdsa::{DerSignature, SigningKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rand_core::OsRng;
use x509_cert::builder::{Builder, RequestBuilder};
use x509_cert::der::asn1::Ia5String;
use x509_cert::der::Encode;
use x509_cert::ext::pkix::{name::GeneralName, SubjectAltName};
use x509_cert::name::Name;
use zeroize::Zeroize;

use crate::https::AcmeTransport;
use crate::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Error, Identifier, NewAccount,
    NewOrder, OrderStatus,
};

/// Pluggable hook to publish HTTP-01 challenge responses.
pub trait Http01ChallengeSink: Send + Sync {
    /// Publish `key_authorization` for the given challenge `token`.
    fn place(&self, token: &str, key_authorization: &str) -> Result<(), Error>;
    /// Remove a previously published challenge response.
    fn clear(&self, token: &str) -> Result<(), Error>;
}

/// In-memory challenge sink for unit tests.
#[derive(Default)]
pub struct MemoryChallengeSink {
    entries: std::sync::Mutex<std::collections::HashMap<String, String>>,
    placed: std::sync::Mutex<Vec<String>>,
    cleared: std::sync::Mutex<Vec<String>>,
}

impl MemoryChallengeSink {
    /// Create an empty sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Tokens passed to [`Self::place`].
    pub fn placed_tokens(&self) -> Vec<String> {
        self.placed.lock().unwrap().clone()
    }

    /// Tokens passed to [`Self::clear`].
    pub fn cleared_tokens(&self) -> Vec<String> {
        self.cleared.lock().unwrap().clone()
    }

    /// Look up a stored key authorization by token.
    pub fn get(&self, token: &str) -> Option<String> {
        self.entries.lock().unwrap().get(token).cloned()
    }
}

impl Http01ChallengeSink for MemoryChallengeSink {
    fn place(&self, token: &str, key_authorization: &str) -> Result<(), Error> {
        self.entries
            .lock()
            .unwrap()
            .insert(token.to_owned(), key_authorization.to_owned());
        self.placed.lock().unwrap().push(token.to_owned());
        Ok(())
    }

    fn clear(&self, token: &str) -> Result<(), Error> {
        self.entries.lock().unwrap().remove(token);
        self.cleared.lock().unwrap().push(token.to_owned());
        Ok(())
    }
}

/// Inputs for a single HTTP-01 issuance run.
pub struct ProvisionRequest {
    /// DNS identifier to certify.
    pub domain: String,
    /// ACME directory URL (must be `https://`).
    pub directory_url: String,
    /// Optional contact email (`mailto:` added automatically).
    pub email: Option<String>,
    /// Existing account credentials JSON, or `None` to create a new account.
    pub account_credentials_json: Option<String>,
    /// Reuse an existing leaf private key PEM (renew). `None` → generate a new key (issue).
    pub existing_private_key_pem: Option<String>,
}

/// Successful HTTP-01 provisioning result.
pub struct ProvisionOutcome {
    /// Leaf private key PEM (zeroed on drop).
    pub private_key_pem: String,
    /// Issued certificate chain PEM.
    pub certificate_chain_pem: String,
    /// Serialized [`AccountCredentials`] for reuse.
    pub account_credentials_json: String,
}

impl Drop for ProvisionOutcome {
    fn drop(&mut self) {
        self.private_key_pem.zeroize();
    }
}

/// Run the full HTTP-01 ACME flow against `directory_url`.
pub fn provision_http01(
    transport: Arc<dyn AcmeTransport>,
    sink: &dyn Http01ChallengeSink,
    req: ProvisionRequest,
) -> Result<ProvisionOutcome, Error> {
    if !req.directory_url.starts_with("https://") {
        return Err(Error::Str("directory URL must use HTTPS"));
    }

    let domain = req.domain.clone();
    let (account, account_credentials_json) = open_or_create_account(transport, &req)?;

    finish_provision(
        sink,
        domain,
        account,
        account_credentials_json,
        req.existing_private_key_pem,
    )
}

fn open_or_create_account(
    transport: Arc<dyn AcmeTransport>,
    req: &ProvisionRequest,
) -> Result<(Account, String), Error> {
    if let Some(json) = req.account_credentials_json.as_ref() {
        let creds: AccountCredentials = serde_json::from_str(json)?;
        return Ok((Account::from_credentials(creds, transport)?, json.clone()));
    }

    let contact = match &req.email {
        Some(email) => vec![format!("mailto:{email}")],
        None => vec![],
    };
    let contact_refs: Vec<&str> = contact.iter().map(String::as_str).collect();
    let new_account = NewAccount {
        contact: &contact_refs,
        terms_of_service_agreed: true,
        only_return_existing: false,
    };

    let (account, credentials) =
        Account::create(&new_account, &req.directory_url, None, transport)?;

    Ok((
        account,
        serde_json::to_string(&credentials).map_err(Error::from)?,
    ))
}

fn finish_provision(
    sink: &dyn Http01ChallengeSink,
    domain: String,
    account: Account,
    account_credentials_json: String,
    existing_private_key_pem: Option<String>,
) -> Result<ProvisionOutcome, Error> {
    let identifier = Identifier::Dns(domain.clone());
    let mut order = account.new_order(&NewOrder {
        identifiers: &[identifier],
    })?;

    // Fresh orders are Pending; re-issue after a recent cert may open Ready
    // (authorizations still valid) — skip HTTP-01 in that case.
    match order.state().status {
        OrderStatus::Pending => {
            let authorizations = order.authorizations()?;
            let mut challenge_urls = Vec::new();
            let mut tokens = Vec::new();

            for authz in &authorizations {
                match authz.status {
                    AuthorizationStatus::Pending => {}
                    AuthorizationStatus::Valid => continue,
                    _ => return Err(Error::Str("unexpected authorization status")),
                }

                let challenge = authz
                    .challenges
                    .iter()
                    .find(|c| c.r#type == ChallengeType::Http01)
                    .ok_or(Error::Str("no http-01 challenge found"))?;

                let key_auth = order.key_authorization(challenge);
                sink.place(&challenge.token, key_auth.as_str())?;
                tokens.push(challenge.token.clone());
                challenge_urls.push(challenge.url.clone());
            }

            for url in &challenge_urls {
                order.set_challenge_ready(url)?;
            }

            let mut tries = 1u8;
            let mut delay = Duration::from_millis(250);
            loop {
                sleep(delay);
                order.refresh()?;
                let status = order.state().status;
                if status == OrderStatus::Invalid {
                    return Err(Error::Str("order is invalid"));
                }
                if matches!(status, OrderStatus::Ready | OrderStatus::Valid) {
                    break;
                }
                delay *= 2;
                tries += 1;
                if tries >= 5 {
                    return Err(Error::Str("order not ready"));
                }
            }

            for token in tokens {
                sink.clear(&token)?;
            }
        }
        OrderStatus::Ready | OrderStatus::Valid => {}
        OrderStatus::Invalid => return Err(Error::Str("order is invalid")),
        _ => return Err(Error::Str("unexpected order status")),
    }

    let (private_key_pem, csr_der) = match existing_private_key_pem {
        Some(pem) => csr_from_private_key_pem(&domain, &pem)?,
        None => generate_p256_key_and_csr(&domain)?,
    };

    order.finalize(&csr_der)?;

    let mut tries = 0u8;
    let cert_chain_pem = loop {
        if let Some(pem) = order.certificate()? {
            break pem;
        }
        sleep(Duration::from_secs(1));
        tries += 1;
        if tries > 10 {
            return Err(Error::Str("no certificate received"));
        }
    };

    Ok(ProvisionOutcome {
        private_key_pem,
        certificate_chain_pem: cert_chain_pem,
        account_credentials_json,
    })
}

/// Generate a PKCS#8 P-256 leaf key + PKCS#10 CSR (pure RustCrypto; no ring/rcgen).
fn generate_p256_key_and_csr(domain: &str) -> Result<(String, Vec<u8>), Error> {
    let signing_key = SigningKey::random(&mut OsRng);
    let private_key_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| Error::CryptoKey(e.to_string()))?
        .to_string();
    let csr_der = build_csr_der(domain, &signing_key)?;
    Ok((private_key_pem, csr_der))
}

/// Build a CSR for an existing PKCS#8 P-256 private key PEM (stable-key renew).
fn csr_from_private_key_pem(
    domain: &str,
    private_key_pem: &str,
) -> Result<(String, Vec<u8>), Error> {
    let signing_key = SigningKey::from_pkcs8_pem(private_key_pem)
        .map_err(|e| Error::CryptoKey(format!("decode existing leaf key: {e}")))?;
    let csr_der = build_csr_der(domain, &signing_key)?;
    Ok((private_key_pem.to_owned(), csr_der))
}

fn build_csr_der(domain: &str, signing_key: &SigningKey) -> Result<Vec<u8>, Error> {
    let subject = Name::from_str(&format!("CN={domain}"))
        .map_err(|e| Error::Http(format!("csr subject: {e}")))?;
    let mut builder = RequestBuilder::new(subject, signing_key)
        .map_err(|e| Error::Http(format!("csr builder: {e}")))?;
    let dns = Ia5String::new(domain).map_err(|e| Error::Http(format!("csr san: {e}")))?;
    builder
        .add_extension(&SubjectAltName(vec![GeneralName::DnsName(dns)]))
        .map_err(|e| Error::Http(format!("csr san ext: {e}")))?;
    let csr = builder
        .build::<DerSignature>()
        .map_err(|e| Error::Http(format!("csr sign: {e}")))?;
    csr.to_der()
        .map_err(|e| Error::Http(format!("csr der: {e}")))
}
