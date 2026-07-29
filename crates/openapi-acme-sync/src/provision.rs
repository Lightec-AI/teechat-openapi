//! HTTP-01 certificate provisioning orchestration.

use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use zeroize::Zeroize;

use crate::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Error, Identifier, NewAccount,
    NewOrder, OrderStatus,
};
use crate::https::DnsResolver;

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
    resolver: Arc<dyn DnsResolver>,
    sink: &dyn Http01ChallengeSink,
    req: ProvisionRequest,
) -> Result<ProvisionOutcome, Error> {
    if !req.directory_url.starts_with("https://") {
        return Err(Error::Str("directory URL must use HTTPS"));
    }

    let domain = req.domain.clone();
    let (account, account_credentials_json) =
        open_or_create_account(resolver, &req, AccountOpener::Default)?;

    finish_provision(
        sink,
        domain,
        account,
        account_credentials_json,
    )
}

#[cfg(test)]
pub(crate) fn provision_http01_with_roots(
    resolver: Arc<dyn DnsResolver>,
    roots: rustls::RootCertStore,
    sink: &dyn Http01ChallengeSink,
    req: ProvisionRequest,
) -> Result<ProvisionOutcome, Error> {
    if !req.directory_url.starts_with("https://") {
        return Err(Error::Str("directory URL must use HTTPS"));
    }

    let domain = req.domain.clone();
    let (account, account_credentials_json) =
        open_or_create_account(resolver, &req, AccountOpener::CustomRoots(roots))?;

    finish_provision(
        sink,
        domain,
        account,
        account_credentials_json,
    )
}

enum AccountOpener {
    Default,
    #[cfg(test)]
    CustomRoots(rustls::RootCertStore),
}

fn open_or_create_account(
    resolver: Arc<dyn DnsResolver>,
    req: &ProvisionRequest,
    opener: AccountOpener,
) -> Result<(Account, String), Error> {
    if let Some(json) = req.account_credentials_json.as_ref() {
        let creds: AccountCredentials = serde_json::from_str(json)?;
        return Ok((
            Account::from_credentials(creds, resolver)?,
            json.clone(),
        ));
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

    let (account, credentials) = match opener {
        AccountOpener::Default => Account::create(
            &new_account,
            &req.directory_url,
            None,
            resolver,
        )?,
        #[cfg(test)]
        AccountOpener::CustomRoots(roots) => Account::create_with_roots(
            &new_account,
            &req.directory_url,
            None,
            resolver,
            roots,
        )?,
    };

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
) -> Result<ProvisionOutcome, Error> {
    let identifier = Identifier::Dns(domain.clone());
    let mut order = account.new_order(&NewOrder {
        identifiers: &[identifier],
    })?;

    if !matches!(order.state().status, OrderStatus::Pending) {
        return Err(Error::Str("expected pending order"));
    }

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

    let key_pair = KeyPair::generate().map_err(|e| Error::Http(e.to_string()))?;
    let mut params = CertificateParams::new(vec![domain])
        .map_err(|e| Error::Http(e.to_string()))?;
    params.distinguished_name = DistinguishedName::new();
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| Error::Http(e.to_string()))?;
    let csr_der = csr.der().to_vec();

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

    for token in tokens {
        sink.clear(&token)?;
    }

    Ok(ProvisionOutcome {
        private_key_pem: key_pair.serialize_pem(),
        certificate_chain_pem: cert_chain_pem,
        account_credentials_json,
    })
}
