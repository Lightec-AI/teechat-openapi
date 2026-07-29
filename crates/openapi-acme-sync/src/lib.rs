//! Sync pure-Rust ACME (RFC 8555) client.
//!
//! Derived from [small-acme](https://github.com/Icelk/small-acme) /
//! [instant-acme](https://github.com/InstantDomain/instant-acme) (Apache-2.0),
//! adapted for Fortanix EDP: pluggable [`AcmeTransport`] (direct rustls/`TcpStream`
//! with DNS, or host ceremony-helper HTTPS relay).

#![warn(unreachable_pub)]
#![warn(missing_docs)]

use std::fmt;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as EcdsaSignature, SigningKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rand_core::OsRng;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

mod https;
mod provision;
#[cfg(test)]
mod mock_acme;

pub use https::{
    AcmeTransport, DnsResolver, FnAcmeTransport, FnDnsResolver, HttpResponse, HttpsTransport,
    StdDnsResolver,
};
pub use provision::{
    provision_http01, Http01ChallengeSink, MemoryChallengeSink, ProvisionOutcome,
    ProvisionRequest,
};

mod types;
pub use types::{
    AccountCredentials, Authorization, AuthorizationStatus, Challenge, ChallengeType, Error,
    Identifier, LetsEncrypt, NewAccount, NewOrder, OrderState, OrderStatus, Problem,
    RevocationReason, RevocationRequest, ZeroSsl,
};
use types::{
    DirectoryUrls, Empty, FinalizeRequest, Header, JoseJson, Jwk, KeyOrKeyId, NewAccountPayload,
    Signer, SigningAlgorithm,
};

/// An ACME order as described in RFC 8555 (section 7.1.3)
///
/// An order is created from an [`Account`] by calling [`Account::new_order()`]. The `Order`
/// type represents the stable identity of an order, while the [`Order::state()`] method
/// gives you access to the current state of the order according to the server.
///
/// <https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.3>
pub struct Order {
    account: Arc<AccountInner>,
    nonce: Option<String>,
    url: String,
    state: OrderState,
}

impl Order {
    /// Retrieve the authorizations for this order
    pub fn authorizations(&mut self) -> Result<Vec<Authorization>, Error> {
        let mut authorizations = Vec::with_capacity(self.state.authorizations.len());
        for url in &self.state.authorizations {
            authorizations.push(self.account.get(&mut self.nonce, url)?);
        }
        Ok(authorizations)
    }

    /// Create a [`KeyAuthorization`] for the given [`Challenge`]
    pub fn key_authorization(&self, challenge: &Challenge) -> KeyAuthorization {
        KeyAuthorization::new(challenge, &self.account.key)
    }

    /// Request a certificate from the given Certificate Signing Request (CSR)
    pub fn finalize(&mut self, csr_der: &[u8]) -> Result<(), Error> {
        let rsp = self.account.post(
            Some(&FinalizeRequest::new(csr_der)),
            self.nonce.take(),
            &self.state.finalize,
        )?;

        self.nonce = nonce_from_response(&rsp);
        self.state = Problem::check::<OrderState>(rsp)?;
        Ok(())
    }

    /// Get the certificate for this order
    pub fn certificate(&mut self) -> Result<Option<String>, Error> {
        if matches!(self.state.status, OrderStatus::Processing) {
            let rsp = self
                .account
                .post(None::<&Empty>, self.nonce.take(), &self.url)?;
            self.nonce = nonce_from_response(&rsp);
            self.state = Problem::check::<OrderState>(rsp)?;
        }

        if let Some(error) = &self.state.error {
            return Err(Error::Api(error.clone()));
        } else if self.state.status == OrderStatus::Processing {
            return Ok(None);
        } else if self.state.status != OrderStatus::Valid {
            return Err(Error::Str("invalid order state"));
        }

        let cert_url = match &self.state.certificate {
            Some(cert_url) => cert_url,
            None => return Err(Error::Str("no certificate URL found")),
        };

        let rsp = self
            .account
            .post(None::<&Empty>, self.nonce.take(), cert_url)?;

        self.nonce = nonce_from_response(&rsp);
        let body = Problem::from_response(rsp)?;
        Ok(Some(
            String::from_utf8(body.to_vec())
                .map_err(|_| Error::Str("unable to decode certificate as UTF-8"))?,
        ))
    }

    /// Notify the server that the given challenge is ready to be completed
    pub fn set_challenge_ready(&mut self, challenge_url: &str) -> Result<(), Error> {
        let rsp = self
            .account
            .post(Some(&Empty {}), self.nonce.take(), challenge_url)?;

        self.nonce = nonce_from_response(&rsp);
        let _ = Problem::check::<Challenge>(rsp)?;
        Ok(())
    }

    /// Get the current state of the given challenge
    pub fn challenge(&mut self, challenge_url: &str) -> Result<Challenge, Error> {
        self.account.get(&mut self.nonce, challenge_url)
    }

    /// Refresh the current state of the order
    pub fn refresh(&mut self) -> Result<&OrderState, Error> {
        let rsp = self
            .account
            .post(None::<&Empty>, self.nonce.take(), &self.url)?;

        self.nonce = nonce_from_response(&rsp);
        self.state = Problem::check::<OrderState>(rsp)?;
        Ok(&self.state)
    }

    /// Get the last known state of the order
    pub fn state(&mut self) -> &OrderState {
        &self.state
    }

    /// Get the URL of the order
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// An ACME account as described in RFC 8555 (section 7.1.2)
#[derive(Clone)]
pub struct Account {
    inner: Arc<AccountInner>,
}

impl Account {
    /// Restore an existing account from serialized credentials.
    pub fn from_credentials(
        credentials: AccountCredentials,
        transport: Arc<dyn AcmeTransport>,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: Arc::new(AccountInner::from_credentials(credentials, transport)?),
        })
    }

    /// Restore an existing account from ID, PKCS#8 key, and directory URL.
    pub fn from_parts(
        id: String,
        key_pkcs8_der: &[u8],
        directory_url: &str,
        transport: Arc<dyn AcmeTransport>,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: Arc::new(AccountInner {
                id,
                key: Key::from_pkcs8_der(key_pkcs8_der)?,
                client: Client::new(directory_url, transport)?,
            }),
        })
    }

    /// Create a new ACME account.
    pub fn create(
        account: &NewAccount<'_>,
        server_url: &str,
        external_account: Option<&ExternalAccountKey>,
        transport: Arc<dyn AcmeTransport>,
    ) -> Result<(Account, AccountCredentials), Error> {
        Self::create_inner(
            account,
            external_account,
            Client::new(server_url, transport)?,
            server_url,
        )
    }

    fn create_inner(
        account: &NewAccount<'_>,
        external_account: Option<&ExternalAccountKey>,
        client: Client,
        server_url: &str,
    ) -> Result<(Account, AccountCredentials), Error> {
        let (key, key_pkcs8) = Key::generate()?;
        let payload = NewAccountPayload {
            new_account: account,
            external_account_binding: external_account
                .map(|eak| {
                    JoseJson::new(
                        Some(&Jwk::new(&key.inner)),
                        eak.header(None, &client.urls.new_account),
                        eak,
                    )
                })
                .transpose()?,
        };

        let rsp = client.post(Some(&payload), None, &key, &client.urls.new_account)?;

        let account_url = rsp.header("Location").map(|s| s.to_owned());

        let _ = Problem::from_response(rsp)?;
        let id = account_url.ok_or(Error::Str("failed to get account URL"))?;
        let credentials = AccountCredentials {
            id: id.clone(),
            key_pkcs8,
            directory: Some(server_url.to_owned()),
            urls: None,
        };

        let account = AccountInner {
            client,
            key,
            id: id.clone(),
        };

        Ok((
            Self {
                inner: Arc::new(account),
            },
            credentials,
        ))
    }

    /// Create a new order based on the given [`NewOrder`]
    pub fn new_order(&self, order: &NewOrder<'_>) -> Result<Order, Error> {
        let rsp = self
            .inner
            .post(Some(order), None, &self.inner.client.urls.new_order)?;

        let nonce = nonce_from_response(&rsp);
        let order_url = rsp.header("Location").map(|s| s.to_owned());

        Ok(Order {
            account: self.inner.clone(),
            nonce,
            state: Problem::check::<OrderState>(rsp)?,
            url: order_url.ok_or(Error::Str("no order URL found"))?,
        })
    }

    /// Revokes a previously issued certificate
    pub fn revoke<'a>(&'a self, payload: &RevocationRequest<'a>) -> Result<(), Error> {
        let rsp = self
            .inner
            .post(Some(payload), None, &self.inner.client.urls.revoke_cert)?;
        let _ = Problem::from_response(rsp)?;
        Ok(())
    }
}

struct AccountInner {
    client: Client,
    key: Key,
    id: String,
}

impl AccountInner {
    fn from_credentials(
        credentials: AccountCredentials,
        transport: Arc<dyn AcmeTransport>,
    ) -> Result<Self, Error> {
        Ok(Self {
            id: credentials.id,
            key: Key::from_pkcs8_der(credentials.key_pkcs8.as_ref())?,
            client: match (credentials.directory, credentials.urls) {
                (Some(server_url), _) => Client::new(&server_url, transport)?,
                (None, Some(urls)) => Client { transport, urls },
                (None, None) => return Err(Error::Str("no server URLs found")),
            },
        })
    }

    fn get<T: DeserializeOwned>(&self, nonce: &mut Option<String>, url: &str) -> Result<T, Error> {
        let rsp = self.post(None::<&Empty>, nonce.take(), url)?;
        *nonce = nonce_from_response(&rsp);
        Problem::check(rsp)
    }

    fn post(
        &self,
        payload: Option<&impl Serialize>,
        nonce: Option<String>,
        url: &str,
    ) -> Result<HttpResponse, Error> {
        self.client.post(payload, nonce, self, url)
    }
}

impl Signer for AccountInner {
    type Signature = <Key as Signer>::Signature;

    fn header<'n, 'u: 'n, 's: 'u>(&'s self, nonce: Option<&'n str>, url: &'u str) -> Header<'n> {
        debug_assert!(nonce.is_some());
        Header {
            alg: self.key.signing_algorithm,
            key: KeyOrKeyId::KeyId(&self.id),
            nonce,
            url,
        }
    }

    fn sign(&self, payload: &[u8]) -> Result<Self::Signature, Error> {
        self.key.sign(payload)
    }
}

pub(crate) struct Client {
    transport: Arc<dyn AcmeTransport>,
    urls: DirectoryUrls,
}

impl Client {
    pub(crate) fn new(
        server_url: &str,
        transport: Arc<dyn AcmeTransport>,
    ) -> Result<Self, Error> {
        Self::connect(server_url, transport)
    }

    pub(crate) fn connect(
        server_url: &str,
        transport: Arc<dyn AcmeTransport>,
    ) -> Result<Self, Error> {
        if !server_url.starts_with("https://") {
            return Err(Error::Str("directory URL must use HTTPS"));
        }
        let rsp = transport.request("GET", server_url, None, None)?;
        if !(200..300).contains(&rsp.status) {
            let preview: String = String::from_utf8_lossy(&rsp.body).chars().take(200).collect();
            return Err(Error::Http(format!(
                "ACME directory HTTP {}: {preview}",
                rsp.status
            )));
        }
        let urls: DirectoryUrls = match serde_json::from_slice(&rsp.body) {
            Ok(u) => u,
            Err(e) => {
                let preview: String =
                    String::from_utf8_lossy(&rsp.body).chars().take(240).collect();
                return Err(Error::Http(format!(
                    "ACME directory JSON ({e}); len={} prefix={preview:?}",
                    rsp.body.len()
                )));
            }
        };
        Ok(Client { transport, urls })
    }

    fn post(
        &self,
        payload: Option<&impl Serialize>,
        nonce: Option<String>,
        signer: &impl Signer,
        url: &str,
    ) -> Result<HttpResponse, Error> {
        let nonce = self.nonce(nonce)?;
        let body = JoseJson::new(payload, signer.header(Some(&nonce), url), signer)?;
        let bytes = serde_json::to_vec(&body).map_err(Error::from)?;
        self.transport
            .request("POST", url, Some(JOSE_JSON), Some(&bytes))
    }

    fn nonce(&self, nonce: Option<String>) -> Result<String, Error> {
        if let Some(nonce) = nonce {
            return Ok(nonce);
        }

        let rsp = self
            .transport
            .request("HEAD", &self.urls.new_nonce, None, None)?;
        if rsp.status != 200 {
            return Err(Error::Str("error response from newNonce resource"));
        }

        match nonce_from_response(&rsp) {
            Some(nonce) => Ok(nonce),
            None => Err(Error::Str("no nonce found in newNonce response")),
        }
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("transport", &"..")
            .field("urls", &self.urls)
            .finish()
    }
}

struct Key {
    signing_algorithm: SigningAlgorithm,
    inner: SigningKey,
    thumb: String,
}

impl Key {
    fn generate() -> Result<(Self, Vec<u8>), Error> {
        let key = SigningKey::random(&mut OsRng);
        let pkcs8 = key
            .to_pkcs8_der()
            .map_err(|e| Error::CryptoKey(e.to_string()))?;
        let thumb = URL_SAFE_NO_PAD.encode(Jwk::thumb_sha256(&key)?);

        Ok((
            Self {
                signing_algorithm: SigningAlgorithm::Es256,
                inner: key,
                thumb,
            },
            pkcs8.as_bytes().to_vec(),
        ))
    }

    fn from_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self, Error> {
        let key = SigningKey::from_pkcs8_der(pkcs8_der)
            .map_err(|e| Error::CryptoKey(e.to_string()))?;
        let thumb = URL_SAFE_NO_PAD.encode(Jwk::thumb_sha256(&key)?);

        Ok(Self {
            signing_algorithm: SigningAlgorithm::Es256,
            inner: key,
            thumb,
        })
    }
}

impl Signer for Key {
    type Signature = Vec<u8>;

    fn header<'n, 'u: 'n, 's: 'u>(&'s self, nonce: Option<&'n str>, url: &'u str) -> Header<'n> {
        debug_assert!(nonce.is_some());
        Header {
            alg: self.signing_algorithm,
            key: KeyOrKeyId::from_key(&self.inner),
            nonce,
            url,
        }
    }

    fn sign(&self, payload: &[u8]) -> Result<Self::Signature, Error> {
        let sig: EcdsaSignature = self.inner.sign(payload);
        Ok(sig.to_bytes().to_vec())
    }
}

/// The response value to use for challenge responses
pub struct KeyAuthorization(String);

impl KeyAuthorization {
    fn new(challenge: &Challenge, key: &Key) -> Self {
        Self(format!("{}.{}", challenge.token, &key.thumb))
    }

    /// Get the key authorization value (HTTP-01).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// SHA-256 digest of the key authorization (TLS-ALPN-01).
    pub fn digest(&self) -> impl AsRef<[u8]> {
        Sha256::digest(self.0.as_bytes())
    }

    /// Base64-encoded SHA256 digest (DNS-01).
    pub fn dns_value(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.digest())
    }
}

impl fmt::Debug for KeyAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("KeyAuthorization").finish()
    }
}

/// External account binding key (RFC 8555 section 7.3.4).
pub struct ExternalAccountKey {
    id: String,
    key: Vec<u8>,
}

impl ExternalAccountKey {
    /// Create a new external account key
    pub fn new(id: String, key_value: &[u8]) -> Self {
        Self {
            id,
            key: key_value.to_vec(),
        }
    }
}

impl Signer for ExternalAccountKey {
    type Signature = Vec<u8>;

    fn header<'n, 'u: 'n, 's: 'u>(&'s self, nonce: Option<&'n str>, url: &'u str) -> Header<'n> {
        debug_assert_eq!(nonce, None);
        Header {
            alg: SigningAlgorithm::Hs256,
            key: KeyOrKeyId::KeyId(&self.id),
            nonce,
            url,
        }
    }

    fn sign(&self, payload: &[u8]) -> Result<Self::Signature, Error> {
        let mut mac =
            HmacSha256::new_from_slice(&self.key).map_err(|_| Error::Crypto)?;
        mac.update(payload);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

fn nonce_from_response(rsp: &HttpResponse) -> Option<String> {
    rsp.header(REPLAY_NONCE).map(ToOwned::to_owned)
}

const JOSE_JSON: &str = "application/jose+json";
const REPLAY_NONCE: &str = "Replay-Nonce";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_old_credentials() -> Result<(), Error> {
        const CREDENTIALS: &str = r#"{"id":"id","key_pkcs8":"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJVWC_QzOTCS5vtsJp2IG-UDc8cdDfeoKtxSZxaznM-mhRANCAAQenCPoGgPFTdPJ7VLLKt56RxPlYT1wNXnHc54PEyBg3LxKaH0-sJkX0mL8LyPEdsfL_Oz4TxHkWLJGrXVtNhfH","urls":{"newNonce":"new-nonce","newAccount":"new-acct","newOrder":"new-order", "revokeCert": "revoke-cert"}}"#;
        let creds = serde_json::from_str::<AccountCredentials>(CREDENTIALS)?;
        // URLs-only credentials cannot reach a live server; ensure key material parses.
        Key::from_pkcs8_der(creds.key_pkcs8.as_ref())?;
        Ok(())
    }

    #[test]
    fn deserialize_new_credentials() -> Result<(), Error> {
        const CREDENTIALS: &str = r#"{"id":"id","key_pkcs8":"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJVWC_QzOTCS5vtsJp2IG-UDc8cdDfeoKtxSZxaznM-mhRANCAAQenCPoGgPFTdPJ7VLLKt56RxPlYT1wNXnHc54PEyBg3LxKaH0-sJkX0mL8LyPEdsfL_Oz4TxHkWLJGrXVtNhfH","directory":"https://acme-staging-v02.api.letsencrypt.org/directory"}"#;
        let creds = serde_json::from_str::<AccountCredentials>(CREDENTIALS)?;
        Key::from_pkcs8_der(creds.key_pkcs8.as_ref())?;
        Ok(())
    }
}
