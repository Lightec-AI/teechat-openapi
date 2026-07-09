use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use subtle::ConstantTimeEq;

use crate::auth::{AuthContext, Authenticator};
use crate::authz::{SignedAuthz, SignedRevocation};
use crate::error::ApiError;
use crate::key_format::{hash_api_key, parse_api_key, ParsedApiKey};

pub trait L0AuthorizeClient: Send + Sync {
    fn authorize(&self, key_id: &str, key_hash_hex: &str) -> Result<SignedAuthz, ApiError>;
}

#[derive(Debug, Clone)]
struct CachedAuthz {
    authz: SignedAuthz,
}

pub struct RemoteAuthenticator {
    verify_key: VerifyingKey,
    client: Arc<dyn L0AuthorizeClient>,
    revocations: RwLock<HashSet<String>>,
    cache: RwLock<HashMap<String, CachedAuthz>>,
}

impl RemoteAuthenticator {
    pub fn new(verify_key: VerifyingKey, client: Arc<dyn L0AuthorizeClient>) -> Self {
        Self {
            verify_key,
            client,
            revocations: RwLock::new(HashSet::new()),
            cache: RwLock::new(HashMap::new()),
        }
    }

    pub fn apply_revocation(&self, revocation: &SignedRevocation) -> Result<(), ApiError> {
        revocation.verify_signature(&self.verify_key)?;
        self.revocations
            .write()
            .map_err(|_| ApiError::Internal("revocation lock poisoned".into()))?
            .insert(revocation.key_id.clone());
        self.cache
            .write()
            .map_err(|_| ApiError::Internal("cache lock poisoned".into()))?
            .remove(&revocation.key_id);
        Ok(())
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    fn cache_hit(&self, parsed: &ParsedApiKey, hash: &str, now_ms: u64) -> Result<Option<AuthContext>, ApiError> {
        let cache = self
            .cache
            .read()
            .map_err(|_| ApiError::Internal("cache lock poisoned".into()))?;
        let Some(entry) = cache.get(&parsed.key_id) else {
            return Ok(None);
        };
        if entry.authz.exp_ms <= now_ms {
            return Ok(None);
        }
        let hash_match: bool = entry.authz.key_hash_hex.as_bytes().ct_eq(hash.as_bytes()).into();
        if !hash_match {
            return Ok(None);
        }
        entry.authz.verify_signature(&self.verify_key)?;
        Ok(Some(AuthContext {
            key_id: parsed.key_id.clone(),
        }))
    }

    fn store_cache(&self, authz: SignedAuthz) -> Result<(), ApiError> {
        authz.verify_signature(&self.verify_key)?;
        self.cache
            .write()
            .map_err(|_| ApiError::Internal("cache lock poisoned".into()))?
            .insert(
                authz.key_id.clone(),
                CachedAuthz { authz },
            );
        Ok(())
    }

    pub fn authenticate_parsed(&self, parsed: &ParsedApiKey) -> Result<AuthContext, ApiError> {
        if self
            .revocations
            .read()
            .map_err(|_| ApiError::Internal("revocation lock poisoned".into()))?
            .contains(&parsed.key_id)
        {
            return Err(ApiError::Unauthorized);
        }

        let hash = hash_api_key(&parsed.full_key);
        let now_ms = Self::now_ms();
        if let Some(ctx) = self.cache_hit(parsed, &hash, now_ms)? {
            return Ok(ctx);
        }

        let authz = self.client.authorize(&parsed.key_id, &hash)?;
        authz.verify_signature(&self.verify_key)?;
        if authz.exp_ms <= now_ms {
            return Err(ApiError::Unauthorized);
        }
        let hash_match: bool = authz.key_hash_hex.as_bytes().ct_eq(hash.as_bytes()).into();
        if !hash_match {
            return Err(ApiError::Unauthorized);
        }
        self.store_cache(authz)?;
        Ok(AuthContext {
            key_id: parsed.key_id.clone(),
        })
    }

    pub fn authenticate_bearer(&self, authorization: Option<&str>) -> Result<AuthContext, ApiError> {
        let header = authorization.ok_or(ApiError::Unauthorized)?;
        let token = header
            .strip_prefix("Bearer ")
            .ok_or(ApiError::Unauthorized)?;
        if token.is_empty() {
            return Err(ApiError::Unauthorized);
        }
        let parsed = parse_api_key(token).ok_or(ApiError::Unauthorized)?;
        self.authenticate_parsed(&parsed)
    }
}

pub enum EdgeAuthenticator {
    Catalog(Authenticator),
    Remote(Arc<RemoteAuthenticator>),
}

impl EdgeAuthenticator {
    pub fn from_catalog(catalog: Authenticator) -> Self {
        Self::Catalog(catalog)
    }

    pub fn from_remote(remote: RemoteAuthenticator) -> Self {
        Self::Remote(Arc::new(remote))
    }

    pub fn remote_arc(&self) -> Option<Arc<RemoteAuthenticator>> {
        match self {
            Self::Remote(r) => Some(Arc::clone(r)),
            _ => None,
        }
    }

    pub fn authenticate_bearer(&self, authorization: Option<&str>) -> Result<AuthContext, ApiError> {
        match self {
            Self::Catalog(a) => a.authenticate_bearer(authorization),
            Self::Remote(r) => r.authenticate_bearer(authorization),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::{sign_test_authz, sign_test_revocation};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    struct MockClient {
        authz: SignedAuthz,
    }

    impl L0AuthorizeClient for MockClient {
        fn authorize(&self, _key_id: &str, _key_hash_hex: &str) -> Result<SignedAuthz, ApiError> {
            Ok(self.authz.clone())
        }
    }

    fn signed_authz(signing: &SigningKey, key_id: &str, hash: &str, exp_ms: u64) -> SignedAuthz {
        sign_test_authz(key_id, hash, exp_ms, signing)
    }

    #[test]
    fn remote_auth_cache_hit() {
        let mut csprng = OsRng;
        let signing = SigningKey::generate(&mut csprng);
        let verify_key = signing.verifying_key();
        let secret = "A".repeat(32);
        let api_key = format!("sk-teechat-tcak_ab12CD34.{secret}");
        let hash = hash_api_key(&api_key);
        let authz = signed_authz(&signing, "tcak_ab12CD34", &hash, RemoteAuthenticator::now_ms() + 60_000);
        let client = Arc::new(MockClient { authz });
        let remote = RemoteAuthenticator::new(verify_key, client);
        let ctx = remote
            .authenticate_bearer(Some(&format!("Bearer {api_key}")))
            .unwrap();
        assert_eq!(ctx.key_id, "tcak_ab12CD34");
        // second call uses cache — still ok if mock stopped working
        let ctx2 = remote
            .authenticate_bearer(Some(&format!("Bearer {api_key}")))
            .unwrap();
        assert_eq!(ctx2.key_id, ctx.key_id);
    }

    #[test]
    fn revoked_key_rejected_before_l0() {
        let mut csprng = OsRng;
        let signing = SigningKey::generate(&mut csprng);
        let verify_key = signing.verifying_key();
        let secret = "B".repeat(32);
        let api_key = format!("sk-teechat-tcak_cd56EF78.{secret}");
        let hash = hash_api_key(&api_key);
        let authz = signed_authz(&signing, "tcak_cd56EF78", &hash, RemoteAuthenticator::now_ms() + 60_000);
        let client = Arc::new(MockClient { authz });
        let remote = RemoteAuthenticator::new(verify_key, client);
        let revocation = sign_test_revocation("tcak_cd56EF78", 1, 2, &signing);
        remote.apply_revocation(&revocation).unwrap();
        assert!(remote
            .authenticate_bearer(Some(&format!("Bearer {api_key}")))
            .is_err());
    }
}
