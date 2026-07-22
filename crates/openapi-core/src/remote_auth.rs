use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use subtle::ConstantTimeEq;

use crate::auth::{AuthContext, Authenticator};
use crate::authz::{SignedAuthz, SignedRevocation};
use crate::error::ApiError;
use crate::key_format::{hash_api_key, parse_api_key, ParsedApiKey};

/// Default outbound revocation poll interval (D6-pull).
pub const DEFAULT_REVOKE_POLL_SECS: u64 = 15;

#[derive(Debug, Clone)]
pub struct RevocationDelta {
    pub epoch: u64,
    pub revocations: Vec<SignedRevocation>,
}

pub trait L0AuthorizeClient: Send + Sync {
    fn authorize(&self, key_id: &str, key_hash_hex: &str) -> Result<SignedAuthz, ApiError>;

    /// Pull signed revocation frames with `epoch > since_epoch`.
    fn fetch_revocations(&self, since_epoch: u64) -> Result<RevocationDelta, ApiError>;
}

#[derive(Debug, Clone)]
struct CachedAuthz {
    authz: SignedAuthz,
}

/// Shared schedule for background poll + convoy timer resets.
#[derive(Debug)]
pub struct RevocationPollClock {
    interval: Duration,
    next_due: Mutex<Instant>,
    cvar: Condvar,
}

impl RevocationPollClock {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            next_due: Mutex::new(Instant::now() + interval),
            cvar: Condvar::new(),
        }
    }

    pub fn reset(&self) {
        if let Ok(mut due) = self.next_due.lock() {
            *due = Instant::now() + self.interval;
            self.cvar.notify_all();
        }
    }

    /// Block until due, then return (caller should poll then call `reset`).
    pub fn wait_until_due(&self) {
        let mut due = self.next_due.lock().expect("poll clock lock");
        loop {
            let now = Instant::now();
            if now >= *due {
                return;
            }
            let wait = *due - now;
            let (guard, _) = self.cvar.wait_timeout(due, wait).expect("poll clock wait");
            due = guard;
        }
    }
}

pub struct RemoteAuthenticator {
    verify_key: VerifyingKey,
    client: Arc<dyn L0AuthorizeClient>,
    revocations: RwLock<HashSet<String>>,
    cache: RwLock<HashMap<String, CachedAuthz>>,
    local_epoch: AtomicU64,
    poll_clock: Arc<RevocationPollClock>,
}

impl RemoteAuthenticator {
    pub fn new(verify_key: VerifyingKey, client: Arc<dyn L0AuthorizeClient>) -> Self {
        Self::with_poll_interval(
            verify_key,
            client,
            Duration::from_secs(DEFAULT_REVOKE_POLL_SECS),
        )
    }

    pub fn with_poll_interval(
        verify_key: VerifyingKey,
        client: Arc<dyn L0AuthorizeClient>,
        poll_interval: Duration,
    ) -> Self {
        Self {
            verify_key,
            client,
            revocations: RwLock::new(HashSet::new()),
            cache: RwLock::new(HashMap::new()),
            local_epoch: AtomicU64::new(0),
            poll_clock: Arc::new(RevocationPollClock::new(poll_interval)),
        }
    }

    pub fn poll_clock(&self) -> Arc<RevocationPollClock> {
        Arc::clone(&self.poll_clock)
    }

    pub fn local_epoch(&self) -> u64 {
        self.local_epoch.load(Ordering::Acquire)
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

    /// Fetch + apply revoke deltas; advances `local_epoch`; resets poll timer.
    pub fn sync_revocations_from_l0(&self) -> Result<usize, ApiError> {
        let since = self.local_epoch();
        let delta = self.client.fetch_revocations(since)?;
        let mut applied = 0usize;
        for frame in &delta.revocations {
            self.apply_revocation(frame)?;
            applied += 1;
        }
        if delta.epoch > since {
            self.local_epoch.store(delta.epoch, Ordering::Release);
        }
        self.poll_clock.reset();
        Ok(applied)
    }

    fn convoy_after_authorize(&self, authz_epoch: u64) -> Result<(), ApiError> {
        if authz_epoch > self.local_epoch() {
            self.sync_revocations_from_l0()?;
        } else {
            // Already current — still postpone next background poll.
            self.poll_clock.reset();
        }
        Ok(())
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    fn cache_hit(
        &self,
        parsed: &ParsedApiKey,
        hash: &str,
        now_ms: u64,
    ) -> Result<Option<AuthContext>, ApiError> {
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
        let hash_match: bool = entry
            .authz
            .key_hash_hex
            .as_bytes()
            .ct_eq(hash.as_bytes())
            .into();
        if !hash_match {
            return Ok(None);
        }
        entry.authz.verify_signature(&self.verify_key)?;
        Ok(Some(AuthContext {
            key_id: parsed.key_id.clone(),
            policy: entry.authz.policy.clone(),
        }))
    }

    fn store_cache(&self, authz: SignedAuthz) -> Result<(), ApiError> {
        authz.verify_signature(&self.verify_key)?;
        self.cache
            .write()
            .map_err(|_| ApiError::Internal("cache lock poisoned".into()))?
            .insert(authz.key_id.clone(), CachedAuthz { authz });
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
        let epoch = authz.epoch;
        let policy = authz.policy.clone();
        self.store_cache(authz)?;
        // Convoy: pull if L0 epoch advanced; always reset poll countdown.
        let _ = self.convoy_after_authorize(epoch);
        Ok(AuthContext {
            key_id: parsed.key_id.clone(),
            policy,
        })
    }

    pub fn authenticate_bearer(
        &self,
        authorization: Option<&str>,
    ) -> Result<AuthContext, ApiError> {
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

    pub fn authenticate_bearer(
        &self,
        authorization: Option<&str>,
    ) -> Result<AuthContext, ApiError> {
        match self {
            Self::Catalog(a) => a.authenticate_bearer(authorization),
            Self::Remote(r) => r.authenticate_bearer(authorization),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::{
        sign_test_authz, sign_test_authz_with_policy, sign_test_revocation, OpenApiKeyPolicy,
    };
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    struct MockClient {
        authz: SignedAuthz,
        delta: Mutex<RevocationDelta>,
        fetch_count: Mutex<u32>,
    }

    impl L0AuthorizeClient for MockClient {
        fn authorize(&self, _key_id: &str, _key_hash_hex: &str) -> Result<SignedAuthz, ApiError> {
            Ok(self.authz.clone())
        }

        fn fetch_revocations(&self, since_epoch: u64) -> Result<RevocationDelta, ApiError> {
            *self.fetch_count.lock().unwrap() += 1;
            let d = self.delta.lock().unwrap().clone();
            let frames: Vec<_> = d
                .revocations
                .iter()
                .filter(|r| r.epoch > since_epoch)
                .cloned()
                .collect();
            Ok(RevocationDelta {
                epoch: d.epoch,
                revocations: frames,
            })
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
        let authz = signed_authz(
            &signing,
            "tcak_ab12CD34",
            &hash,
            RemoteAuthenticator::now_ms() + 60_000,
        );
        let client = Arc::new(MockClient {
            authz,
            delta: Mutex::new(RevocationDelta {
                epoch: 1,
                revocations: vec![],
            }),
            fetch_count: Mutex::new(0),
        });
        let remote = RemoteAuthenticator::new(verify_key, client.clone());
        let ctx = remote
            .authenticate_bearer(Some(&format!("Bearer {api_key}")))
            .unwrap();
        assert_eq!(ctx.key_id, "tcak_ab12CD34");
        assert!(ctx.policy.allows_model("any"));
        assert_eq!(ctx.policy.rpm, 120);
        let ctx2 = remote
            .authenticate_bearer(Some(&format!("Bearer {api_key}")))
            .unwrap();
        assert_eq!(ctx2.key_id, ctx.key_id);
        assert_eq!(ctx2.policy, ctx.policy);
        // Convoy on first authorize calls fetch once.
        assert!(*client.fetch_count.lock().unwrap() >= 1);
    }

    #[test]
    fn convoy_pulls_when_authz_epoch_ahead() {
        let mut csprng = OsRng;
        let signing = SigningKey::generate(&mut csprng);
        let verify_key = signing.verifying_key();
        let secret = "C".repeat(32);
        let api_key = format!("sk-teechat-tcak_ef90AB12.{secret}");
        let hash = hash_api_key(&api_key);
        let authz = sign_test_authz_with_policy(
            "tcak_ef90AB12",
            &hash,
            RemoteAuthenticator::now_ms() + 60_000,
            OpenApiKeyPolicy {
                models: vec!["*".into()],
                rpm: 180,
                key_set: "api".into(),
                remaining_tokens: None,
                max_in_flight: None,
            },
            5,
            &signing,
        );
        let victim = "tcak_deadbeef";
        let rev = sign_test_revocation(victim, 1, 5, &signing);
        let client = Arc::new(MockClient {
            authz,
            delta: Mutex::new(RevocationDelta {
                epoch: 5,
                revocations: vec![rev],
            }),
            fetch_count: Mutex::new(0),
        });
        let remote = RemoteAuthenticator::new(verify_key, client);
        remote
            .authenticate_bearer(Some(&format!("Bearer {api_key}")))
            .unwrap();
        assert_eq!(remote.local_epoch(), 5);
        assert!(remote.revocations.read().unwrap().contains(victim));
    }

    #[test]
    fn convoy_resets_poll_timer_when_epoch_current() {
        let mut csprng = OsRng;
        let signing = SigningKey::generate(&mut csprng);
        let verify_key = signing.verifying_key();
        let secret = "E".repeat(32);
        let api_key = format!("sk-teechat-tcak_aa11BB22.{secret}");
        let hash = hash_api_key(&api_key);
        let authz = sign_test_authz_with_policy(
            "tcak_aa11BB22",
            &hash,
            RemoteAuthenticator::now_ms() + 60_000,
            OpenApiKeyPolicy {
                models: vec!["*".into()],
                rpm: 60,
                key_set: "api".into(),
                remaining_tokens: None,
                max_in_flight: None,
            },
            1,
            &signing,
        );
        let client = Arc::new(MockClient {
            authz,
            delta: Mutex::new(RevocationDelta {
                epoch: 1,
                revocations: vec![],
            }),
            fetch_count: Mutex::new(0),
        });
        let remote =
            RemoteAuthenticator::with_poll_interval(verify_key, client, Duration::from_secs(30));
        // Make next poll "soon"; authorize convoy should push it out by ~30s.
        {
            let clock = remote.poll_clock();
            let mut due = clock.next_due.lock().unwrap();
            *due = Instant::now() + Duration::from_millis(5);
        }
        remote
            .authenticate_bearer(Some(&format!("Bearer {api_key}")))
            .unwrap();
        let remaining = {
            let clock = remote.poll_clock();
            let due = clock.next_due.lock().unwrap();
            due.saturating_duration_since(Instant::now())
        };
        assert!(
            remaining > Duration::from_secs(20),
            "expected poll timer reset toward full interval, remaining={remaining:?}"
        );
    }

    #[test]
    fn remote_auth_returns_restricted_policy_from_cache() {
        let mut csprng = OsRng;
        let signing = SigningKey::generate(&mut csprng);
        let verify_key = signing.verifying_key();
        let secret = "C".repeat(32);
        let api_key = format!("sk-teechat-tcak_ef90AB12.{secret}");
        let hash = hash_api_key(&api_key);
        let policy = OpenApiKeyPolicy {
            models: vec!["teechat-lite".into()],
            rpm: 5,
            key_set: "api".into(),
            remaining_tokens: None,
            max_in_flight: None,
        };
        let authz = sign_test_authz_with_policy(
            "tcak_ef90AB12",
            &hash,
            RemoteAuthenticator::now_ms() + 60_000,
            policy.clone(),
            1,
            &signing,
        );
        let client = Arc::new(MockClient {
            authz,
            delta: Mutex::new(RevocationDelta {
                epoch: 0,
                revocations: vec![],
            }),
            fetch_count: Mutex::new(0),
        });
        let remote = RemoteAuthenticator::new(verify_key, client);
        let ctx = remote
            .authenticate_bearer(Some(&format!("Bearer {api_key}")))
            .unwrap();
        assert_eq!(ctx.policy, policy);
        let ctx2 = remote
            .authenticate_bearer(Some(&format!("Bearer {api_key}")))
            .unwrap();
        assert_eq!(ctx2.policy, policy);
    }

    #[test]
    fn revoked_key_rejected_before_l0() {
        let mut csprng = OsRng;
        let signing = SigningKey::generate(&mut csprng);
        let verify_key = signing.verifying_key();
        let secret = "B".repeat(32);
        let api_key = format!("sk-teechat-tcak_cd56EF78.{secret}");
        let hash = hash_api_key(&api_key);
        let authz = signed_authz(
            &signing,
            "tcak_cd56EF78",
            &hash,
            RemoteAuthenticator::now_ms() + 60_000,
        );
        let client = Arc::new(MockClient {
            authz,
            delta: Mutex::new(RevocationDelta {
                epoch: 0,
                revocations: vec![],
            }),
            fetch_count: Mutex::new(0),
        });
        let remote = RemoteAuthenticator::new(verify_key, client);
        let revocation = sign_test_revocation("tcak_cd56EF78", 1, 2, &signing);
        remote.apply_revocation(&revocation).unwrap();
        assert!(remote
            .authenticate_bearer(Some(&format!("Bearer {api_key}")))
            .is_err());
    }

    #[test]
    fn sync_revocations_applies_delta() {
        let mut csprng = OsRng;
        let signing = SigningKey::generate(&mut csprng);
        let verify_key = signing.verifying_key();
        let rev = sign_test_revocation("tcak_gone0001", 9, 3, &signing);
        let authz = signed_authz(
            &signing,
            "tcak_other001",
            "aa",
            RemoteAuthenticator::now_ms() + 60_000,
        );
        let client = Arc::new(MockClient {
            authz,
            delta: Mutex::new(RevocationDelta {
                epoch: 3,
                revocations: vec![rev],
            }),
            fetch_count: Mutex::new(0),
        });
        let remote = RemoteAuthenticator::new(verify_key, client);
        assert_eq!(remote.sync_revocations_from_l0().unwrap(), 1);
        assert_eq!(remote.local_epoch(), 3);
        assert!(remote.revocations.read().unwrap().contains("tcak_gone0001"));
    }
}
