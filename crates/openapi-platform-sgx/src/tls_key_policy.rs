//! SGX TLS key policy (`OPENAPI_TLS_KEY_POLICY`).
//!
//! EDP has no measured `/etc/tls_key_policy` file. Lab/practice passes the role as an
//! enclave arg. Semantics match CVM sealing §11:
//! - `key_ceremony` — mint/export only (no seal-sync import)
//! - `seal_sync` — import/serve (no local ACME issue)

/// Canonical policy values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsKeyPolicy {
    /// Generate → ACME → seal; may export via seal-sync admin; must not import.
    KeyCeremony,
    /// Must seal-sync import from attested peer; must not locally generate.
    SealSync,
}

impl TlsKeyPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KeyCeremony => "key_ceremony",
            Self::SealSync => "seal_sync",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "key_ceremony" => Some(Self::KeyCeremony),
            "seal_sync" => Some(Self::SealSync),
            _ => None,
        }
    }
}

/// Resolve policy from `OPENAPI_TLS_KEY_POLICY` (required when seal-sync or ceremony mint).
pub fn resolve_tls_key_policy() -> Result<TlsKeyPolicy, String> {
    let raw = std::env::var("OPENAPI_TLS_KEY_POLICY")
        .map_err(|_| "OPENAPI_TLS_KEY_POLICY required (key_ceremony|seal_sync)".to_string())?;
    TlsKeyPolicy::parse(&raw).ok_or_else(|| {
        format!("invalid OPENAPI_TLS_KEY_POLICY {raw:?} (want key_ceremony|seal_sync)")
    })
}

/// Optional resolve — `None` when unset (legacy single-slot lab without seal-sync).
pub fn resolve_tls_key_policy_optional() -> Result<Option<TlsKeyPolicy>, String> {
    match std::env::var("OPENAPI_TLS_KEY_POLICY") {
        Ok(raw) if !raw.trim().is_empty() => {
            Ok(Some(TlsKeyPolicy::parse(&raw).ok_or_else(|| {
                format!("invalid OPENAPI_TLS_KEY_POLICY {raw:?} (want key_ceremony|seal_sync)")
            })?))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn parse_roles() {
        assert_eq!(
            TlsKeyPolicy::parse("key_ceremony"),
            Some(TlsKeyPolicy::KeyCeremony)
        );
        assert_eq!(
            TlsKeyPolicy::parse("seal_sync"),
            Some(TlsKeyPolicy::SealSync)
        );
        assert!(TlsKeyPolicy::parse("other").is_none());
    }

    #[test]
    fn resolve_optional() {
        let _g = LOCK.lock().unwrap();
        std::env::remove_var("OPENAPI_TLS_KEY_POLICY");
        assert!(resolve_tls_key_policy_optional().unwrap().is_none());
        std::env::set_var("OPENAPI_TLS_KEY_POLICY", "seal_sync");
        assert_eq!(
            resolve_tls_key_policy_optional().unwrap(),
            Some(TlsKeyPolicy::SealSync)
        );
        std::env::remove_var("OPENAPI_TLS_KEY_POLICY");
    }
}
