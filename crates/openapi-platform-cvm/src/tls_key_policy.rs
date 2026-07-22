//! Measured TLS key policy (`/etc/tls_key_policy`).
//!
//! Baked into the golden rootfs (`image_digest` / verity). Prod must not override via env.
//! See TeeChat `docs/design/openapi-edge-sealing-threat-model.md` §11.

use std::fs;
use std::path::Path;

/// Canonical path covered by the golden image measurement.
pub const TLS_KEY_POLICY_PATH: &str = "/etc/tls_key_policy";

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

/// Read policy from `path` (tests) or [`TLS_KEY_POLICY_PATH`].
pub fn read_tls_key_policy_from(path: &Path) -> Result<TlsKeyPolicy, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let line = raw
        .lines()
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("{} empty", path.display()))?;
    TlsKeyPolicy::parse(line).ok_or_else(|| {
        format!(
            "{}: invalid tls_key_policy {line:?} (want key_ceremony|seal_sync)",
            path.display()
        )
    })
}

/// Path to policy file. Prod goldens use [`TLS_KEY_POLICY_PATH`].
/// `OPENAPI_TLS_KEY_POLICY_PATH` is a CI/test redirect only (must not be set on prod units).
pub fn tls_key_policy_path() -> std::path::PathBuf {
    std::env::var("OPENAPI_TLS_KEY_POLICY_PATH")
        .ok()
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(TLS_KEY_POLICY_PATH))
}

pub fn read_tls_key_policy() -> Result<TlsKeyPolicy, String> {
    read_tls_key_policy_from(&tls_key_policy_path())
}

/// Prod: load measured policy file. Dev: optional env `OPENAPI_TLS_KEY_POLICY` if file missing.
pub fn resolve_tls_key_policy_for_profile(profile_prod: bool) -> Result<TlsKeyPolicy, String> {
    if profile_prod {
        if std::env::var("OPENAPI_TLS_KEY_POLICY")
            .ok()
            .filter(|s| !s.is_empty())
            .is_some()
        {
            return Err(
                "OPENAPI_TLS_KEY_POLICY env override is forbidden in prod (use /etc/tls_key_policy)"
                    .into(),
            );
        }
    }
    match read_tls_key_policy() {
        Ok(p) => Ok(p),
        Err(file_err) => {
            if profile_prod {
                return Err(format!(
                    "prod requires measured {}: {file_err}",
                    tls_key_policy_path().display()
                ));
            }
            if let Ok(v) = std::env::var("OPENAPI_TLS_KEY_POLICY") {
                return TlsKeyPolicy::parse(&v).ok_or_else(|| {
                    format!("OPENAPI_TLS_KEY_POLICY invalid {v:?} (want key_ceremony|seal_sync)")
                });
            }
            // Dev default: allow seal-sync wiring without a policy file.
            Ok(TlsKeyPolicy::SealSync)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn parses_ceremony_and_sync() {
        assert_eq!(
            TlsKeyPolicy::parse("key_ceremony\n"),
            Some(TlsKeyPolicy::KeyCeremony)
        );
        assert_eq!(
            TlsKeyPolicy::parse("seal_sync"),
            Some(TlsKeyPolicy::SealSync)
        );
        assert_eq!(TlsKeyPolicy::parse("generate"), None);
    }

    #[test]
    fn reads_temp_file() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("teechat-tls-key-policy-{n}"));
        {
            let mut f = fs::File::create(&p).unwrap();
            writeln!(f, "key_ceremony").unwrap();
        }
        let got = read_tls_key_policy_from(&p).unwrap();
        let _ = fs::remove_file(&p);
        assert_eq!(got, TlsKeyPolicy::KeyCeremony);
    }
}
