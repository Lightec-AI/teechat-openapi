//! Sealed monotonic high-water mark for host-clock anti-rollback (RB-49).
//!
//! Both OpenAPI edges (`openapi-platform-cvm` / `openapi-platform-sgx`) share this
//! module. Enforcement is off by default (`OPENAPI_SEALED_TIME` unset/false) so
//! live deploy stays on today's host-clock behavior until explicitly enabled.
//!
//! When enabled, first boot soft-seeds the floor from the observed host clock so
//! a fresh install is not worse than today. Subsequent observations may never
//! move below the persisted floor; rewind rejects. Epoch skew cannot resurrect
//! an epoch whose `not_after` is already behind the floor.

use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;

const ENV_ENABLE: &str = "OPENAPI_SEALED_TIME";
const ENV_PATH: &str = "OPENAPI_SEALED_TIME_PATH";
const DEFAULT_PROD_PATH: &str = "/data/openapi-sealed-time.floor";
const FLOOR_FILE_NAME: &str = "openapi-sealed-time.floor";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SealedTimeError {
    #[error("host clock {host_ms} is behind sealed floor {floor_ms} (RB-49)")]
    Rewind { host_ms: u64, floor_ms: u64 },
    #[error("sealed time io: {0}")]
    Io(String),
    #[error("corrupt sealed time floor: {0}")]
    Corrupt(String),
}

/// Whether `OPENAPI_SEALED_TIME` requests enforcement.
pub fn sealed_time_enabled_from_env() -> bool {
    match std::env::var(ENV_ENABLE) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "on"
        }
        Err(_) => false,
    }
}

/// Persist path: `OPENAPI_SEALED_TIME_PATH`, else `/data/…` when that dir exists,
/// else process temp (tests / lab).
pub fn sealed_time_path_from_env() -> PathBuf {
    if let Ok(p) = std::env::var(ENV_PATH) {
        let p = p.trim();
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    if Path::new("/data").is_dir() {
        return PathBuf::from(DEFAULT_PROD_PATH);
    }
    std::env::temp_dir().join(FLOOR_FILE_NAME)
}

#[derive(Debug, Clone)]
pub struct SealedTimeStore {
    path: PathBuf,
    /// When false, observe is a no-op passthrough (current prod default).
    enforce: bool,
}

impl SealedTimeStore {
    pub fn new(path: PathBuf, enforce: bool) -> Self {
        Self { path, enforce }
    }

    pub fn from_env() -> Self {
        Self::new(sealed_time_path_from_env(), sealed_time_enabled_from_env())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn enforce(&self) -> bool {
        self.enforce
    }

    pub fn read_floor_ms(&self) -> Result<Option<u64>, SealedTimeError> {
        read_floor_at(&self.path)
    }

    /// Observe host time. When enforcement is off, returns `host_now_ms` unchanged.
    /// When on: soft-seed on first boot; reject rewind below floor; advance floor.
    pub fn observe(&self, host_now_ms: u64) -> Result<u64, SealedTimeError> {
        if !self.enforce {
            return Ok(host_now_ms);
        }
        observe_at(&self.path, host_now_ms)
    }
}

/// Process-wide helper used by both edges' `current_unix_ms` paths.
pub fn observe_host_time_from_env(host_now_ms: u64) -> Result<u64, SealedTimeError> {
    SealedTimeStore::from_env().observe(host_now_ms)
}

fn read_floor_at(path: &Path) -> Result<Option<u64>, SealedTimeError> {
    match fs::read_to_string(path) {
        Ok(s) => {
            let n = s.trim().parse::<u64>().map_err(|_| {
                SealedTimeError::Corrupt(format!("{}: {}", path.display(), s.trim()))
            })?;
            Ok(Some(n))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(SealedTimeError::Io(format!("read {}: {e}", path.display()))),
    }
}

fn write_floor_at(path: &Path, floor_ms: u64) -> Result<(), SealedTimeError> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            fs::create_dir_all(dir)
                .map_err(|e| SealedTimeError::Io(format!("mkdir {}: {e}", dir.display())))?;
        }
    }
    fs::write(path, format!("{floor_ms}\n"))
        .map_err(|e| SealedTimeError::Io(format!("write {}: {e}", path.display())))
}

fn observe_at(path: &Path, host_now_ms: u64) -> Result<u64, SealedTimeError> {
    match read_floor_at(path)? {
        None => {
            // Soft start: seed from first observation.
            write_floor_at(path, host_now_ms)?;
            Ok(host_now_ms)
        }
        Some(floor) => {
            if host_now_ms < floor {
                return Err(SealedTimeError::Rewind {
                    host_ms: host_now_ms,
                    floor_ms: floor,
                });
            }
            if host_now_ms > floor {
                write_floor_at(path, host_now_ms)?;
            }
            Ok(host_now_ms)
        }
    }
}

/// RB-49.3: once the sealed floor is past `not_after`, skew must not resurrect
/// the epoch. Returns true when the epoch is dead relative to the floor.
pub fn floor_past_not_after(floor_ms: u64, not_after_ms: u64) -> bool {
    floor_ms > not_after_ms
}

/// Epoch window check that applies sealed-floor anti-skew (RB-49.3).
///
/// When `sealed_floor_ms` is `Some` and already past `not_after`, the epoch is
/// rejected even if `now_ms + skew` would still cover it.
pub fn epoch_window_active(
    now_ms: u64,
    not_before_ms: u64,
    not_after_ms: u64,
    skew_ms: u64,
    sealed_floor_ms: Option<u64>,
) -> bool {
    if not_before_ms > not_after_ms {
        return false;
    }
    if let Some(floor) = sealed_floor_ms {
        if floor_past_not_after(floor, not_after_ms) {
            return false;
        }
    }
    now_ms >= not_before_ms.saturating_sub(skew_ms)
        && now_ms <= not_after_ms.saturating_add(skew_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serialize env-touching tests if any; filesystem tests use unique temp dirs.
    static LOCK: Mutex<()> = Mutex::new(());

    fn temp_store(enforce: bool) -> (tempfile::TempDir, SealedTimeStore) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FLOOR_FILE_NAME);
        (dir, SealedTimeStore::new(path, enforce))
    }

    /// 49.1 — rewind past floor rejects.
    #[test]
    fn rb49_1_rewind_past_floor_rejects() {
        let (_dir, store) = temp_store(true);
        assert_eq!(store.observe(1_700_000_000_000).unwrap(), 1_700_000_000_000);
        let err = store.observe(1_699_999_000_000).unwrap_err();
        assert!(matches!(
            err,
            SealedTimeError::Rewind {
                host_ms: 1_699_999_000_000,
                floor_ms: 1_700_000_000_000
            }
        ));
    }

    /// 49.2 — crash + restart: floor ≥ last sealed value.
    #[test]
    fn rb49_2_restart_monotonic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FLOOR_FILE_NAME);
        let store = SealedTimeStore::new(path.clone(), true);
        store.observe(5_000).unwrap();
        store.observe(9_000).unwrap();
        drop(store);
        let restarted = SealedTimeStore::new(path, true);
        assert_eq!(restarted.read_floor_ms().unwrap(), Some(9_000));
        assert_eq!(restarted.observe(9_500).unwrap(), 9_500);
        assert!(restarted.observe(8_000).is_err());
    }

    /// 49.3 — raising skew cannot accept an epoch expired beyond the floor.
    #[test]
    fn rb49_3_skew_cannot_widen_past_floor() {
        let not_after = 1_000_u64;
        let floor = 1_500_u64;
        let now = 1_500_u64;
        let huge_skew = 10_000_000_u64;
        // Without floor, huge skew would still accept.
        assert!(epoch_window_active(now, 0, not_after, huge_skew, None));
        // With floor past not_after, reject regardless of skew.
        assert!(!epoch_window_active(
            now,
            0,
            not_after,
            huge_skew,
            Some(floor)
        ));
        assert!(floor_past_not_after(floor, not_after));
    }

    /// 49.6 — shared module is the single logic both edges import (compile + API).
    #[test]
    fn rb49_6_shared_store_api_for_both_edges() {
        let _g = LOCK.lock().unwrap();
        let (_dir, off) = temp_store(false);
        // Flag off: rewind is ignored (current prod behavior).
        assert_eq!(off.observe(100).unwrap(), 100);
        assert_eq!(off.observe(50).unwrap(), 50);
        assert!(off.read_floor_ms().unwrap().is_none());

        let (_dir2, on) = temp_store(true);
        assert_eq!(on.observe(100).unwrap(), 100);
        assert_eq!(on.read_floor_ms().unwrap(), Some(100));
        // Soft-start path exists and both CVM/SGX call SealedTimeStore::from_env.
        let _ = sealed_time_enabled_from_env();
        let _ = sealed_time_path_from_env();
    }

    #[test]
    fn soft_start_seeds_from_first_observation() {
        let (_dir, store) = temp_store(true);
        assert!(store.read_floor_ms().unwrap().is_none());
        assert_eq!(store.observe(42).unwrap(), 42);
        assert_eq!(store.read_floor_ms().unwrap(), Some(42));
    }
}
