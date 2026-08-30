//! Persist the highest accepted OpenAPI / golden epoch and refuse rollback (RB-04).

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{AttestError, Result};

pub const OPENAPI_EPOCH_KIND: &str = "openapi-edge";
pub const GOLDEN_EPOCH_KIND: &str = "golden-digests";

pub fn epoch_floor_dir() -> PathBuf {
    if let Ok(p) = std::env::var("TEECHAT_OPENAPI_ATTEST_EPOCH_FLOOR_DIR") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    if let Ok(p) = std::env::var("XDG_STATE_HOME") {
        if !p.trim().is_empty() {
            return PathBuf::from(p).join("teechat-openapi-attest");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("teechat-openapi-attest");
    }
    std::env::temp_dir().join("teechat-openapi-attest")
}

fn floor_path(kind: &str) -> PathBuf {
    epoch_floor_dir().join(format!("{kind}.epoch"))
}

pub fn read_epoch_floor(kind: &str) -> Result<Option<u64>> {
    read_epoch_floor_at(&floor_path(kind))
}

pub fn read_epoch_floor_at(path: &Path) -> Result<Option<u64>> {
    match fs::read_to_string(path) {
        Ok(s) => {
            let n = s.trim().parse::<u64>().map_err(|_| {
                AttestError::Policy(format!(
                    "corrupt epoch floor {}: {}",
                    path.display(),
                    s.trim()
                ))
            })?;
            Ok(Some(n))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(AttestError::Io(format!(
            "read epoch floor {}: {e}",
            path.display()
        ))),
    }
}

pub fn remember_epoch(kind: &str, epoch: u64) -> Result<()> {
    remember_epoch_at(&floor_path(kind), epoch)
}

pub fn remember_epoch_at(path: &Path, epoch: u64) -> Result<()> {
    if epoch < 1 {
        return Err(AttestError::Policy(format!("invalid epoch {epoch}")));
    }
    let current = read_epoch_floor_at(path)?.unwrap_or(0);
    if epoch <= current {
        return Ok(());
    }
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| AttestError::Io(format!("epoch floor dir: {e}")))?;
    }
    fs::write(path, format!("{epoch}\n"))
        .map_err(|e| AttestError::Io(format!("write epoch floor {}: {e}", path.display())))
}

pub fn assert_epoch_monotonic(kind: &str, epoch: u64) -> Result<()> {
    assert_epoch_monotonic_at(kind, epoch, &floor_path(kind))
}

pub fn assert_epoch_monotonic_at(kind: &str, epoch: u64, path: &Path) -> Result<()> {
    if epoch < 1 {
        return Err(AttestError::Policy(format!(
            "{kind} epoch {epoch} is invalid"
        )));
    }
    if let Some(floor) = read_epoch_floor_at(path)? {
        if epoch < floor {
            return Err(AttestError::Policy(format!(
                "{kind} epoch {epoch} is below persisted floor {floor} (RB-04)"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn accepts_first_epoch_and_refuses_rollback() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("openapi-edge.epoch");
        assert_epoch_monotonic_at(OPENAPI_EPOCH_KIND, 36, &path).unwrap();
        remember_epoch_at(&path, 36).unwrap();
        assert_eq!(read_epoch_floor_at(&path).unwrap(), Some(36));
        remember_epoch_at(&path, 41).unwrap();
        assert_eq!(read_epoch_floor_at(&path).unwrap(), Some(41));
        let err = assert_epoch_monotonic_at(OPENAPI_EPOCH_KIND, 40, &path).unwrap_err();
        assert!(err.to_string().contains("below persisted floor 41"));
        assert_epoch_monotonic_at(OPENAPI_EPOCH_KIND, 41, &path).unwrap();
    }
}
