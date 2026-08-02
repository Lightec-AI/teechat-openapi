//! Signed maintenance windows (§8.6.6) — message + Retry-After only.
//!
//! Must stay in lockstep with TeeChat `src/lib/confidential/maintenance-windows.ts`.

use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const SCHEMA: &str = "teechat-maintenance-windows/v1";
pub const KEY_ID: &str = "maintenance-windows-v1";

/// Ed25519 pin — must match `MAINTENANCE_WINDOWS_PINNED_PUBLIC_KEY_HEX` in TeeChat.
pub const PINNED_PUBLIC_KEY_HEX: &str =
    "d8e142936c4e12720b2d4ac98c2149279f1bd77369dc7bbd68caa04e7316ccca";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceScope {
    Fleet,
    Engine,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceReason {
    GpuHandover,
    GatewayCutover,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenancePhase {
    Hard,
    Soft,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintenanceWindow {
    pub id: String,
    pub scope: MaintenanceScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_id: Option<String>,
    pub not_before: String,
    /// Preferred hard-downtime end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hard_not_after: Option<String>,
    /// Soft advisory end; omit for open-ended soft.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soft_not_after: Option<String>,
    /// Legacy hard-only end when `hard_not_after` is absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    pub reason: MaintenanceReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintenanceWindowsManifest {
    pub schema: String,
    pub key_id: String,
    pub version: u64,
    pub published_at: String,
    pub windows: Vec<MaintenanceWindow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveMaintenance {
    pub window: MaintenanceWindow,
    pub phase: MaintenancePhase,
    pub manifest_version: u64,
    pub not_before_ms: u64,
    pub hard_not_after_ms: u64,
    pub soft_not_after_ms: Option<u64>,
    pub retry_after_secs: u64,
}

#[derive(Debug, Clone)]
pub struct VerifiedMaintenance {
    pub manifest: MaintenanceWindowsManifest,
    pub signature_verified: bool,
}

/// Shared edge cache. Missing / bad signature → no active window (fail open on availability).
#[derive(Debug, Default)]
pub struct MaintenanceState {
    inner: RwLock<Option<VerifiedMaintenance>>,
    version_floor: RwLock<u64>,
}

impl MaintenanceState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&self) {
        *self.inner.write().expect("maintenance lock") = None;
    }

    pub fn set_verified(&self, verified: VerifiedMaintenance) -> Result<(), String> {
        if !verified.signature_verified {
            return Err("signature_not_verified".into());
        }
        let mut floor = self.version_floor.write().expect("maintenance floor");
        if verified.manifest.version < *floor {
            return Err(format!(
                "version_rollback_{}_lt_{}",
                verified.manifest.version, *floor
            ));
        }
        *floor = verified.manifest.version;
        *self.inner.write().expect("maintenance lock") = Some(verified);
        Ok(())
    }

    pub fn active(&self, now_ms: u64, engine_id: Option<&str>) -> Option<ActiveMaintenance> {
        let guard = self.inner.read().expect("maintenance lock");
        let verified = guard.as_ref()?;
        if !verified.signature_verified {
            return None;
        }
        select_active(&verified.manifest, now_ms, engine_id)
    }

    pub fn status_json(&self, now_ms: u64, region: &str) -> serde_json::Value {
        match self.active(now_ms, None) {
            Some(active) => {
                let mode = match active.phase {
                    MaintenancePhase::Hard => "hard_maintenance",
                    MaintenancePhase::Soft => "soft_maintenance",
                };
                serde_json::json!({
                    "mode": mode,
                    "phase": active.phase,
                    "region": region,
                    "retry_after": active.retry_after_secs,
                    "window": {
                        "id": active.window.id,
                        "scope": active.window.scope,
                        "engine_id": active.window.engine_id,
                        "not_before": active.window.not_before,
                        "hard_not_after": active.window.hard_not_after,
                        "soft_not_after": active.window.soft_not_after,
                        "not_after": active.window.not_after,
                        "reason": active.window.reason,
                        "message": active.window.message,
                    },
                    "manifest_version": active.manifest_version,
                })
            }
            None => serde_json::json!({
                "mode": "ok",
                "phase": null,
                "region": region,
                "retry_after": null,
                "window": null,
            }),
        }
    }
}

pub type SharedMaintenanceState = Arc<MaintenanceState>;

pub fn parse_manifest_bytes(bytes: &[u8]) -> Result<MaintenanceWindowsManifest, String> {
    let m: MaintenanceWindowsManifest =
        serde_json::from_slice(bytes).map_err(|e| format!("json: {e}"))?;
    if m.schema != SCHEMA {
        return Err(format!("bad_schema_{}", m.schema));
    }
    if m.key_id != KEY_ID {
        return Err(format!("bad_key_id_{}", m.key_id));
    }
    if m.version < 1 {
        return Err("bad_version".into());
    }
    for w in &m.windows {
        if w.id.trim().is_empty() {
            return Err("bad_window_id".into());
        }
        if matches!(w.scope, MaintenanceScope::Engine)
            && w.engine_id
                .as_ref()
                .map(|s| s.trim().is_empty())
                .unwrap_or(true)
        {
            return Err("engine_scope_requires_engine_id".into());
        }
        resolve_bounds(w)?;
    }
    Ok(m)
}

struct WindowBounds {
    not_before_ms: u64,
    hard_not_after_ms: u64,
    soft_not_after_ms: Option<u64>,
    has_soft_phase: bool,
}

fn resolve_bounds(w: &MaintenanceWindow) -> Result<WindowBounds, String> {
    let not_before_ms = parse_rfc3339_ms(&w.not_before)?;
    let hard_raw = w
        .hard_not_after
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            w.not_after
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
        .ok_or_else(|| format!("missing_hard_end_{}", w.id))?;
    let hard_not_after_ms = parse_rfc3339_ms(hard_raw)?;
    if hard_not_after_ms <= not_before_ms {
        return Err(format!("bad_hard_interval_{}", w.id));
    }
    let legacy_hard_only = w
        .hard_not_after
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .is_none()
        && w.not_after
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .is_some();
    if legacy_hard_only {
        return Ok(WindowBounds {
            not_before_ms,
            hard_not_after_ms,
            soft_not_after_ms: Some(hard_not_after_ms),
            has_soft_phase: false,
        });
    }
    match w
        .soft_not_after
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        None => Ok(WindowBounds {
            not_before_ms,
            hard_not_after_ms,
            soft_not_after_ms: None,
            has_soft_phase: true,
        }),
        Some(soft) => {
            let soft_ms = parse_rfc3339_ms(soft)?;
            if soft_ms <= hard_not_after_ms {
                return Err(format!("bad_soft_interval_{}", w.id));
            }
            Ok(WindowBounds {
                not_before_ms,
                hard_not_after_ms,
                soft_not_after_ms: Some(soft_ms),
                has_soft_phase: true,
            })
        }
    }
}

pub fn verify_signature(
    manifest_bytes: &[u8],
    signature_hex: &str,
    public_key_hex: &str,
) -> Result<(), String> {
    let sig_bytes = hex::decode(signature_hex.trim()).map_err(|_| "bad_signature_hex")?;
    if sig_bytes.len() != 64 {
        return Err("bad_signature_len".into());
    }
    let pk_bytes = hex::decode(public_key_hex.trim()).map_err(|_| "bad_public_key_hex")?;
    if pk_bytes.len() != 32 {
        return Err("bad_public_key_len".into());
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|e| format!("public_key: {e}"))?;
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(manifest_bytes, &sig)
        .map_err(|_| "signature_mismatch".into())
}

pub fn verify_and_parse(
    manifest_bytes: &[u8],
    signature_hex: &str,
) -> Result<VerifiedMaintenance, String> {
    verify_signature(manifest_bytes, signature_hex, PINNED_PUBLIC_KEY_HEX)?;
    let manifest = parse_manifest_bytes(manifest_bytes)?;
    Ok(VerifiedMaintenance {
        manifest,
        signature_verified: true,
    })
}

pub fn load_from_files(manifest_path: &str, sig_path: &str) -> Result<VerifiedMaintenance, String> {
    let bytes = std::fs::read(manifest_path).map_err(|e| format!("read_manifest: {e}"))?;
    let sig = std::fs::read_to_string(sig_path).map_err(|e| format!("read_sig: {e}"))?;
    verify_and_parse(&bytes, sig.trim())
}

/// Load from `OPENAPI_MAINTENANCE_MANIFEST_PATH` + `OPENAPI_MAINTENANCE_MANIFEST_SIG_PATH`.
/// When unset, returns `Ok(None)` (no maintenance UX). Bad signature is an error.
pub fn try_load_from_env() -> Result<Option<VerifiedMaintenance>, String> {
    let Some(path) = std::env::var("OPENAPI_MAINTENANCE_MANIFEST_PATH")
        .ok()
        .filter(|s| !s.trim().is_empty())
    else {
        return Ok(None);
    };
    let sig_path = std::env::var("OPENAPI_MAINTENANCE_MANIFEST_SIG_PATH")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| {
            let p = std::path::Path::new(&path);
            if p.file_name().and_then(|n| n.to_str()) == Some("manifest.json") {
                p.with_file_name("manifest.sig")
                    .to_string_lossy()
                    .into_owned()
            } else {
                format!("{path}.sig")
            }
        });
    Ok(Some(load_from_files(&path, &sig_path)?))
}

/// Apply env-loaded windows onto shared state. Logs are the caller's responsibility.
pub fn apply_env_to_state(state: &MaintenanceState) -> Result<bool, String> {
    match try_load_from_env()? {
        Some(v) => {
            state.set_verified(v)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

pub fn select_active(
    manifest: &MaintenanceWindowsManifest,
    now_ms: u64,
    engine_id: Option<&str>,
) -> Option<ActiveMaintenance> {
    let mut best: Option<ActiveMaintenance> = None;
    for window in &manifest.windows {
        if matches!(window.scope, MaintenanceScope::Engine) {
            let Some(want) = engine_id.map(str::trim).filter(|s| !s.is_empty()) else {
                continue;
            };
            let got = window.engine_id.as_deref().map(str::trim).unwrap_or("");
            if want != got {
                continue;
            }
        }
        let Ok(bounds) = resolve_bounds(window) else {
            continue;
        };
        let phase = if now_ms < bounds.not_before_ms {
            continue;
        } else if now_ms <= bounds.hard_not_after_ms {
            MaintenancePhase::Hard
        } else if !bounds.has_soft_phase {
            continue;
        } else if bounds
            .soft_not_after_ms
            .map(|e| now_ms <= e)
            .unwrap_or(true)
        {
            MaintenancePhase::Soft
        } else {
            continue;
        };
        let retry_after_secs = match phase {
            MaintenancePhase::Hard => ((bounds.hard_not_after_ms - now_ms).div_ceil(1000)).max(1),
            MaintenancePhase::Soft => match bounds.soft_not_after_ms {
                Some(end) => ((end - now_ms).div_ceil(1000)).max(1),
                None => 180,
            },
        };
        let candidate = ActiveMaintenance {
            window: window.clone(),
            phase,
            manifest_version: manifest.version,
            not_before_ms: bounds.not_before_ms,
            hard_not_after_ms: bounds.hard_not_after_ms,
            soft_not_after_ms: bounds.soft_not_after_ms,
            retry_after_secs,
        };
        let better = match &best {
            None => true,
            Some(b) => match (candidate.phase, b.phase) {
                (MaintenancePhase::Hard, MaintenancePhase::Soft) => true,
                (MaintenancePhase::Soft, MaintenancePhase::Hard) => false,
                (MaintenancePhase::Hard, MaintenancePhase::Hard) => {
                    candidate.hard_not_after_ms > b.hard_not_after_ms
                }
                (MaintenancePhase::Soft, MaintenancePhase::Soft) => {
                    candidate.soft_not_after_ms.unwrap_or(u64::MAX)
                        > b.soft_not_after_ms.unwrap_or(u64::MAX)
                }
            },
        };
        if better {
            best = Some(candidate);
        }
    }
    best
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
pub fn parse_rfc3339_ms_for_test(s: &str) -> u64 {
    parse_rfc3339_ms(s).expect("rfc3339")
}

fn parse_rfc3339_ms(s: &str) -> Result<u64, String> {
    // Accept `...Z` and `...+00:00` by normalizing to chrono-less parse via `time` alternative:
    // openapi-core avoids chrono; use a minimal parser for the shapes we publish.
    let s = s.trim();
    let normalized = if let Some(rest) = s.strip_suffix('Z') {
        format!("{rest}+00:00")
    } else {
        s.to_string()
    };
    // YYYY-MM-DDTHH:MM:SS(.fff)?(+|-)HH:MM
    let (datetime, offset) = split_offset(&normalized)?;
    let (date, time) = datetime
        .split_once('T')
        .ok_or_else(|| "rfc3339_missing_T".to_string())?;
    let mut d = date.split('-');
    let year: i64 = d.next().ok_or("year")?.parse().map_err(|_| "year")?;
    let month: u32 = d.next().ok_or("month")?.parse().map_err(|_| "month")?;
    let day: u32 = d.next().ok_or("day")?.parse().map_err(|_| "day")?;
    let (time_main, frac) = match time.split_once('.') {
        Some((a, b)) => (a, Some(b)),
        None => (time, None),
    };
    let mut t = time_main.split(':');
    let hour: u32 = t.next().ok_or("hour")?.parse().map_err(|_| "hour")?;
    let minute: u32 = t.next().ok_or("minute")?.parse().map_err(|_| "minute")?;
    let second: u32 = t.next().ok_or("second")?.parse().map_err(|_| "second")?;
    let millis = match frac {
        Some(f) => {
            let digits: String = f.chars().take(3).collect();
            let padded = format!("{digits:0<3}");
            padded.parse::<u32>().unwrap_or(0)
        }
        None => 0,
    };
    let days = days_from_civil(year, month, day)?;
    let day_ms = (days as i64) * 86_400_000;
    let tod_ms = (hour as i64) * 3_600_000
        + (minute as i64) * 60_000
        + (second as i64) * 1000
        + millis as i64;
    let utc_ms = day_ms + tod_ms - offset;
    if utc_ms < 0 {
        return Err("before_epoch".into());
    }
    Ok(utc_ms as u64)
}

fn split_offset(s: &str) -> Result<(&str, i64), String> {
    if let Some(i) = s.rfind('+') {
        if i > 10 {
            let off = parse_offset(&s[i..])?;
            return Ok((&s[..i], off));
        }
    }
    if let Some(i) = s.rfind('-') {
        // Avoid treating date dashes as offset: offset starts at position after time.
        if i > 10 {
            let off = -parse_offset(&format!("+{}", &s[i + 1..]))?;
            return Ok((&s[..i], off));
        }
    }
    Err("rfc3339_missing_offset".into())
}

fn parse_offset(s: &str) -> Result<i64, String> {
    // +HH:MM or +HHMM
    let s = s.trim_start_matches('+');
    let (h, m) = if let Some((a, b)) = s.split_once(':') {
        (
            a.parse::<i64>().map_err(|_| "offset_h")?,
            b.parse::<i64>().map_err(|_| "offset_m")?,
        )
    } else if s.len() == 4 {
        (
            s[..2].parse::<i64>().map_err(|_| "offset_h")?,
            s[2..].parse::<i64>().map_err(|_| "offset_m")?,
        )
    } else {
        return Err("offset_fmt".into());
    };
    Ok(h * 3_600_000 + m * 60_000)
}

/// Days since Unix epoch (1970-01-01), civil date algorithm.
fn days_from_civil(year: i64, month: u32, day: u32) -> Result<i64, String> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err("bad_ymd".into());
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400) as u64;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp as u64 + 2) / 5 + day as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Ok((era * 146_097 + doe as i64) - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sign_hex(sk: &SigningKey, bytes: &[u8]) -> String {
        hex::encode(sk.sign(bytes).to_bytes())
    }

    fn sample_manifest(version: u64) -> MaintenanceWindowsManifest {
        MaintenanceWindowsManifest {
            schema: SCHEMA.into(),
            key_id: KEY_ID.into(),
            version,
            published_at: "2026-08-02T00:00:00.000Z".into(),
            windows: vec![MaintenanceWindow {
                id: "wave-b".into(),
                scope: MaintenanceScope::Fleet,
                engine_id: None,
                not_before: "2026-08-02T10:00:00.000Z".into(),
                hard_not_after: Some("2026-08-02T10:30:00.000Z".into()),
                soft_not_after: Some("2026-08-02T12:00:00.000Z".into()),
                not_after: None,
                reason: MaintenanceReason::GpuHandover,
                message: Some("GPU handover".into()),
            }],
        }
    }

    #[test]
    fn verify_and_select_active() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key();
        let pk_hex = hex::encode(pk.to_bytes());
        let manifest = sample_manifest(3);
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let sig = sign_hex(&sk, &bytes);
        verify_signature(&bytes, &sig, &pk_hex).unwrap();
        let parsed = parse_manifest_bytes(&bytes).unwrap();
        let now = parse_rfc3339_ms("2026-08-02T10:15:00.000Z").unwrap();
        let active = select_active(&parsed, now, None).unwrap();
        assert_eq!(active.window.id, "wave-b");
        assert_eq!(active.phase, MaintenancePhase::Hard);
        assert!(active.retry_after_secs > 0);
        let soft = select_active(
            &parsed,
            parse_rfc3339_ms("2026-08-02T11:00:00.000Z").unwrap(),
            None,
        )
        .unwrap();
        assert_eq!(soft.phase, MaintenancePhase::Soft);
        assert!(select_active(
            &parsed,
            parse_rfc3339_ms("2026-08-02T09:00:00.000Z").unwrap(),
            None
        )
        .is_none());
    }

    #[test]
    fn state_rejects_rollback_and_unsigned() {
        let state = MaintenanceState::new();
        let m = sample_manifest(5);
        state
            .set_verified(VerifiedMaintenance {
                manifest: m.clone(),
                signature_verified: true,
            })
            .unwrap();
        assert!(state
            .set_verified(VerifiedMaintenance {
                manifest: sample_manifest(4),
                signature_verified: true,
            })
            .is_err());
        assert!(state
            .set_verified(VerifiedMaintenance {
                manifest: m,
                signature_verified: false,
            })
            .is_err());
    }

    #[test]
    fn pinned_key_roundtrip_with_env_secret_if_present() {
        // When ops key is present locally, ensure pin matches published empty manifest.
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../config/maintenance-windows/maintenance-windows.json");
        let sig = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../../../vendor/www.teechat.ai/public/.well-known/teechat/maintenance/manifest.sig",
        );
        let manifest_www = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../../../vendor/www.teechat.ai/public/.well-known/teechat/maintenance/manifest.json",
        );
        if manifest_www.is_file() && sig.is_file() {
            let bytes = std::fs::read(&manifest_www).unwrap();
            let sig_hex = std::fs::read_to_string(&sig).unwrap();
            verify_and_parse(&bytes, sig_hex.trim()).unwrap();
            let _ = manifest; // silence
        }
    }
}
