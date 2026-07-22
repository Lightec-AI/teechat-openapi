//! OpenAPI TLS ceremony SPKI allowlist (public pins after key ceremony).
//!
//! See TeeChat `docs/ops/openapi-tls-key-ceremony.md`.

use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{AttestError, Result};
use crate::manifest::{parse_rfc3339_secs, PINNED_KEY_ID, PINNED_PUBLIC_KEY_HEX};

pub const CEREMONY_SCHEMA: &str = "teechat-openapi-tls-ceremony/v1";
pub const DEFAULT_CEREMONY_WWW_URL: &str =
    "https://www.teechat.ai/.well-known/teechat/openapi-tls-ceremony/manifest.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CeremonyManifest {
    pub schema: String,
    pub key_id: String,
    pub published_at: String,
    pub epoch: u64,
    pub not_after: String,
    #[serde(default)]
    pub retired_grace_period_days: u64,
    #[serde(default)]
    pub manifest_url: Option<String>,
    pub hostnames: Vec<String>,
    #[serde(default)]
    pub active: Vec<CeremonyRelease>,
    #[serde(default)]
    pub retired: Vec<CeremonyRelease>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CeremonyRelease {
    pub ceremony_id: String,
    pub spki_sha256: String,
    pub golden_version: String,
    pub published_at: String,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub retired_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VerifiedCeremonyManifest {
    pub manifest: CeremonyManifest,
    pub trust_source: String,
}

#[derive(Debug, Clone, Default)]
pub struct CeremonyLoadOptions {
    pub prefer_www: bool,
    pub manifest_path: Option<String>,
    pub manifest_sig_path: Option<String>,
    pub www_url: Option<String>,
}

pub fn parse_ceremony_manifest(bytes: &[u8]) -> Result<CeremonyManifest> {
    let m: CeremonyManifest = serde_json::from_slice(bytes)
        .map_err(|e| AttestError::Manifest(format!("ceremony json: {e}")))?;
    if m.schema != CEREMONY_SCHEMA {
        return Err(AttestError::Manifest(format!(
            "unsupported ceremony schema {}",
            m.schema
        )));
    }
    if m.key_id != PINNED_KEY_ID {
        return Err(AttestError::Manifest(format!(
            "unexpected ceremony key_id {} (want {})",
            m.key_id, PINNED_KEY_ID
        )));
    }
    Ok(m)
}

fn verify_sig(bytes: &[u8], sig_hex: &str) -> Result<()> {
    let pk_bytes = hex::decode(PINNED_PUBLIC_KEY_HEX)
        .map_err(|e| AttestError::Manifest(format!("pinned pubkey: {e}")))?;
    let vk = VerifyingKey::from_bytes(
        pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| AttestError::Manifest("pinned pubkey length".into()))?,
    )
    .map_err(|e| AttestError::Manifest(format!("pubkey: {e}")))?;
    let sig_raw = hex::decode(sig_hex.trim())
        .map_err(|e| AttestError::Manifest(format!("ceremony sig hex: {e}")))?;
    let sig = Signature::from_slice(&sig_raw)
        .map_err(|e| AttestError::Manifest(format!("ceremony sig: {e}")))?;
    vk.verify(bytes, &sig)
        .map_err(|e| AttestError::Manifest(format!("ceremony signature: {e}")))?;
    Ok(())
}

pub fn load_signed_ceremony_files(
    manifest_path: &Path,
    sig_path: &Path,
) -> Result<VerifiedCeremonyManifest> {
    let bytes = fs::read(manifest_path).map_err(|e| AttestError::Io(e.to_string()))?;
    let sig = fs::read_to_string(sig_path).map_err(|e| AttestError::Io(e.to_string()))?;
    verify_sig(&bytes, &sig)?;
    Ok(VerifiedCeremonyManifest {
        manifest: parse_ceremony_manifest(&bytes)?,
        trust_source: "local".into(),
    })
}

fn fetch_url(url: &str) -> Result<Vec<u8>> {
    let resp = ureq::get(url)
        .call()
        .map_err(|e| AttestError::Http(e.to_string()))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .read_to_end(&mut buf)
        .map_err(|e| AttestError::Http(e.to_string()))?;
    Ok(buf)
}

pub fn load_ceremony_allowlist(opts: &CeremonyLoadOptions) -> Result<VerifiedCeremonyManifest> {
    if let (Some(mp), Some(sp)) = (&opts.manifest_path, &opts.manifest_sig_path) {
        return load_signed_ceremony_files(Path::new(mp), Path::new(sp));
    }
    let www = opts.www_url.as_deref().unwrap_or(DEFAULT_CEREMONY_WWW_URL);
    let bytes = fetch_url(www)?;
    let sig_url = if www.ends_with("manifest.json") {
        www.replace("manifest.json", "manifest.sig")
    } else {
        format!("{www}.sig")
    };
    let sig = String::from_utf8(fetch_url(&sig_url)?)
        .map_err(|e| AttestError::Http(format!("ceremony sig utf8: {e}")))?;
    verify_sig(&bytes, &sig)?;
    Ok(VerifiedCeremonyManifest {
        manifest: parse_ceremony_manifest(&bytes)?,
        trust_source: "teechat_fallback".into(),
    })
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// True if SPKI is on active list, or retired within grace.
pub fn spki_on_ceremony_allowlist(manifest: &CeremonyManifest, spki_sha256: &str) -> bool {
    let h = spki_sha256.trim().to_ascii_lowercase();
    if manifest
        .active
        .iter()
        .any(|r| r.spki_sha256.eq_ignore_ascii_case(&h))
    {
        return true;
    }
    let grace = manifest.retired_grace_period_days.saturating_mul(86400);
    let now = now_unix();
    for r in &manifest.retired {
        if !r.spki_sha256.eq_ignore_ascii_case(&h) {
            continue;
        }
        let Some(retired_at) = &r.retired_at else {
            return true;
        };
        match parse_rfc3339_secs(retired_at) {
            Ok(retired) if now <= retired.saturating_add(grace) => return true,
            _ => continue,
        }
    }
    false
}

/// When `active` is empty, ceremony pin is not yet enforced (bootstrap).
pub fn ceremony_pin_required(manifest: &CeremonyManifest) -> bool {
    !manifest.active.is_empty()
}
