//! Signed OpenAPI edge measurement allowlist (`teechat-openapi-edge-manifest/v1`).

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use openapi_platform::{Measurement, QuoteFormat};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{AttestError, Result};

pub const DEFAULT_MANIFEST_URL: &str =
    "https://www.teechat.ai/.well-known/teechat/openapi-attestation/global/manifest.json";
pub const PINNED_KEY_ID: &str = "openapi-attestation-v1";
/// Hex-encoded Ed25519 public key from `manifest/keys/openapi-attestation-v1.pub`.
pub const PINNED_PUBLIC_KEY_HEX: &str =
    "e2ea0bdac9f57cd912e45d3bcd11c46576273b72608b294fcc8660193db234b5";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenApiEdgeManifest {
    pub schema: String,
    pub key_id: String,
    pub published_at: String,
    pub epoch: u64,
    pub not_after: String,
    #[serde(default = "default_grace")]
    pub retired_grace_period_days: u64,
    #[serde(default)]
    pub manifest_url: Option<String>,
    pub policy: ManifestPolicy,
    pub regions: Vec<ManifestRegion>,
    #[serde(default)]
    pub next_key: Option<NextKey>,
}

fn default_grace() -> u64 {
    30
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestPolicy {
    pub reject_debug: bool,
    pub max_quote_age_ms: u64,
    #[serde(default = "default_true")]
    pub require_session_spki_bind: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestRegion {
    pub region: String,
    pub hostnames: Vec<String>,
    pub active: Vec<EdgeRelease>,
    #[serde(default)]
    pub retired: Vec<EdgeRelease>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EdgeRelease {
    pub build_version: String,
    pub code_hash: String,
    pub quote_formats: Vec<String>,
    pub measurement: Measurement,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub retired_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NextKey {
    pub key_id: String,
    pub public_key_hex: String,
    #[serde(default)]
    pub not_before: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VerifiedManifest {
    pub manifest: OpenApiEdgeManifest,
    pub key_id: String,
    pub bytes: Vec<u8>,
}

pub fn load_pinned_verifying_key() -> Result<VerifyingKey> {
    verifying_key_from_hex(PINNED_PUBLIC_KEY_HEX)
}

pub fn verifying_key_from_hex(hex_str: &str) -> Result<VerifyingKey> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| AttestError::Manifest(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(AttestError::Manifest("public key must be 32 bytes".into()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr).map_err(|e| AttestError::Manifest(e.to_string()))
}

pub fn verify_manifest_signature(bytes: &[u8], sig_hex: &str, key: &VerifyingKey) -> Result<()> {
    let sig_bytes = hex::decode(sig_hex.trim().replace(['\n', ' ', '\r'], ""))
        .map_err(|e| AttestError::Manifest(format!("sig hex: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(AttestError::Manifest("signature must be 64 bytes".into()));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&arr);
    key.verify(bytes, &sig)
        .map_err(|_| AttestError::Manifest("Ed25519 signature invalid".into()))
}

fn parse_rfc3339_secs(s: &str) -> Result<u64> {
    // Minimal parser: use chrono-less approach via `httpdate` alternative —
    // accept `YYYY-MM-DDTHH:MM:SS(.mmm)Z` only.
    let s = s.trim();
    let (date, time) = s
        .strip_suffix('Z')
        .and_then(|t| t.split_once('T'))
        .ok_or_else(|| AttestError::Manifest(format!("bad timestamp {s}")))?;
    let mut d = date.split('-');
    let y: i64 = d
        .next()
        .and_then(|x| x.parse().ok())
        .ok_or_else(|| AttestError::Manifest("bad year".into()))?;
    let mo: u32 = d
        .next()
        .and_then(|x| x.parse().ok())
        .ok_or_else(|| AttestError::Manifest("bad month".into()))?;
    let day: u32 = d
        .next()
        .and_then(|x| x.parse().ok())
        .ok_or_else(|| AttestError::Manifest("bad day".into()))?;
    let time = time.split('.').next().unwrap_or(time);
    let mut t = time.split(':');
    let hh: u32 = t
        .next()
        .and_then(|x| x.parse().ok())
        .ok_or_else(|| AttestError::Manifest("bad hour".into()))?;
    let mm: u32 = t
        .next()
        .and_then(|x| x.parse().ok())
        .ok_or_else(|| AttestError::Manifest("bad minute".into()))?;
    let ss: u32 = t
        .next()
        .and_then(|x| x.parse().ok())
        .ok_or_else(|| AttestError::Manifest("bad second".into()))?;
    // Days from civil date (Howard Hinnant algorithm)
    let y = if mo <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if mo > 2 { mo - 3 } else { mo + 9 };
    let doy = (153 * mp as u64 + 2) / 5 + day as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = (era * 146097 + doe as i64 - 719468) as i64;
    let secs = days * 86400 + (hh as i64) * 3600 + (mm as i64) * 60 + ss as i64;
    if secs < 0 {
        return Err(AttestError::Manifest("timestamp before epoch".into()));
    }
    Ok(secs as u64)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn parse_and_validate_manifest(bytes: &[u8], key_id_hint: Option<&str>) -> Result<OpenApiEdgeManifest> {
    let m: OpenApiEdgeManifest = serde_json::from_slice(bytes)
        .map_err(|e| AttestError::Manifest(format!("json: {e}")))?;
    if m.schema != "teechat-openapi-edge-manifest/v1" {
        return Err(AttestError::Manifest(format!("unsupported schema {}", m.schema)));
    }
    if let Some(hint) = key_id_hint {
        if m.key_id != hint && hint == PINNED_KEY_ID {
            // allow next_key after rotation when signed by pinned key; key_id itself checked by caller
        }
    }
    let not_after = parse_rfc3339_secs(&m.not_after)?;
    if now_unix() > not_after {
        return Err(AttestError::Manifest(format!(
            "manifest expired at {}",
            m.not_after
        )));
    }
    Ok(m)
}

pub fn verify_signed_manifest_bytes(bytes: &[u8], sig_hex: &str) -> Result<VerifiedManifest> {
    let pinned = load_pinned_verifying_key()?;
    verify_manifest_signature(bytes, sig_hex, &pinned)?;
    let manifest = parse_and_validate_manifest(bytes, Some(PINNED_KEY_ID))?;
    if manifest.key_id != PINNED_KEY_ID {
        // Accept only if next_key rotation already completed under a previously pinned key —
        // for v1 pin we require key_id match unless next_key authorizes a different signer
        // that signed this document. Detached sig is checked against pinned key above, so
        // key_id must still be the pinned id for the first root.
        if manifest.key_id != PINNED_KEY_ID {
            return Err(AttestError::Manifest(format!(
                "unexpected key_id {} (pinned {})",
                manifest.key_id, PINNED_KEY_ID
            )));
        }
    }
    Ok(VerifiedManifest {
        key_id: manifest.key_id.clone(),
        manifest,
        bytes: bytes.to_vec(),
    })
}

pub fn fetch_signed_manifest(manifest_url: &str) -> Result<VerifiedManifest> {
    let sig_url = if manifest_url.ends_with("manifest.json") {
        manifest_url.replacen("manifest.json", "manifest.sig", 1)
    } else {
        format!("{manifest_url}.sig")
    };
    let bytes = http_get_bytes(manifest_url)?;
    let sig = String::from_utf8(http_get_bytes(&sig_url)?)
        .map_err(|e| AttestError::Manifest(format!("sig utf8: {e}")))?;
    verify_signed_manifest_bytes(&bytes, &sig)
}

pub fn load_signed_manifest_files(manifest_path: &Path, sig_path: &Path) -> Result<VerifiedManifest> {
    let bytes = fs::read(manifest_path).map_err(|e| AttestError::Io(e.to_string()))?;
    let sig = fs::read_to_string(sig_path).map_err(|e| AttestError::Io(e.to_string()))?;
    verify_signed_manifest_bytes(&bytes, &sig)
}

pub(crate) fn http_get_bytes(url: &str) -> Result<Vec<u8>> {
    let resp = ureq::get(url)
        .set("Accept", "application/json, text/plain, */*")
        .call()
        .map_err(|e| AttestError::Http(format!("GET {url}: {e}")))?;
    if !(200..300).contains(&resp.status()) {
        return Err(AttestError::Http(format!(
            "GET {url}: HTTP {}",
            resp.status()
        )));
    }
    let mut buf = Vec::new();
    resp.into_reader()
        .read_to_end(&mut buf)
        .map_err(|e| AttestError::Http(e.to_string()))?;
    Ok(buf)
}

pub fn find_matching_release<'a>(
    manifest: &'a OpenApiEdgeManifest,
    hostname: &str,
    build_version: &str,
    code_hash: &str,
    measurement: &Measurement,
    quote_format: QuoteFormat,
) -> Result<&'a EdgeRelease> {
    let host = hostname.to_ascii_lowercase();
    let region = manifest
        .regions
        .iter()
        .find(|r| r.hostnames.iter().any(|h| h.eq_ignore_ascii_case(&host)))
        .ok_or_else(|| AttestError::Policy(format!("hostname {hostname} not in manifest")))?;

    let fmt = quote_format.as_str();
    let candidates = region.active.iter().chain(region.retired.iter());
    for rel in candidates {
        if rel.build_version != build_version {
            continue;
        }
        if !rel.code_hash.eq_ignore_ascii_case(code_hash) {
            continue;
        }
        if !measurement_eq(&rel.measurement, measurement) {
            continue;
        }
        if !rel.quote_formats.iter().any(|f| f == fmt) {
            continue;
        }
        if let Some(retired_at) = &rel.retired_at {
            let retired = parse_rfc3339_secs(retired_at)?;
            let grace = manifest.retired_grace_period_days.saturating_mul(86400);
            if now_unix() > retired.saturating_add(grace) {
                continue;
            }
        }
        return Ok(rel);
    }
    Err(AttestError::Policy(
        "edge measurement/build/code_hash not on allowlist for this hostname".into(),
    ))
}

fn measurement_eq(a: &Measurement, b: &Measurement) -> bool {
    match (a, b) {
        (Measurement::Mrenclave { value: va }, Measurement::Mrenclave { value: vb }) => {
            va.eq_ignore_ascii_case(vb)
        }
        (
            Measurement::LaunchDigest {
                launch_digest: la,
                image_digest: ia,
            },
            Measurement::LaunchDigest {
                launch_digest: lb,
                image_digest: ib,
            },
        ) => la.eq_ignore_ascii_case(lb) && ia.eq_ignore_ascii_case(ib),
        _ => false,
    }
}

/// Convenience: SHA-256 of UTF-8 for diagnostics.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    #[test]
    fn signs_and_verifies_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let body = br#"{"schema":"teechat-openapi-edge-manifest/v1","key_id":"t","published_at":"2026-07-16T00:00:00Z","epoch":1,"not_after":"2099-01-01T00:00:00Z","policy":{"reject_debug":true,"max_quote_age_ms":3600000},"regions":[{"region":"global","hostnames":["openapi.teechat.ai"],"active":[],"retired":[]}]}"#;
        let sig = sk.sign(body);
        verify_manifest_signature(body, &hex::encode(sig.to_bytes()), &vk).unwrap();
    }
}
