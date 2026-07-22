//! Public golden digests allowlist (`teechat-golden-digests-manifest/v1`).
//!
//! Trust order: GitHub `teechat-golden-digests` Releases → signed www `.well-known` fallback.
//! See TeeChat `docs/design/golden-digests-publish.md`.

use std::fs;
use std::path::Path;

use openapi_platform::Measurement;
use serde::{Deserialize, Serialize};

use crate::error::{AttestError, Result};
use crate::manifest::{
    http_get_bytes, load_pinned_verifying_key, verify_manifest_signature, PINNED_PUBLIC_KEY_HEX,
};

pub const GOLDEN_SCHEMA: &str = "teechat-golden-digests-manifest/v1";
pub const GOLDEN_KEY_ID: &str = "golden-digests-v1";
pub const DEFAULT_GOLDEN_GITHUB_OWNER: &str = "Lightec-AI";
pub const DEFAULT_GOLDEN_GITHUB_REPO: &str = "teechat-golden-digests";
pub const GOLDEN_ASSET_NAME: &str = "golden-digests.json";
pub const DEFAULT_GOLDEN_WWW_URL: &str =
    "https://www.teechat.ai/.well-known/teechat/golden/manifest.json";

/// Same Ed25519 pubkey as OpenAPI attestation v1 until a dedicated golden key is rotated in.
pub const GOLDEN_PINNED_PUBLIC_KEY_HEX: &str = PINNED_PUBLIC_KEY_HEX;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GoldenDigestsManifest {
    pub schema: String,
    pub key_id: String,
    pub published_at: String,
    pub epoch: u64,
    pub not_after: String,
    #[serde(default)]
    pub retired_grace_period_days: u64,
    #[serde(default)]
    pub manifest_url: Option<String>,
    pub roles: GoldenRoles,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GoldenRoles {
    #[serde(default)]
    pub openapi: Option<GoldenRole>,
    #[serde(default)]
    pub gateway: Option<GoldenRole>,
    #[serde(default)]
    pub engine: Option<GoldenRole>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GoldenRole {
    pub backends: std::collections::BTreeMap<String, GoldenBackend>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GoldenBackend {
    #[serde(default)]
    pub active: Vec<GoldenRelease>,
    #[serde(default)]
    pub retired: Vec<GoldenRelease>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GoldenRelease {
    pub golden_version: String,
    #[serde(default)]
    pub vehicle: Option<String>,
    #[serde(default)]
    pub launch_digest: Option<String>,
    #[serde(default)]
    pub image_digest: Option<String>,
    #[serde(default)]
    pub rootfs_verity_sha256: Option<String>,
    #[serde(default)]
    pub mr_enclave: Option<String>,
    #[serde(default)]
    pub mr_signer: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub retired_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VerifiedGoldenManifest {
    pub manifest: GoldenDigestsManifest,
    /// `github` | `teechat_fallback` | `local`
    pub trust_source: String,
}

pub fn parse_golden_manifest(bytes: &[u8]) -> Result<GoldenDigestsManifest> {
    let m: GoldenDigestsManifest = serde_json::from_slice(bytes)
        .map_err(|e| AttestError::Manifest(format!("golden json: {e}")))?;
    if m.schema != GOLDEN_SCHEMA {
        return Err(AttestError::Manifest(format!(
            "unsupported golden schema {}",
            m.schema
        )));
    }
    if m.key_id != GOLDEN_KEY_ID {
        return Err(AttestError::Manifest(format!(
            "unexpected golden key_id {} (want {})",
            m.key_id, GOLDEN_KEY_ID
        )));
    }
    Ok(m)
}

pub fn verify_signed_golden_bytes(bytes: &[u8], sig_hex: &str) -> Result<VerifiedGoldenManifest> {
    let key = load_pinned_verifying_key()?;
    verify_manifest_signature(bytes, sig_hex, &key)?;
    let manifest = parse_golden_manifest(bytes)?;
    Ok(VerifiedGoldenManifest {
        manifest,
        trust_source: "teechat_fallback".into(),
    })
}

pub fn load_signed_golden_files(
    manifest_path: &Path,
    sig_path: &Path,
) -> Result<VerifiedGoldenManifest> {
    let bytes = fs::read(manifest_path).map_err(|e| AttestError::Io(e.to_string()))?;
    let sig = fs::read_to_string(sig_path).map_err(|e| AttestError::Io(e.to_string()))?;
    let mut v = verify_signed_golden_bytes(&bytes, &sig)?;
    v.trust_source = "local".into();
    Ok(v)
}

pub fn fetch_signed_golden_www(url: &str) -> Result<VerifiedGoldenManifest> {
    let sig_url = if url.ends_with("manifest.json") {
        url.replacen("manifest.json", "manifest.sig", 1)
    } else {
        format!("{url}.sig")
    };
    let bytes = http_get_bytes(url)?;
    let sig = String::from_utf8(http_get_bytes(&sig_url)?)
        .map_err(|e| AttestError::Manifest(format!("golden sig utf8: {e}")))?;
    verify_signed_golden_bytes(&bytes, &sig)
}

pub fn fetch_github_golden_digests(
    owner: &str,
    repo: &str,
    tag: Option<&str>,
) -> Result<VerifiedGoldenManifest> {
    let base = match tag {
        Some(t) => format!("https://github.com/{owner}/{repo}/releases/download/{t}"),
        None => format!("https://github.com/{owner}/{repo}/releases/latest/download"),
    };
    let url = format!("{base}/{GOLDEN_ASSET_NAME}");
    let bytes = http_get_bytes(&url)?;
    let manifest = parse_golden_manifest(&bytes)?;
    Ok(VerifiedGoldenManifest {
        manifest,
        trust_source: "github".into(),
    })
}

/// Load golden digests: local signed → GitHub primary → www signed fallback.
pub fn load_golden_digests(opts: &GoldenLoadOptions) -> Result<VerifiedGoldenManifest> {
    if let (Some(mp), Some(sp)) = (&opts.manifest_path, &opts.manifest_sig_path) {
        return load_signed_golden_files(Path::new(mp), Path::new(sp));
    }
    if opts.prefer_www {
        return fetch_signed_golden_www(opts.www_url.as_deref().unwrap_or(DEFAULT_GOLDEN_WWW_URL));
    }
    match fetch_github_golden_digests(
        &opts.github_owner,
        &opts.github_repo,
        opts.github_tag.as_deref(),
    ) {
        Ok(v) => Ok(v),
        Err(gh_err) => {
            let mut v =
                fetch_signed_golden_www(opts.www_url.as_deref().unwrap_or(DEFAULT_GOLDEN_WWW_URL))?;
            v.trust_source = format!("teechat_fallback (GitHub error: {gh_err})");
            Ok(v)
        }
    }
}

#[derive(Debug, Clone)]
pub struct GoldenLoadOptions {
    pub github_owner: String,
    pub github_repo: String,
    pub github_tag: Option<String>,
    pub www_url: Option<String>,
    pub manifest_path: Option<String>,
    pub manifest_sig_path: Option<String>,
    pub prefer_www: bool,
}

impl Default for GoldenLoadOptions {
    fn default() -> Self {
        Self {
            github_owner: DEFAULT_GOLDEN_GITHUB_OWNER.into(),
            github_repo: DEFAULT_GOLDEN_GITHUB_REPO.into(),
            github_tag: None,
            www_url: Some(DEFAULT_GOLDEN_WWW_URL.into()),
            manifest_path: None,
            manifest_sig_path: None,
            prefer_www: false,
        }
    }
}

pub fn find_golden_release<'a>(
    manifest: &'a GoldenDigestsManifest,
    role: &str,
    backend: &str,
    golden_version: &str,
) -> Result<&'a GoldenRelease> {
    let role_obj = match role {
        "openapi" => manifest.roles.openapi.as_ref(),
        "gateway" => manifest.roles.gateway.as_ref(),
        "engine" => manifest.roles.engine.as_ref(),
        other => {
            return Err(AttestError::Policy(format!("unknown golden role {other}")));
        }
    }
    .ok_or_else(|| AttestError::Policy(format!("golden role {role} missing")))?;

    let backend_obj = role_obj.backends.get(backend).ok_or_else(|| {
        AttestError::Policy(format!("golden backend {backend} missing for {role}"))
    })?;

    for rel in backend_obj.active.iter().chain(backend_obj.retired.iter()) {
        if rel.golden_version == golden_version {
            return Ok(rel);
        }
    }
    Err(AttestError::Policy(format!(
        "golden_version {golden_version} not on allowlist for {role}/{backend}"
    )))
}

/// Challenge measurement must match the golden digests row (authoritative TEE pin).
pub fn measurement_matches_golden(golden: &GoldenRelease, measurement: &Measurement) -> bool {
    match measurement {
        Measurement::LaunchDigest {
            launch_digest,
            image_digest,
        } => {
            let Some(gl) = golden.launch_digest.as_deref() else {
                return false;
            };
            let Some(gi) = golden.image_digest.as_deref() else {
                return false;
            };
            gl.eq_ignore_ascii_case(launch_digest) && gi.eq_ignore_ascii_case(image_digest)
        }
        Measurement::Mrenclave { value } => golden
            .mr_enclave
            .as_deref()
            .is_some_and(|m| m.eq_ignore_ascii_case(value)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_staging_shape() {
        let raw = r#"{
          "schema":"teechat-golden-digests-manifest/v1",
          "key_id":"golden-digests-v1",
          "published_at":"2026-07-22T10:00:00.000Z",
          "epoch":1,
          "not_after":"2099-01-01T00:00:00.000Z",
          "roles":{
            "openapi":{"backends":{"sev-snp-cvm":{"active":[{
              "golden_version":"openapi-sev-snp-legacy-2026-07",
              "launch_digest":"aa",
              "image_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            }],"retired":[]}}}
          }
        }"#;
        let m = parse_golden_manifest(raw.as_bytes()).unwrap();
        let g = find_golden_release(
            &m,
            "openapi",
            "sev-snp-cvm",
            "openapi-sev-snp-legacy-2026-07",
        )
        .unwrap();
        assert_eq!(g.launch_digest.as_deref(), Some("aa"));
    }

    #[test]
    fn golden_pin_mismatch_rejects_measurement() {
        let raw = r#"{
          "schema":"teechat-golden-digests-manifest/v1",
          "key_id":"golden-digests-v1",
          "published_at":"2026-07-22T10:00:00.000Z",
          "epoch":1,
          "not_after":"2099-01-01T00:00:00.000Z",
          "roles":{
            "openapi":{"backends":{"sev-snp-cvm":{"active":[{
              "golden_version":"openapi-sev-snp-legacy-2026-07",
              "launch_digest":"aa",
              "image_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            }],"retired":[]}}}
          }
        }"#;
        let m = parse_golden_manifest(raw.as_bytes()).unwrap();
        let g = find_golden_release(
            &m,
            "openapi",
            "sev-snp-cvm",
            "openapi-sev-snp-legacy-2026-07",
        )
        .unwrap();
        let wrong = Measurement::LaunchDigest {
            launch_digest: "cc".into(),
            image_digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .into(),
        };
        assert!(!measurement_matches_golden(g, &wrong));
        assert!(find_golden_release(&m, "openapi", "sev-snp-cvm", "no-such-pin").is_err());
    }
}
