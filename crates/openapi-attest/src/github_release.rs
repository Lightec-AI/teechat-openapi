//! Fetch OpenAPI edge allowlist + SHA256SUMS from GitHub Releases (primary trust).

use serde::Deserialize;

use crate::error::{AttestError, Result};
use crate::manifest::{parse_and_validate_manifest, OpenApiEdgeManifest, VerifiedManifest};

pub const DEFAULT_GITHUB_OWNER: &str = "Lightec-AI";
pub const DEFAULT_GITHUB_REPO: &str = "teechat-openapi";
pub const ATTEST_ASSET_NAME: &str = "openapi-edge-attest.json";
pub const SHA256SUMS_ASSET_NAME: &str = "SHA256SUMS";

#[derive(Debug, Clone)]
pub struct GitHubReleaseTrust {
    pub manifest: VerifiedManifest,
    pub release_html_url: String,
    pub release_tag: String,
    /// Digests from SHA256SUMS (lowercase hex), if the asset was present.
    pub sha256sums: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct GhRelease {
    tag_name: String,
    html_url: String,
    assets: Vec<GhAsset>,
}

#[derive(Debug, Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
}

pub fn github_releases_api_url(owner: &str, repo: &str, tag: Option<&str>) -> String {
    match tag {
        Some(t) if !t.is_empty() => {
            format!("https://api.github.com/repos/{owner}/{repo}/releases/tags/{t}")
        }
        _ => format!("https://api.github.com/repos/{owner}/{repo}/releases/latest"),
    }
}

pub fn github_releases_html_url(owner: &str, repo: &str) -> String {
    format!("https://github.com/{owner}/{repo}/releases")
}

/// Fetch allowlist (and optional SHA256SUMS) from a GitHub Release.
pub fn fetch_github_release_trust(
    owner: &str,
    repo: &str,
    tag: Option<&str>,
) -> Result<GitHubReleaseTrust> {
    let api = github_releases_api_url(owner, repo, tag);
    let body = http_get_github(&api)?;
    let release: GhRelease = serde_json::from_slice(&body)
        .map_err(|e| AttestError::Http(format!("GitHub release JSON: {e}")))?;

    let attest_url = release
        .assets
        .iter()
        .find(|a| a.name == ATTEST_ASSET_NAME)
        .map(|a| a.browser_download_url.clone())
        .ok_or_else(|| {
            AttestError::Manifest(format!(
                "GitHub release {} missing asset {ATTEST_ASSET_NAME}",
                release.tag_name
            ))
        })?;

    let attest_bytes = http_get_github(&attest_url)?;
    let manifest = parse_and_validate_manifest(&attest_bytes, None)?;
    let verified = VerifiedManifest {
        key_id: format!("github:{}:{}", repo, release.tag_name),
        manifest,
        bytes: attest_bytes,
    };

    let sha256sums = match release
        .assets
        .iter()
        .find(|a| a.name == SHA256SUMS_ASSET_NAME)
    {
        Some(a) => {
            let raw = http_get_github(&a.browser_download_url)?;
            let text = String::from_utf8(raw)
                .map_err(|e| AttestError::Manifest(format!("SHA256SUMS utf8: {e}")))?;
            Some(parse_sha256sums(&text)?)
        }
        None => None,
    };

    Ok(GitHubReleaseTrust {
        manifest: verified,
        release_html_url: release.html_url,
        release_tag: release.tag_name,
        sha256sums,
    })
}

/// When SHA256SUMS is present, `code_hash` must appear as one of its digests.
pub fn cross_check_code_hash_against_sha256sums(
    code_hash: &str,
    sha256sums: Option<&[String]>,
) -> Result<()> {
    let Some(sums) = sha256sums else {
        return Ok(());
    };
    if sums.is_empty() {
        return Err(AttestError::Policy("SHA256SUMS is empty".into()));
    }
    let want = code_hash.to_ascii_lowercase();
    if !sums.iter().any(|d| d.eq_ignore_ascii_case(&want)) {
        return Err(AttestError::Policy(format!(
            "edge code_hash {code_hash} not present in GitHub release SHA256SUMS"
        )));
    }
    Ok(())
}

pub fn parse_sha256sums(text: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Formats: "<hex>  <name>" or "<hex> *<name>"
        let hex = line
            .split_whitespace()
            .next()
            .ok_or_else(|| AttestError::Manifest("SHA256SUMS: empty line".into()))?;
        if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AttestError::Manifest(format!(
                "SHA256SUMS: bad digest {hex}"
            )));
        }
        out.push(hex.to_ascii_lowercase());
    }
    Ok(out)
}

pub fn fallback_tip(owner: &str, repo: &str, release_html_url: Option<&str>) -> String {
    let page = release_html_url
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| github_releases_html_url(owner, repo));
    format!(
        "GitHub Releases were unreachable; used the teechat.ai signed allowlist as a network fallback. \
When you can reach GitHub, open {page} and confirm the release asset \
{ATTEST_ASSET_NAME} (and SHA256SUMS) lists the same build_version / code_hash / measurement as this result."
    )
}

fn http_get_github(url: &str) -> Result<Vec<u8>> {
    let resp = ureq::get(url)
        .set(
            "Accept",
            "application/vnd.github+json, application/octet-stream, */*",
        )
        .set("User-Agent", "teechat-openapi-attest")
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

/// Convenience for tests / local unsigned allowlist files (no signature).
pub fn load_unsigned_allowlist_bytes(bytes: &[u8]) -> Result<VerifiedManifest> {
    let manifest: OpenApiEdgeManifest = parse_and_validate_manifest(bytes, None)?;
    Ok(VerifiedManifest {
        key_id: "local-unsigned".into(),
        manifest,
        bytes: bytes.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sha256sums() {
        let text = "\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  openapi
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb *teechat-openapi-attest
";
        let digests = parse_sha256sums(text).unwrap();
        assert_eq!(digests.len(), 2);
        assert_eq!(digests[0].chars().next().unwrap(), 'a');
    }

    #[test]
    fn cross_check_requires_digest_when_sums_present() {
        let sums = vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()];
        cross_check_code_hash_against_sha256sums(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Some(&sums),
        )
        .unwrap();
        assert!(cross_check_code_hash_against_sha256sums(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            Some(&sums),
        )
        .is_err());
        cross_check_code_hash_against_sha256sums("anything", None).unwrap();
    }

    #[test]
    fn fallback_tip_mentions_github() {
        let tip = fallback_tip(DEFAULT_GITHUB_OWNER, DEFAULT_GITHUB_REPO, None);
        assert!(tip.contains("teechat.ai"));
        assert!(tip.contains("github.com/Lightec-AI/teechat-openapi/releases"));
        assert!(tip.contains(ATTEST_ASSET_NAME));
    }
}
