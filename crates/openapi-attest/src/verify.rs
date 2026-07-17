//! End-to-end OpenAPI edge attestation verification.

use openapi_platform::{verify_challenge_report_data, QuoteFormat};
use serde::Serialize;
use url::Url;

use crate::challenge_client::{challenge_edge, generate_nonce, ChallengeOutcome};
use crate::error::{AttestError, Result};
use crate::github_release::{
    cross_check_code_hash_against_sha256sums, fallback_tip, fetch_github_release_trust,
    github_releases_html_url, DEFAULT_GITHUB_OWNER, DEFAULT_GITHUB_REPO,
};
use crate::manifest::{
    fetch_signed_manifest, find_matching_release, load_signed_manifest_files, VerifiedManifest,
    DEFAULT_MANIFEST_URL,
};
use crate::sgx;
use crate::snp;
use crate::tls_spki::fetch_peer_tls_identity;

#[derive(Debug, Clone, Serialize)]
pub struct AttestationVerdict {
    pub ok: bool,
    pub endpoint: String,
    pub hostname: String,
    pub quote_format: String,
    pub build_version: String,
    pub code_hash: String,
    pub measurement: serde_json::Value,
    pub tls_cert_spki_sha256: String,
    pub peer_spki_sha256: String,
    /// `spki` (contract) or `cert_der` (legacy edge that hashed the whole leaf).
    pub session_bind_mode: String,
    pub manifest_epoch: u64,
    pub manifest_key_id: String,
    /// `github` | `teechat_fallback` | `local`
    pub trust_source: String,
    pub github_release_url: String,
    /// Non-empty when `trust_source=teechat_fallback`.
    pub trust_fallback_tip: String,
    pub hardware: serde_json::Value,
    pub verified_at_unix: u64,
}

pub struct VerifyOptions {
    pub endpoint: String,
    pub manifest_url: Option<String>,
    pub manifest_path: Option<String>,
    pub manifest_sig_path: Option<String>,
    pub skip_session_spki: bool,
    /// Force teechat.ai signed manifest (skip GitHub). Useful for tests/ops.
    pub prefer_teechat_manifest: bool,
    pub github_owner: String,
    pub github_repo: String,
    pub github_tag: Option<String>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            endpoint: "https://openapi.teechat.ai".into(),
            manifest_url: Some(DEFAULT_MANIFEST_URL.into()),
            manifest_path: None,
            manifest_sig_path: None,
            skip_session_spki: false,
            prefer_teechat_manifest: false,
            github_owner: DEFAULT_GITHUB_OWNER.into(),
            github_repo: DEFAULT_GITHUB_REPO.into(),
            github_tag: None,
        }
    }
}

struct TrustBundle {
    manifest: VerifiedManifest,
    trust_source: String,
    github_release_url: String,
    trust_fallback_tip: String,
    sha256sums: Option<Vec<String>>,
}

pub fn verify_openapi_edge(opts: VerifyOptions) -> Result<AttestationVerdict> {
    let hostname = hostname_of(&opts.endpoint)?;
    let port = port_of(&opts.endpoint)?;

    let peer = fetch_peer_tls_identity(&hostname, port)?;
    let trust = load_trust_bundle(&opts)?;

    let nonce = generate_nonce();
    let outcome = challenge_edge(&opts.endpoint, &nonce)?;
    finish_verify(
        outcome,
        trust,
        peer.spki_sha256_hex,
        peer.cert_sha256_hex,
        &hostname,
        opts.skip_session_spki,
    )
}

fn load_trust_bundle(opts: &VerifyOptions) -> Result<TrustBundle> {
    let default_gh_url = github_releases_html_url(&opts.github_owner, &opts.github_repo);

    // 1) Explicit local signed files (ops/dev override)
    if let (Some(mp), Some(sp)) = (opts.manifest_path.as_ref(), opts.manifest_sig_path.as_ref()) {
        let manifest =
            load_signed_manifest_files(std::path::Path::new(mp), std::path::Path::new(sp))?;
        return Ok(TrustBundle {
            manifest,
            trust_source: "local".into(),
            github_release_url: default_gh_url,
            trust_fallback_tip: String::new(),
            sha256sums: None,
        });
    }

    // 2) Forced teechat.ai (or only --manifest-url without local files)
    if opts.prefer_teechat_manifest {
        return load_teechat_fallback(opts, &default_gh_url, None);
    }

    // 3) GitHub Releases (primary)
    match fetch_github_release_trust(
        &opts.github_owner,
        &opts.github_repo,
        opts.github_tag.as_deref(),
    ) {
        Ok(gh) => Ok(TrustBundle {
            manifest: gh.manifest,
            trust_source: "github".into(),
            github_release_url: gh.release_html_url,
            trust_fallback_tip: String::new(),
            sha256sums: gh.sha256sums,
        }),
        Err(gh_err) => {
            // Transport / missing asset → teechat.ai signed fallback
            let tip = fallback_tip(
                &opts.github_owner,
                &opts.github_repo,
                Some(&default_gh_url),
            );
            let mut bundle = load_teechat_fallback(opts, &default_gh_url, Some(&tip))?;
            // Preserve why we fell back in tip (already set); annotate with GitHub error.
            bundle.trust_fallback_tip = format!("{tip} (GitHub error: {gh_err})");
            Ok(bundle)
        }
    }
}

fn load_teechat_fallback(
    opts: &VerifyOptions,
    default_gh_url: &str,
    tip: Option<&str>,
) -> Result<TrustBundle> {
    let url = opts
        .manifest_url
        .as_deref()
        .unwrap_or(DEFAULT_MANIFEST_URL);
    let manifest = fetch_signed_manifest(url)?;
    Ok(TrustBundle {
        manifest,
        trust_source: "teechat_fallback".into(),
        github_release_url: default_gh_url.to_string(),
        trust_fallback_tip: tip.unwrap_or("").to_string(),
        sha256sums: None,
    })
}

fn finish_verify(
    outcome: ChallengeOutcome,
    trust: TrustBundle,
    peer_spki: String,
    peer_cert: String,
    hostname: &str,
    skip_session_spki: bool,
) -> Result<AttestationVerdict> {
    let response = &outcome.response;
    let verified_manifest = &trust.manifest;

    verify_challenge_report_data(&outcome.nonce, response)
        .map_err(|e| AttestError::Challenge(e.to_string()))?;

    let require_spki = verified_manifest.manifest.policy.require_session_spki_bind;
    let mut session_bind_mode = "skipped".to_string();
    if require_spki && !skip_session_spki {
        let edge = response.edge.tls_cert_spki_sha256.as_str();
        if edge.eq_ignore_ascii_case(&peer_spki) {
            session_bind_mode = "spki".into();
        } else if edge.eq_ignore_ascii_case(&peer_cert) {
            session_bind_mode = "cert_der".into();
        } else {
            return Err(AttestError::Policy(format!(
                "session SPKI mismatch: edge={} peer_spki={} peer_cert={}",
                edge, peer_spki, peer_cert
            )));
        }
    }

    find_matching_release(
        &verified_manifest.manifest,
        hostname,
        &response.edge.build_version,
        &response.edge.code_hash,
        &response.edge.measurement,
        response.quote_format,
    )?;

    cross_check_code_hash_against_sha256sums(
        &response.edge.code_hash,
        trust.sha256sums.as_deref(),
    )?;

    let reject_debug = verified_manifest.manifest.policy.reject_debug;
    let hardware = match response.quote_format {
        QuoteFormat::SgxReport => {
            return Err(AttestError::Policy(
                "quote_format=sgx_report is not remotely verifiable; reject for internet clients"
                    .into(),
            ));
        }
        QuoteFormat::SgxDcapEcdsa => {
            let r = sgx::verify_sgx_dcap_quote(&response.quote_b64, reject_debug)?;
            serde_json::json!({
                "kind": "sgx_dcap_ecdsa",
                "mrenclave": r.mrenclave_hex,
                "mrsigner": r.mrsigner_hex,
                "isv_prod_id": r.isv_prod_id,
                "isv_svn": r.isv_svn,
                "debug": r.debug,
                "tcb_status": r.tcb_status,
            })
        }
        QuoteFormat::SnpReport => {
            let r = snp::verify_snp_report(&response.quote_b64, reject_debug)?;
            serde_json::json!({
                "kind": "snp_report",
                "product": r.product_name,
                "launch_measurement": r.launch_measurement_hex,
                "chip_id": r.chip_id_hex,
                "policy_debug": r.policy_debug,
                "guest_svn": r.guest_svn,
            })
        }
    };

    let measurement = serde_json::to_value(&response.edge.measurement)
        .map_err(|e| AttestError::Challenge(e.to_string()))?;

    Ok(AttestationVerdict {
        ok: true,
        endpoint: outcome.endpoint,
        hostname: hostname.to_string(),
        quote_format: response.quote_format.as_str().to_string(),
        build_version: response.edge.build_version.clone(),
        code_hash: response.edge.code_hash.clone(),
        measurement,
        tls_cert_spki_sha256: response.edge.tls_cert_spki_sha256.clone(),
        peer_spki_sha256: peer_spki,
        session_bind_mode,
        manifest_epoch: verified_manifest.manifest.epoch,
        manifest_key_id: verified_manifest.key_id.clone(),
        trust_source: trust.trust_source,
        github_release_url: trust.github_release_url,
        trust_fallback_tip: trust.trust_fallback_tip,
        hardware,
        verified_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    })
}

fn hostname_of(endpoint: &str) -> Result<String> {
    let u = Url::parse(endpoint).map_err(|e| AttestError::Http(format!("bad url: {e}")))?;
    u.host_str()
        .map(|h| h.to_string())
        .ok_or_else(|| AttestError::Http("endpoint missing host".into()))
}

fn port_of(endpoint: &str) -> Result<u16> {
    let u = Url::parse(endpoint).map_err(|e| AttestError::Http(format!("bad url: {e}")))?;
    Ok(u.port_or_known_default().unwrap_or(443))
}
