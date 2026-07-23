//! CLI: challenge and fully verify `openapi.teechat.ai` attestation.
//!
//! ```text
//! teechat-openapi-attest verify https://openapi.teechat.ai
//! ```
//!
//! Primary trust: GitHub Releases. teechat.ai is a network fallback only.

use anyhow::{bail, Context, Result};
use openapi_attest::ceremony::CeremonyLoadOptions;
use openapi_attest::golden::GoldenLoadOptions;
use openapi_attest::{
    verify_openapi_edge, VerifyOptions, DEFAULT_GITHUB_OWNER, DEFAULT_GITHUB_REPO,
    DEFAULT_MANIFEST_URL,
};

fn main() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        return Ok(());
    }
    let cmd = args.remove(0);
    match cmd.as_str() {
        "verify" => {
            let mut endpoint = "https://openapi.teechat.ai".to_string();
            let mut manifest_url = Some(DEFAULT_MANIFEST_URL.to_string());
            let mut manifest_path = None;
            let mut manifest_sig_path = None;
            let mut skip_spki = false;
            let mut prefer_teechat = false;
            let mut github_owner = DEFAULT_GITHUB_OWNER.to_string();
            let mut github_repo = DEFAULT_GITHUB_REPO.to_string();
            let mut github_tag = None;
            let mut golden = GoldenLoadOptions::default();
            let mut require_golden = true;
            let mut ceremony = CeremonyLoadOptions::default();
            let mut require_ceremony = true;
            let mut i = 0;
            while i < args.len() {
                match args[i].as_str() {
                    "--manifest-url" => {
                        i += 1;
                        manifest_url = Some(args.get(i).context("--manifest-url value")?.clone());
                    }
                    "--manifest" => {
                        i += 1;
                        manifest_path = Some(args.get(i).context("--manifest value")?.clone());
                    }
                    "--sig" => {
                        i += 1;
                        manifest_sig_path = Some(args.get(i).context("--sig value")?.clone());
                    }
                    "--skip-session-spki" => skip_spki = true,
                    "--prefer-teechat-manifest" => prefer_teechat = true,
                    "--github-owner" => {
                        i += 1;
                        github_owner = args.get(i).context("--github-owner value")?.clone();
                    }
                    "--github-repo" => {
                        i += 1;
                        github_repo = args.get(i).context("--github-repo value")?.clone();
                    }
                    "--github-tag" => {
                        i += 1;
                        github_tag = Some(args.get(i).context("--github-tag value")?.clone());
                    }
                    "--golden-github-owner" => {
                        i += 1;
                        golden.github_owner =
                            args.get(i).context("--golden-github-owner value")?.clone();
                    }
                    "--golden-github-repo" => {
                        i += 1;
                        golden.github_repo =
                            args.get(i).context("--golden-github-repo value")?.clone();
                    }
                    "--golden-github-tag" => {
                        i += 1;
                        golden.github_tag =
                            Some(args.get(i).context("--golden-github-tag value")?.clone());
                    }
                    "--golden-manifest-url" => {
                        i += 1;
                        golden.www_url =
                            Some(args.get(i).context("--golden-manifest-url value")?.clone());
                    }
                    "--golden-manifest" => {
                        i += 1;
                        golden.manifest_path =
                            Some(args.get(i).context("--golden-manifest value")?.clone());
                    }
                    "--golden-sig" => {
                        i += 1;
                        golden.manifest_sig_path =
                            Some(args.get(i).context("--golden-sig value")?.clone());
                    }
                    "--prefer-golden-www" => golden.prefer_www = true,
                    "--skip-golden-digests" => require_golden = false,
                    "--ceremony-manifest-url" => {
                        i += 1;
                        ceremony.www_url = Some(
                            args.get(i)
                                .context("--ceremony-manifest-url value")?
                                .clone(),
                        );
                    }
                    "--ceremony-manifest" => {
                        i += 1;
                        ceremony.manifest_path =
                            Some(args.get(i).context("--ceremony-manifest value")?.clone());
                    }
                    "--ceremony-sig" => {
                        i += 1;
                        ceremony.manifest_sig_path =
                            Some(args.get(i).context("--ceremony-sig value")?.clone());
                    }
                    "--skip-ceremony-spki" => require_ceremony = false,
                    other if !other.starts_with('-') => endpoint = other.to_string(),
                    other => bail!("unknown flag {other}"),
                }
                i += 1;
            }
            let verdict = verify_openapi_edge(VerifyOptions {
                endpoint,
                allowlist_hostname: None,
                manifest_url,
                manifest_path,
                manifest_sig_path,
                skip_session_spki: skip_spki,
                prefer_teechat_manifest: prefer_teechat,
                github_owner,
                github_repo,
                github_tag,
                golden,
                require_golden_digests: require_golden,
                ceremony,
                require_ceremony_spki: require_ceremony,
            })
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            if verdict.trust_source == "teechat_fallback" && !verdict.trust_fallback_tip.is_empty()
            {
                eprintln!("WARNING: {}", verdict.trust_fallback_tip);
            }
            if let Some(gs) = &verdict.golden_trust_source {
                if gs.starts_with("teechat_fallback") {
                    eprintln!("WARNING: golden digests via {gs}");
                }
            }
            println!("{}", serde_json::to_string_pretty(&verdict)?);
            if !verdict.ok {
                std::process::exit(2);
            }
            Ok(())
        }
        "curl-example" => {
            println!("{}", CURL_EXAMPLE);
            Ok(())
        }
        other => bail!("unknown command {other}"),
    }
}

fn print_help() {
    eprintln!(
        "\
teechat-openapi-attest — independently verify TeeChat OpenAPI edge attestation

Usage:
  teechat-openapi-attest verify [https://openapi.teechat.ai] [flags]
  teechat-openapi-attest curl-example

Trust (default):
  1. Golden digests — Lightec-AI/teechat-golden-digests (+ www .well-known/teechat/golden/)
  2. App GitHub Releases (teechat-openapi): openapi-edge-attest.json + SHA256SUMS
  3. teechat.ai signed app allowlist — only if app GitHub is unreachable

Flags:
  --github-owner <org>   default: Lightec-AI
  --github-repo <name>   default: teechat-openapi
  --github-tag <tag>     pin a release tag (default: latest)
  --prefer-teechat-manifest
                         skip GitHub; use teechat.ai (or --manifest-url) only
  --manifest-url <url>   Fallback signed app allowlist URL
  --manifest <path>      Local app manifest.json (use with --sig)
  --sig <path>           Local app manifest.sig
  --golden-github-owner / --golden-github-repo / --golden-github-tag
  --golden-manifest-url  www golden fallback URL
  --golden-manifest / --golden-sig   local signed golden digests
  --prefer-golden-www    skip golden GitHub; use www (or --golden-manifest-url)
  --skip-golden-digests  break-glass: do not require golden channel
  --ceremony-manifest-url / --ceremony-manifest / --ceremony-sig
                         TLS ceremony SPKI allowlist (www by default)
  --skip-ceremony-spki   break-glass: skip SPKI pin (empty active[] already skips)
  --skip-session-spki    Monitors may omit peer SPKI bind (not recommended)

Challenge from the edge is evidence only — not the allowlist trust root.
"
    );
}

const CURL_EXAMPLE: &str = r#"# Evidence retrieval only — does NOT verify quote signatures, collateral, or the allowlist.
# Prefer: teechat-openapi-attest verify https://openapi.teechat.ai
# Trust primary: https://github.com/Lightec-AI/teechat-openapi/releases

NONCE=$(openssl rand 32 | openssl base64 -A | tr '+/' '-_' | tr -d '=')
curl -fsS -X POST https://openapi.teechat.ai/v1/attestation/challenge \
  -H 'Content-Type: application/json' \
  -d "{\"nonce_b64\":\"${NONCE}\"}" | tee openapi-challenge.json
"#;
