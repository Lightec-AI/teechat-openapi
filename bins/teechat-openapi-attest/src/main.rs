//! CLI: challenge and fully verify `openapi.teechat.ai` attestation.
//!
//! ```text
//! teechat-openapi-attest verify https://openapi.teechat.ai
//! ```
//!
//! Primary trust: GitHub Releases. teechat.ai is a network fallback only.

use anyhow::{bail, Context, Result};
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
                    other if !other.starts_with('-') => endpoint = other.to_string(),
                    other => bail!("unknown flag {other}"),
                }
                i += 1;
            }
            let verdict = verify_openapi_edge(VerifyOptions {
                endpoint,
                manifest_url,
                manifest_path,
                manifest_sig_path,
                skip_session_spki: skip_spki,
                prefer_teechat_manifest: prefer_teechat,
                github_owner,
                github_repo,
                github_tag,
            })
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            if verdict.trust_source == "teechat_fallback" && !verdict.trust_fallback_tip.is_empty()
            {
                eprintln!("WARNING: {}", verdict.trust_fallback_tip);
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
  1. GitHub Releases (Lightec-AI/teechat-openapi): openapi-edge-attest.json + SHA256SUMS
  2. teechat.ai Ed25519-signed .well-known allowlist — only if GitHub is unreachable
     (prints a tip on stderr; see trust_fallback_tip in JSON)

Flags:
  --github-owner <org>   default: Lightec-AI
  --github-repo <name>   default: teechat-openapi
  --github-tag <tag>     pin a release tag (default: latest)
  --prefer-teechat-manifest
                         skip GitHub; use teechat.ai (or --manifest-url) only
  --manifest-url <url>   Fallback signed allowlist URL
  --manifest <path>      Local manifest.json (use with --sig; trust_source=local)
  --sig <path>           Local manifest.sig
  --skip-session-spki    Monitors may omit peer SPKI bind (not recommended)

Full verification covers: TLS SPKI, challenge nonce, report_data binding,
SGX DCAP or SEV-SNP quote crypto, and the measurement allowlist.
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
