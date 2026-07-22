//! In-guest HTTP-01 ACME client (replaces certbot on CVM).
//!
//! Writes a short-lived Let's Encrypt–compatible layout under `--acme-root` so
//! `openapi-tls-ceremony seal-from-acme` can seal + shred the private key.
//!
//! Usage:
//!   openapi-acme issue|renew --domain NAME [--webroot DIR] [--acme-root DIR] [--email ADDR] [--staging]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    // instant-acme / hyper-rustls require an explicit process-level CryptoProvider on rustls 0.23+.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let mut args = std::env::args().skip(1);
    let mode = args
        .next()
        .context("usage: openapi-acme issue|renew --domain NAME [options]")?;
    if matches!(mode.as_str(), "-h" | "--help" | "help") {
        println!(
            "usage: openapi-acme issue|renew --domain NAME [--webroot DIR] [--acme-root DIR] [--email ADDR] [--staging]"
        );
        return Ok(());
    }

    let mut domain = std::env::var("OPENAPI_ACME_CERT_NAME").ok();
    let mut webroot = std::env::var("OPENAPI_ACME_WEBROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/www/acme"));
    let mut acme_root = std::env::var("OPENAPI_ACME_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/teechat-openapi/acme"));
    let mut email = std::env::var("OPENAPI_ACME_EMAIL").ok();
    let mut staging = std::env::var("OPENAPI_ACME_STAGING")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--domain" => domain = Some(args.next().context("--domain needs a value")?),
            "--webroot" => {
                webroot = PathBuf::from(args.next().context("--webroot needs a value")?);
            }
            "--acme-root" => {
                acme_root = PathBuf::from(args.next().context("--acme-root needs a value")?);
            }
            "--email" => email = Some(args.next().context("--email needs a value")?),
            "--staging" => staging = true,
            "-h" | "--help" => {
                println!(
                    "usage: openapi-acme issue|renew --domain NAME [--webroot DIR] [--acme-root DIR] [--email ADDR] [--staging]"
                );
                return Ok(());
            }
            other => bail!("unknown arg: {other}"),
        }
    }

    let domain = domain.context("missing --domain / OPENAPI_ACME_CERT_NAME")?;
    match mode.as_str() {
        "issue" | "renew" => {}
        other => bail!("unknown mode: {other} (want issue|renew)"),
    }

    provision(&domain, &webroot, &acme_root, email.as_deref(), staging).await?;
    info!(%domain, mode = %mode, "ACME certificate written; run openapi-tls-ceremony seal-from-acme next");
    Ok(())
}

async fn provision(
    domain: &str,
    webroot: &Path,
    acme_root: &Path,
    email: Option<&str>,
    staging: bool,
) -> Result<()> {
    fs::create_dir_all(webroot).with_context(|| format!("mkdir {}", webroot.display()))?;
    fs::create_dir_all(acme_root).with_context(|| format!("mkdir {}", acme_root.display()))?;

    let directory_url = if staging {
        LetsEncrypt::Staging.url()
    } else {
        LetsEncrypt::Production.url()
    }
    .to_owned();

    let account_path = acme_root.join(if staging {
        "account.staging.json"
    } else {
        "account.json"
    });
    let account = load_or_create_account(&account_path, &directory_url, email).await?;

    let identifiers = [Identifier::Dns(domain.to_owned())];
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .context("new_order")?;

    let mut authorizations = order.authorizations();
    let mut challenge_files: Vec<PathBuf> = Vec::new();
    while let Some(result) = authorizations.next().await {
        let mut authz = result.context("authorization")?;
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            other => bail!("unexpected authorization status: {other:?}"),
        }

        let mut challenge = authz
            .challenge(ChallengeType::Http01)
            .context("HTTP-01 challenge missing from order")?;
        let token = challenge.token.clone();
        if token.is_empty() {
            bail!("HTTP-01 challenge token empty");
        }
        let key_auth = challenge.key_authorization();
        let challenge_dir = webroot.join(".well-known/acme-challenge");
        fs::create_dir_all(&challenge_dir)?;
        let challenge_path = challenge_dir.join(&token);
        fs::write(&challenge_path, key_auth.as_str())?;
        #[cfg(unix)]
        {
            fs::set_permissions(&challenge_path, fs::Permissions::from_mode(0o644))?;
        }
        challenge_files.push(challenge_path);
        info!(%token, "wrote HTTP-01 challenge file");
        challenge.set_ready().await.context("challenge set_ready")?;
    }

    let status = order
        .poll_ready(&RetryPolicy::default())
        .await
        .context("poll_ready")?;
    if status != OrderStatus::Ready {
        cleanup_challenges(&challenge_files);
        bail!("order not ready after challenges: {status:?}");
    }

    let private_key_pem = order.finalize().await.context("finalize")?;
    let cert_chain_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .context("poll_certificate")?;

    cleanup_challenges(&challenge_files);

    let live = acme_root.join("live").join(domain);
    let archive = acme_root.join("archive").join(domain);
    fs::create_dir_all(&live)?;
    fs::create_dir_all(&archive)?;

    let stamp = chrono_like_stamp();
    let arch_key = archive.join(format!("privkey{stamp}.pem"));
    let arch_chain = archive.join(format!("fullchain{stamp}.pem"));
    write_secret_pem(&arch_key, private_key_pem.as_bytes())?;
    fs::write(&arch_chain, cert_chain_pem.as_bytes())?;
    #[cfg(unix)]
    {
        fs::set_permissions(&arch_chain, fs::Permissions::from_mode(0o644))?;
    }

    replace_symlink(&live.join("privkey.pem"), &arch_key)?;
    replace_symlink(&live.join("fullchain.pem"), &arch_chain)?;
    // cert.pem optional alias for tooling
    replace_symlink(&live.join("cert.pem"), &arch_chain)?;

    info!(
        live = %live.display(),
        "wrote ACME live cert + key (seal + shred next)"
    );
    Ok(())
}

async fn load_or_create_account(
    account_path: &Path,
    directory_url: &str,
    email: Option<&str>,
) -> Result<Account> {
    if account_path.is_file() {
        let raw = fs::read_to_string(account_path)
            .with_context(|| format!("read {}", account_path.display()))?;
        let credentials: AccountCredentials =
            serde_json::from_str(&raw).context("parse ACME account credentials")?;
        match Account::builder()?.from_credentials(credentials).await {
            Ok(account) => {
                info!(path = %account_path.display(), "restored ACME account");
                return Ok(account);
            }
            Err(err) => {
                warn!(
                    path = %account_path.display(),
                    error = %err,
                    "stored ACME account unusable; creating a new one"
                );
            }
        }
    }

    let contact: Vec<String> = email
        .filter(|e| !e.is_empty())
        .map(|e| {
            if e.starts_with("mailto:") {
                e.to_owned()
            } else {
                format!("mailto:{e}")
            }
        })
        .into_iter()
        .collect();
    let contact_refs: Vec<&str> = contact.iter().map(String::as_str).collect();

    let (account, credentials) = Account::builder()?
        .create(
            &NewAccount {
                contact: &contact_refs,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url.to_owned(),
            None,
        )
        .await
        .context("create ACME account")?;

    if let Some(parent) = account_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(&credentials)?;
    fs::write(account_path, json.as_bytes())?;
    #[cfg(unix)]
    {
        fs::set_permissions(account_path, fs::Permissions::from_mode(0o600))?;
    }
    info!(path = %account_path.display(), "created ACME account");
    Ok(account)
}

fn write_secret_pem(path: &Path, pem: &[u8]) -> Result<()> {
    fs::write(path, pem)?;
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn replace_symlink(link: &Path, target: &Path) -> Result<()> {
    if link.exists() || link.symlink_metadata().is_ok() {
        let _ = fs::remove_file(link);
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
            .with_context(|| format!("symlink {} -> {}", link.display(), target.display()))?;
    }
    #[cfg(not(unix))]
    {
        fs::copy(target, link)?;
    }
    Ok(())
}

fn cleanup_challenges(paths: &[PathBuf]) {
    for path in paths {
        if let Err(err) = fs::remove_file(path) {
            warn!(path = %path.display(), error = %err, "failed to remove challenge file");
        }
    }
}

fn chrono_like_stamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("-{secs}")
}
