//! CLI for in-guest TLS issuance ceremony (prod only).

use std::path::PathBuf;

use anyhow::Context;
use openapi_platform_cvm::{
    assert_no_plaintext_privkey_on_disk, assert_prod_ceremony_policy, seal_from_acme_live,
    acme_live_dir, TlsCeremonyPaths,
};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let cmd = args
        .next()
        .context("usage: openapi-tls-ceremony seal-from-acme [--cert-name NAME] [--letsencrypt-root DIR]\n       openapi-tls-ceremony verify-disk [--cert-name NAME] [--letsencrypt-root DIR]")?;

    let cert_name = std::env::var("OPENAPI_ACME_CERT_NAME")
        .unwrap_or_else(|_| "openapi.teechat.ai".into());
    let le_root = std::env::var("OPENAPI_LETSENCRYPT_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/letsencrypt"));

    let mut cert_name_override = None;
    let mut le_root_override = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--cert-name" => {
                cert_name_override = args.next();
            }
            "--letsencrypt-root" => {
                le_root_override = args.next().map(PathBuf::from);
            }
            other => anyhow::bail!("unknown arg: {other}"),
        }
    }

    let cert_name = cert_name_override.as_deref().unwrap_or(&cert_name);
    let le_root = le_root_override.as_ref().unwrap_or(&le_root);

    match cmd.as_str() {
        "seal-from-acme" => {
            assert_prod_ceremony_policy().context("ceremony policy")?;
            let paths = TlsCeremonyPaths::from_env().context("load ceremony paths")?;
            let live = acme_live_dir(le_root, cert_name);
            seal_from_acme_live(&paths, &live, le_root, cert_name)
                .context("seal from acme")?;
            assert_no_plaintext_privkey_on_disk(le_root, cert_name, &[])
                .context("verify no plaintext privkey")?;
            println!(
                "sealed tls key -> {} cert -> {}",
                paths.sealed_key_path.display(),
                paths.cert_path.display()
            );
        }
        "verify-disk" => {
            assert_no_plaintext_privkey_on_disk(le_root, cert_name, &[])
                .context("plaintext privkey found")?;
            println!("OK: no plaintext ACME privkey for {cert_name}");
        }
        _ => anyhow::bail!("unknown command: {cmd}"),
    }

    Ok(())
}
