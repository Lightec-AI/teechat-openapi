use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use openapi_core::App;
use openapi_edge::{run_edge_server, ReadWriteConn};
use openapi_platform::{SealedTlsKeyBlob, Sealer};
use tracing::{info, warn};

use crate::attest::SgxAttestationPlatform;
use crate::ceremony_helper::CeremonyHelperClient;
use crate::edge_upstream::EdgeUpstream;
use crate::env::{load_sgx_edge_env, SgxEdgeEnv};
use crate::gateway_ope_api::probe_gateway_ope_api_at_startup;
use crate::seal::{local_mrenclave_hex, SgxSealer};
use crate::seal_sync::{maybe_start_seal_sync, SealSyncConfig};
use crate::tls::{spki_sha256_hex_from_cert_bytes, TlsAcceptor, TlsConfig};
use crate::tls_key_policy::{resolve_tls_key_policy_optional, TlsKeyPolicy};

pub fn run() -> anyhow::Result<()> {
    TlsConfig::install_crypto_provider().context("tls crypto provider")?;

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let env = load_sgx_edge_env().context("load sgx edge env")?;
    env.validate_profile().context("tls/profile policy")?;

    let runtime_mr = local_mrenclave_hex().context("read MRENCLAVE from enclave report")?;
    info!(
        listen = %env.listen_addr,
        region = %env.region,
        mrenclave = %runtime_mr,
        profile = ?env.profile(),
        "starting openapi SGX edge"
    );

    let sealer = env.runtime_sgx_sealer().context("sgx sealer")?;
    let seal_root = env.seal_root().context("seal root")?;

    // Load (or cold-import) TLS material before building the acceptor / attestation platform.
    let (cert_pem, key_pem) =
        prepare_tls_material(&env, &sealer, seal_root, &runtime_mr).context("prepare TLS")?;

    let tls_spki = if let Some(cert) = cert_pem.as_deref() {
        spki_sha256_hex_from_cert_bytes(cert).map_err(|e| anyhow::anyhow!(e))?
    } else {
        warn!("no TLS cert — attestation SPKI unknown (dev only)");
        "unknown".into()
    };

    let platform = SgxAttestationPlatform::from_env(
        &env.build_version,
        &env.code_hash,
        &runtime_mr,
        &tls_spki,
        Some(env.policy_hash_hex()),
    );

    // Hard OPE cutover: F′ dispatch by default; clear HTTP only as non-prod break-glass.
    probe_gateway_ope_api_at_startup(env.profile());
    let upstream = EdgeUpstream::from_env(env.profile(), &env.upstream_base_url)
        .context("upstream (OPE / clear HTTP)")?;

    let authenticator = env.edge_authenticator().context("auth")?;
    if let Some(remote) = authenticator.remote_arc() {
        crate::remote_client::spawn_revocation_poller(remote);
        info!(
            poll_secs = env.revoke_poll_secs,
            "D6-pull revocation poller started"
        );
    }

    let app = Arc::new(App::new(
        env.config(),
        env.limits(),
        authenticator,
        upstream,
        platform,
        env.usage_signer().context("usage signer")?,
    ));

    let tls_acceptor = build_tls_acceptor_from_material(&env, cert_pem.as_deref(), key_pem.as_deref())?;
    let tls_hook = tls_acceptor.map(|acceptor| {
        move |stream: std::net::TcpStream| -> Option<Box<dyn ReadWriteConn>> {
            acceptor
                .accept(stream)
                .ok()
                .map(|s| Box::new(s) as Box<dyn ReadWriteConn>)
        }
    });

    run_edge_server(&env.listen_addr, app, tls_hook)
}

fn use_ceremony_helper(env: &SgxEdgeEnv) -> bool {
    env.ceremony_helper_url
        .as_ref()
        .map(|u| !u.is_empty())
        .unwrap_or(false)
}

fn helper_client(env: &SgxEdgeEnv) -> anyhow::Result<CeremonyHelperClient> {
    // Prefer from_env so OPENAPI_ARTIFACT_SLOT prefixes sealed-key/tls.crt.
    if std::env::var("OPENAPI_CEREMONY_HELPER_URL").is_ok()
        || std::env::var("OPENAPI_ARTIFACT_SLOT").is_ok()
    {
        return CeremonyHelperClient::from_env().context("ceremony helper from_env");
    }
    let url = env
        .ceremony_helper_url
        .as_deref()
        .context("OPENAPI_CEREMONY_HELPER_URL")?;
    CeremonyHelperClient::from_url(url).context("ceremony helper")
}

fn fetch_tls_artifacts(
    helper: &CeremonyHelperClient,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let cert = helper
        .get_artifact("tls.crt")
        .context("fetch tls.crt from ceremony helper")?;
    let sealed = helper
        .get_artifact("sealed-key.json")
        .context("fetch sealed-key.json from ceremony helper")?;
    Ok((cert, sealed))
}

fn unseal_from_helper(
    helper: &CeremonyHelperClient,
    sealer: &SgxSealer,
    seal_root: Option<&[u8; 32]>,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let (cert_pem, sealed_json) = fetch_tls_artifacts(helper)?;
    let blob: SealedTlsKeyBlob =
        serde_json::from_slice(&sealed_json).context("parse sealed-key.json from helper")?;
    let key = sealer
        .unseal_tls_key(&blob, seal_root)
        .context("unseal tls key from helper artifact")?;
    Ok((cert_pem, key))
}

/// Load sealed TLS (or seal-sync import), start seal-sync admin if configured.
fn prepare_tls_material(
    env: &SgxEdgeEnv,
    sealer: &SgxSealer,
    seal_root: Option<[u8; 32]>,
    mrenclave: &str,
) -> anyhow::Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
    let seal_cfg = SealSyncConfig::from_env();
    let key_policy = resolve_tls_key_policy_optional().map_err(anyhow::Error::msg)?;

    let mut cert_pem = None;
    let mut key_pem = None;

    if use_ceremony_helper(env) {
        let helper = helper_client(env)?;
        if helper.has_sealed_key() {
            let (cert, key) = unseal_from_helper(&helper, sealer, seal_root.as_ref())?;
            cert_pem = Some(cert);
            key_pem = Some(key);
        } else if matches!(key_policy, Some(TlsKeyPolicy::SealSync)) || seal_cfg.peer.is_some() {
            info!("no sealed artifact yet — seal-sync cold start");
        } else if seal_cfg.enabled() {
            // Ceremony export-only: may start listen after ACME mint in a separate process.
            info!("no sealed artifact; seal-sync listen may defer until mint");
        } else if env.profile().is_prod() {
            anyhow::bail!(
                "prod requires sealed TLS via ceremony helper (mint or seal-sync import)"
            );
        }

        if seal_cfg.enabled() {
            let (k, c) = maybe_start_seal_sync(
                &seal_cfg,
                mrenclave,
                helper,
                sealer.clone(),
                seal_root,
                key_pem,
                cert_pem,
            )?;
            key_pem = k;
            cert_pem = c;
        }
        return Ok((cert_pem, key_pem));
    }

    // Legacy host-path TLS (non-EDP / tests).
    if seal_cfg.enabled() {
        warn!("seal-sync env set but OPENAPI_CEREMONY_HELPER_URL unset — seal-sync skipped");
    }
    Ok((None, None))
}

fn build_tls_acceptor_from_material(
    env: &SgxEdgeEnv,
    cert_pem: Option<&[u8]>,
    key_pem: Option<&[u8]>,
) -> anyhow::Result<Option<Arc<TlsAcceptor>>> {
    match (cert_pem, key_pem) {
        (Some(cert), Some(key)) => {
            let server_config = crate::tls::load_server_config_from_pem_bytes(cert, key)
                .context("load TLS from PEM bytes")?;
            Ok(Some(Arc::new(TlsAcceptor::new(server_config))))
        }
        _ if use_ceremony_helper(env) => {
            if env.profile().is_prod() {
                anyhow::bail!(
                    "prod requires TLS acceptor (sealed key via helper or seal-sync import)"
                );
            }
            warn!("no TLS material after prepare — plain TCP (dev only)");
            Ok(None)
        }
        _ => {
            // Fall back to path-based loading for host builds.
            build_tls_acceptor_paths(env)
        }
    }
}

fn build_tls_acceptor_paths(env: &SgxEdgeEnv) -> anyhow::Result<Option<Arc<TlsAcceptor>>> {
    let Some(cert_path) = &env.tls_cert_path else {
        if env.profile().is_prod() {
            anyhow::bail!(
                "prod requires OPENAPI_TLS_CERT_PATH (or OPENAPI_CEREMONY_HELPER_URL) and a working TLS acceptor (TLS-001)"
            );
        }
        return Ok(None);
    };
    let sealer = env.runtime_sgx_sealer().context("sgx sealer")?;
    let seal_root = env.seal_root().context("seal root")?;
    let tls_config = TlsConfig::new(cert_path);
    let server_config = if let Some(sealed_path) = &env.tls_sealed_key_path {
        info!(path = %sealed_path, "loading sealed tls private key");
        match tls_config.load_server_config_from_sealed(
            &sealer,
            Path::new(sealed_path),
            seal_root.as_ref(),
        ) {
            Ok(cfg) => cfg,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("operation not supported")
                    || msg.contains("File::open unsupported")
                    || msg.contains("not supported")
                {
                    anyhow::bail!(
                        "TLS File::open failed on this target ({msg}); set OPENAPI_CEREMONY_HELPER_URL so the enclave can fetch tls.crt + sealed-key.json over TCP"
                    );
                }
                return Err(e).context("unseal tls key");
            }
        }
    } else if let Some(key_path) = &env.tls_key_path {
        if env.profile().is_prod() {
            anyhow::bail!("prod forbids plaintext TLS key path (use sealed key)");
        }
        warn!("using plaintext OPENAPI_TLS_KEY_PATH — seal for production");
        TlsConfig::load_server_config_from_plain_key_path(cert_path, key_path)
            .context("load plaintext tls key")?
    } else if env.profile().is_prod() {
        anyhow::bail!("prod requires sealed TLS key for acceptor (TLS-001)");
    } else {
        return Ok(None);
    };
    Ok(Some(Arc::new(TlsAcceptor::new(server_config))))
}

#[cfg(test)]
mod tests {
    #[test]
    fn run_module_linked() {
        assert!(std::path::Path::new("Cargo.toml").exists());
    }
}
