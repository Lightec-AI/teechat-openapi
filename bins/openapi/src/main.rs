use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use openapi_core::App;
use openapi_edge::{run_edge_server, ReadWriteConn};
use openapi_platform::Sealer;
use openapi_platform_cvm::{
    load_edge_env, log_compile_time_features, maybe_start_seal_sync,
    resolve_tls_key_policy_for_profile, CvmAttestationPlatform, CvmSealer, EdgeUpstream,
    SealSyncConfig, TlsAcceptor, TlsConfig, TlsKeyPolicy,
};
use tracing::{info, warn};

fn main() -> anyhow::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("install rustls crypto provider"))?;

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Required: disclose every runtime-affecting Cargo feature on every start.
    log_compile_time_features();

    let env = load_edge_env().context("load edge env")?;
    env.validate_profile().context("tls/profile policy")?;
    info!(
        listen = %env.listen_addr,
        region = %env.region,
        profile = ?env.profile(),
        "starting openapi edge"
    );

    let sealer = env.cvm_sealer();
    let seal_root = env.seal_root().context("seal root")?;

    let seal_sync_cfg = SealSyncConfig::from_env();
    let sealed_path = env
        .tls_sealed_key_path
        .as_ref()
        .map(PathBuf::from);
    let cert_path = env.tls_cert_path.as_ref().map(PathBuf::from);
    let sealed_missing = sealed_path
        .as_ref()
        .map(|p| !p.exists())
        .unwrap_or(false);

    let prod = env.profile().is_prod();
    let key_policy = resolve_tls_key_policy_for_profile(prod)
        .map_err(anyhow::Error::msg)
        .context("tls_key_policy")?;

    // Fleet cold start: sealed key absent — run seal-sync import before any unseal.
    if sealed_missing
        && seal_sync_cfg.peer.is_some()
        && key_policy == TlsKeyPolicy::SealSync
    {
        let cert_path = cert_path
            .clone()
            .context("OPENAPI_TLS_CERT_PATH required for seal-sync cold start")?;
        let sealed_path = sealed_path
            .clone()
            .context("OPENAPI_TLS_SEALED_KEY_PATH required for seal-sync cold start")?;
        info!(
            peer = ?seal_sync_cfg.peer,
            "seal_sync cold start: importing sealed TLS from peer before serve"
        );
        maybe_start_seal_sync(
            &seal_sync_cfg,
            &env.launch_digest,
            &cert_path,
            &sealed_path,
            sealer.clone(),
            None,
        )
        .context("seal-sync cold start")?;
        if !sealed_path.exists() {
            anyhow::bail!(
                "seal-sync cold start finished but sealed key still missing at {}",
                sealed_path.display()
            );
        }
        info!("seal-sync cold start: sealed key present — continuing warm path");
    }

    let tls_spki = tls_spki_hex(&env, &sealer, seal_root.as_ref())?;

    // Blue/green sealed-key sync (private admin :9443 / peer) — see attested-mtls-seal-sync.
    // Warm path: re-run when listen/export needed or peer realign.
    if seal_sync_cfg.enabled() && !(sealed_missing && seal_sync_cfg.peer.is_some()) {
        let (cert_path, sealed_path, key_pem) =
            load_tls_material_for_seal_sync(&env, &sealer, seal_root.as_ref())
                .context("seal-sync tls material")?;
        maybe_start_seal_sync(
            &seal_sync_cfg,
            &env.launch_digest,
            &cert_path,
            &sealed_path,
            sealer.clone(),
            Some(key_pem),
        )
        .context("seal-sync")?;
    } else if seal_sync_cfg.listen.is_some() {
        // After cold import, start export listen if configured (unusual on fleet).
        let (cert_path, sealed_path, key_pem) =
            load_tls_material_for_seal_sync(&env, &sealer, seal_root.as_ref())
                .context("seal-sync tls material after cold import")?;
        maybe_start_seal_sync(
            &seal_sync_cfg,
            &env.launch_digest,
            &cert_path,
            &sealed_path,
            sealer.clone(),
            Some(key_pem),
        )
        .context("seal-sync listen after cold import")?;
    }

    let policy_hash = env.policy_hash_hex();
    info!(%policy_hash, "edge runtime policy_hash");
    let platform = CvmAttestationPlatform::from_env(
        &env.build_version,
        &env.code_hash,
        &env.launch_digest,
        &env.image_digest,
        &tls_spki,
        Some(policy_hash),
    );

    let authenticator = env.edge_authenticator().context("auth")?;

    if let Some(remote) = authenticator.remote_arc() {
        openapi_platform_cvm::spawn_revocation_poller(remote);
        info!(
            poll_secs = env.revoke_poll_secs,
            "D6-pull revocation poller started"
        );
    }

    // Hard OPE cutover: F′ dispatch by default; clear HTTP only as non-prod break-glass.
    let upstream = EdgeUpstream::from_env(env.profile(), &env.upstream_base_url)
        .context("upstream (OPE / clear HTTP)")?;

    let app = Arc::new(App::new(
        env.config(),
        env.limits(),
        authenticator,
        upstream,
        platform,
        env.usage_signer().context("usage signer")?,
    ));

    let tls_acceptor = build_tls_acceptor(&env, &sealer, seal_root.as_ref())?;
    let tls_hook = tls_acceptor.map(|acceptor| {
        move |stream: std::net::TcpStream| -> Option<Box<dyn ReadWriteConn>> {
            acceptor
                .accept(stream)
                .ok()
                .map(|s| Box::new(s) as Box<dyn ReadWriteConn>)
        }
    });

    // Bounded accept pool + idle cut + shed-on-full (DOS-001).
    run_edge_server(&env.listen_addr, app, tls_hook)
}

fn tls_spki_hex(
    env: &openapi_platform_cvm::EdgeEnv,
    sealer: &CvmSealer,
    seal_root: Option<&[u8; 32]>,
) -> anyhow::Result<String> {
    let Some(cert_path) = &env.tls_cert_path else {
        warn!("OPENAPI_TLS_CERT_PATH not set — plain TCP (dev only)");
        return Ok("unknown".into());
    };

    let tls_config = TlsConfig::new(cert_path);

    if let Some(sealed_path) = &env.tls_sealed_key_path {
        if env.tls_key_path.is_some() {
            warn!("OPENAPI_TLS_KEY_PATH ignored when OPENAPI_TLS_SEALED_KEY_PATH is set");
        }
        tls_config
            .load_server_config_from_sealed(sealer, Path::new(sealed_path), seal_root)
            .context("unseal tls key")?;
        return tls_config
            .cert_spki_sha256_hex()
            .map_err(|e| anyhow::anyhow!(e));
    }

    if let Some(key_path) = &env.tls_key_path {
        warn!("using plaintext OPENAPI_TLS_KEY_PATH — seal for production");
        TlsConfig::load_server_config_from_plain_key_path(cert_path, key_path)
            .context("load plaintext tls key")?;
        return tls_config
            .cert_spki_sha256_hex()
            .map_err(|e| anyhow::anyhow!(e));
    }

    warn!("no TLS key configured — plain TCP (dev only)");
    Ok("unknown".into())
}

fn load_tls_material_for_seal_sync(
    env: &openapi_platform_cvm::EdgeEnv,
    sealer: &CvmSealer,
    seal_root: Option<&[u8; 32]>,
) -> anyhow::Result<(PathBuf, PathBuf, Vec<u8>)> {
    let cert_path = env
        .tls_cert_path
        .as_ref()
        .map(PathBuf::from)
        .context("OPENAPI_TLS_CERT_PATH required for seal-sync")?;
    let sealed_path = env
        .tls_sealed_key_path
        .as_ref()
        .map(PathBuf::from)
        .context("OPENAPI_TLS_SEALED_KEY_PATH required for seal-sync")?;
    let key_pem = sealer
        .unseal_tls_key_from_file(&sealed_path, seal_root)
        .context("unseal key for seal-sync")?;
    Ok((cert_path, sealed_path, key_pem))
}

fn build_tls_acceptor(
    env: &openapi_platform_cvm::EdgeEnv,
    sealer: &CvmSealer,
    seal_root: Option<&[u8; 32]>,
) -> anyhow::Result<Option<Arc<TlsAcceptor>>> {
    let Some(cert_path) = &env.tls_cert_path else {
        if env.profile().is_prod() {
            anyhow::bail!(
                "prod requires OPENAPI_TLS_CERT_PATH and a working TLS acceptor (TLS-001)"
            );
        }
        return Ok(None);
    };

    let tls_config = TlsConfig::new(cert_path);

    let server_config = if let Some(sealed_path) = &env.tls_sealed_key_path {
        info!(path = %sealed_path, "loading sealed tls private key");
        tls_config
            .load_server_config_from_sealed(sealer, Path::new(sealed_path), seal_root)
            .context("unseal tls key")?
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
