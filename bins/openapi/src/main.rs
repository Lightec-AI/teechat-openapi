use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use openapi_core::App;
use openapi_edge::{run_edge_server, ReadWriteConn};
use openapi_platform_cvm::{
    load_edge_env, CvmAttestationPlatform, CvmSealer, EdgeUpstream, TlsAcceptor, TlsConfig,
};
use tracing::{info, warn};

fn main() -> anyhow::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("install rustls crypto provider"))?;

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

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

    let tls_spki = tls_spki_hex(&env, &sealer, seal_root.as_ref())?;

    let platform = CvmAttestationPlatform::from_env(
        &env.build_version,
        &env.code_hash,
        &env.launch_digest,
        &env.image_digest,
        &tls_spki,
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

fn build_tls_acceptor(
    env: &openapi_platform_cvm::EdgeEnv,
    sealer: &CvmSealer,
    seal_root: Option<&[u8; 32]>,
) -> anyhow::Result<Option<Arc<TlsAcceptor>>> {
    let Some(cert_path) = &env.tls_cert_path else {
        if env.profile().is_prod() {
            anyhow::bail!("prod requires OPENAPI_TLS_CERT_PATH and a working TLS acceptor (TLS-001)");
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
