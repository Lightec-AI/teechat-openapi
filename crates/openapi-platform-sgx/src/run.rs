use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use openapi_core::App;
use openapi_edge::{run_edge_server, ReadWriteConn};
use tracing::{info, warn};

use crate::attest::SgxAttestationPlatform;
use crate::env::{load_sgx_edge_env, SgxEdgeEnv};
use crate::seal::{local_mrenclave_hex, SgxSealer};
use crate::tls::{TlsAcceptor, TlsConfig};
use crate::upstream::TcpHttpUpstream;

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

    let tls_spki = tls_spki_hex(&env, &sealer, seal_root.as_ref())?;

    let platform = SgxAttestationPlatform::from_env(
        &env.build_version,
        &env.code_hash,
        &runtime_mr,
        &tls_spki,
    );

    let upstream = TcpHttpUpstream::new(&env.upstream_base_url)
        .map_err(|e| anyhow::anyhow!("upstream: {e}"))?;

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

    let tls_acceptor = build_tls_acceptor(&env, &sealer, seal_root.as_ref())?;
    let tls_hook = tls_acceptor.map(|acceptor| {
        move |stream: std::net::TcpStream| -> Option<Box<dyn ReadWriteConn>> {
            acceptor.accept(stream).ok().map(|s| Box::new(s) as Box<dyn ReadWriteConn>)
        }
    });

    run_edge_server(&env.listen_addr, app, tls_hook)
}

fn tls_spki_hex(
    env: &SgxEdgeEnv,
    sealer: &SgxSealer,
    seal_root: Option<&[u8; 32]>,
) -> anyhow::Result<String> {
    let Some(cert_path) = &env.tls_cert_path else {
        warn!("OPENAPI_TLS_CERT_PATH not set — plain TCP (dev only)");
        return Ok("unknown".into());
    };
    let tls_config = TlsConfig::new(cert_path);
    if let Some(sealed_path) = &env.tls_sealed_key_path {
        tls_config
            .load_server_config_from_sealed(sealer, Path::new(sealed_path), seal_root)
            .context("unseal tls key")?;
        return tls_config.cert_spki_sha256_hex().map_err(|e| anyhow::anyhow!(e));
    }
    if let Some(key_path) = &env.tls_key_path {
        warn!("using plaintext OPENAPI_TLS_KEY_PATH — seal for production");
        TlsConfig::load_server_config_from_plain_key_path(cert_path, key_path)
            .context("load plaintext tls key")?;
        return tls_config.cert_spki_sha256_hex().map_err(|e| anyhow::anyhow!(e));
    }
    warn!("no TLS key configured — plain TCP (dev only)");
    Ok("unknown".into())
}

fn build_tls_acceptor(
    env: &SgxEdgeEnv,
    sealer: &SgxSealer,
    seal_root: Option<&[u8; 32]>,
) -> anyhow::Result<Option<Arc<TlsAcceptor>>> {
    let Some(cert_path) = &env.tls_cert_path else {
        return Ok(None);
    };
    let tls_config = TlsConfig::new(cert_path);
    let server_config = if let Some(sealed_path) = &env.tls_sealed_key_path {
        info!(path = %sealed_path, "loading sealed tls private key");
        tls_config
            .load_server_config_from_sealed(sealer, Path::new(sealed_path), seal_root)
            .context("unseal tls key")?
    } else if let Some(key_path) = &env.tls_key_path {
        warn!("using plaintext OPENAPI_TLS_KEY_PATH — seal for production");
        TlsConfig::load_server_config_from_plain_key_path(cert_path, key_path)
            .context("load plaintext tls key")?
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
