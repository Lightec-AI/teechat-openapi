use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use openapi_core::App;
use openapi_http::{dispatch_request, handle_connection, ParsedRequest};
use openapi_platform_cvm::{
    load_edge_env, CvmAttestationPlatform, CvmSealer, TlsAcceptor, TlsConfig, UreqUpstream,
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
    info!(listen = %env.listen_addr, region = %env.region, "starting openapi edge");

    let seal_root = env.seal_root().context("seal root")?;
    let sealer = env.cvm_sealer();

    let tls_spki = tls_spki_hex(&env, &sealer, seal_root.as_ref())?;

    let platform = CvmAttestationPlatform::from_env(
        &env.build_version,
        &env.code_hash,
        &env.launch_digest,
        &env.image_digest,
        &tls_spki,
    );

    let app = Arc::new(App::new(
        env.config(),
        env.limits(),
        env.authenticator().context("catalog")?,
        UreqUpstream::new(env.upstream_base_url.clone()),
        platform,
        env.usage_signer().context("usage signer")?,
    ));

    let listener = std::net::TcpListener::bind(&env.listen_addr).context("bind listen addr")?;
    info!(addr = ?listener.local_addr()?, "listening");

    let tls_acceptor = build_tls_acceptor(&env, &sealer, seal_root.as_ref())?;

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "accept failed");
                continue;
            }
        };
        let app = Arc::clone(&app);
        let tls = tls_acceptor.clone();
        std::thread::spawn(move || {
            if let Some(acceptor) = tls {
                if let Ok(mut tls_stream) = acceptor.accept(stream) {
                    serve_tls(&app, &mut tls_stream);
                }
            } else {
                let _ = handle_connection(stream, app);
            }
        });
    }

    Ok(())
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

fn serve_tls<U, P>(app: &Arc<App<U, P>>, tls_stream: &mut (impl Read + Write))
where
    U: openapi_core::UpstreamForwarder + 'static,
    P: openapi_platform::AttestationPlatform + 'static,
{
    let mut buffer = vec![0u8; 1024 * 256];
    let mut total = 0usize;
    loop {
        let n = match tls_stream.read(&mut buffer[total..]) {
            Ok(0) => return,
            Ok(n) => n,
            Err(e) => {
                warn!(error = %e, "tls read");
                return;
            }
        };
        total += n;
        match ParsedRequest::parse(&buffer[..total]) {
            Ok(Some(req)) => {
                let response = dispatch_request(
                    app,
                    &req.method,
                    &req.path,
                    req.headers.get("authorization").map(String::as_str),
                    &req.body,
                );
                let _ = tls_stream.write_all(&response);
                let _ = tls_stream.flush();
                return;
            }
            Ok(None) => {
                if total >= buffer.len() {
                    return;
                }
                continue;
            }
            Err(_) => return,
        }
    }
}
