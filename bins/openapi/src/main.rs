use std::io::{Read, Write};
use std::sync::Arc;

use anyhow::Context;
use openapi_core::App;
use openapi_http::{dispatch_request, handle_connection, ParsedRequest};
use openapi_platform_cvm::{
    load_edge_env, CvmAttestationPlatform, TlsAcceptor, TlsConfig, UreqUpstream,
};
use tracing::{info, warn};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let env = load_edge_env().context("load edge env")?;
    info!(listen = %env.listen_addr, region = %env.region, "starting openapi edge");

    let tls_spki = if let (Some(cert), Some(key)) = (&env.tls_cert_path, &env.tls_key_path) {
        TlsConfig {
            cert_path: cert.clone(),
            key_path: key.clone(),
        }
        .cert_spki_sha256_hex()
        .unwrap_or_else(|e| {
            warn!(error = %e, "failed to hash tls cert");
            "unknown".into()
        })
    } else {
        warn!("OPENAPI_TLS_CERT_PATH / OPENAPI_TLS_KEY_PATH not set — plain TCP (dev only)");
        "unknown".into()
    };

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

    let tls_acceptor = match (&env.tls_cert_path, &env.tls_key_path) {
        (Some(cert), Some(key)) => Some(Arc::new(TlsAcceptor::new(
            TlsConfig {
                cert_path: cert.clone(),
                key_path: key.clone(),
            }
            .load_server_config()
            .context("tls config")?,
        ))),
        _ => None,
    };

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
