use std::path::Path;

use anyhow::Context;
use openapi_platform_sgx::{load_sgx_edge_env, seal_tls_key_file};

fn main() -> anyhow::Result<()> {
    let plain = std::env::args()
        .nth(1)
        .context("usage: seal-tls-key-sgx <plain-key.pem> <sealed-out.json>")?;
    let out = std::env::args()
        .nth(2)
        .context("usage: seal-tls-key-sgx <plain-key.pem> <sealed-out.json>")?;

    let env = load_sgx_edge_env().context("load sgx edge env (need OPENAPI_MRENCLAVE)")?;
    let seal_root = env.seal_root().context("seal root")?;
    let sealer = env.sgx_sealer();

    let blob = seal_tls_key_file(
        &sealer,
        Path::new(&plain),
        Path::new(&out),
        seal_root.as_ref(),
    )
    .context("seal tls key")?;

    println!(
        "sealed tls key -> {} (mrenclave={})",
        out, env.mrenclave
    );
    println!("measurement: {:?}", blob.measurement);
    Ok(())
}
