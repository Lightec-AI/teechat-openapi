use std::path::Path;

use anyhow::Context;
use openapi_platform_cvm::{load_edge_env, seal_tls_key_file};

fn main() -> anyhow::Result<()> {
    let plain = std::env::args()
        .nth(1)
        .context("usage: seal-tls-key <plain-key.pem> <sealed-out.json>")?;
    let out = std::env::args()
        .nth(2)
        .context("usage: seal-tls-key <plain-key.pem> <sealed-out.json>")?;

    let env = load_edge_env().context("load edge env")?;
    let seal_root = env.seal_root().context("seal root")?;
    let sealer = env.cvm_sealer();

    let blob = seal_tls_key_file(
        &sealer,
        Path::new(&plain),
        Path::new(&out),
        seal_root.as_ref(),
    )
    .context("seal tls key")?;

    println!(
        "sealed tls key -> {} (measurement: {:?})",
        out, blob.measurement
    );
    Ok(())
}
