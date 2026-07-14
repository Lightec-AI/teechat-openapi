use std::path::Path;

use anyhow::Context;
use openapi_platform::{assert_dev_host_seal_tool, load_edge_profile, validate_tls_key_policy};
use openapi_platform_cvm::{load_edge_env, seal_tls_key_file};

fn main() -> anyhow::Result<()> {
    let plain = std::env::args()
        .nth(1)
        .context("usage: seal-tls-key <plain-key.pem> <sealed-out.json>\n\nDev/staging only. Production: use openapi-tls-ceremony inside the SNP guest.")?;
    let out = std::env::args()
        .nth(2)
        .context("usage: seal-tls-key <plain-key.pem> <sealed-out.json>")?;

    let profile = load_edge_profile();
    // OPS-002: host-side seal is lab-only (same gate as seal-tls-key-sgx).
    assert_dev_host_seal_tool(profile).map_err(|e| anyhow::anyhow!("{e}"))?;

    validate_tls_key_policy(profile).ok();

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
