use std::path::Path;

use anyhow::Context;
use openapi_platform::{assert_dev_host_seal_tool, load_edge_profile};
use openapi_platform_sgx::{load_sgx_edge_env, seal_tls_key_file};

fn main() -> anyhow::Result<()> {
    let plain = std::env::args()
        .nth(1)
        .context(
            "usage: seal-tls-key-sgx <plain-key.pem> <sealed-out.json>\n\n\
             Dev/lab only. Production: seal inside the enclave ceremony — \
             do not host-seal under OPENAPI_PROFILE=prod (OPS-002).",
        )?;
    let out = std::env::args()
        .nth(2)
        .context("usage: seal-tls-key-sgx <plain-key.pem> <sealed-out.json>")?;

    let profile = load_edge_profile();
    assert_dev_host_seal_tool(profile).map_err(|e| anyhow::anyhow!("{e}"))?;

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

#[cfg(test)]
mod tests {
    use openapi_platform::{assert_dev_host_seal_tool, EdgeProfile, ProfileError};

    #[test]
    fn ops002_prod_refuses_host_sgx_seal_tool() {
        assert!(matches!(
            assert_dev_host_seal_tool(EdgeProfile::Prod),
            Err(ProfileError::ProdHostSealTool)
        ));
    }

    #[test]
    fn ops002_dev_allows_host_sgx_seal_tool() {
        assert!(assert_dev_host_seal_tool(EdgeProfile::Dev).is_ok());
    }
}
