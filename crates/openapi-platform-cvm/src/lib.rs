mod attest;
mod env;
mod gateway_ope_api;
mod guest_digest;
mod push;
mod remote_client;
mod seal;
mod snp_report;
mod tls;
mod tls_ceremony;
mod upstream;

pub use attest::CvmAttestationPlatform;
pub use env::{load_edge_env, write_dev_catalog, EdgeEnv, OpenApiAuthMode};
pub use gateway_ope_api::{
    probe_gateway_ope_api_at_startup, DispatchRequest, DispatchResponse, GatewayOpeApiClient,
    GatewayOpeApiConfig, GatewayOpeApiError, HealthResponse,
};
pub use remote_client::{spawn_revocation_poller, UreqL0AuthorizeClient};
// push.rs kept for reference but unused (D6-pull).
pub use guest_digest::{read_attested_launch_digest, verify_launch_digest_attested};
pub use seal::CvmSealer;
pub use tls::{seal_tls_key_file, spki_sha256_hex_from_cert_path, TlsAcceptor, TlsConfig};
pub use tls_ceremony::{
    acme_live_dir, assert_no_plaintext_privkey_on_disk, assert_prod_ceremony_policy,
    discover_acme_privkey_paths, install_cert_chain, seal_from_acme_live, shred_path,
    CeremonyError, TlsCeremonyPaths,
};
pub use upstream::UreqUpstream;
