//! Fortanix EDP SGX platform backend for teechat-openapi.

mod acme_ceremony;
mod attest;
mod ceremony_helper;
mod dcap;
mod env;
mod remote_client;
mod report;
mod run;
mod seal;
mod tls;
mod upstream;

pub use acme_ceremony::{
    assert_acme_ceremony_policy, run_acme_ceremony, seal_from_acme_outcome, AcmeMode,
    HelperChallengeSink, HelperDnsResolver,
};
pub use attest::SgxAttestationPlatform;
pub use ceremony_helper::{CeremonyHelperClient, DEFAULT_CEREMONY_HELPER_URL};
pub use env::{
    load_sgx_edge_env, parse_seal_root_hex, write_dev_catalog, OpenApiAuthMode, SgxEdgeEnv,
};
pub use remote_client::{spawn_revocation_poller, TcpL0Client};
pub use run::run;
pub use seal::{local_mrenclave_hex, SgxSealer, SGX_SEAL_ROOT_LABEL, SGX_TLS_SEAL_LABEL};
pub use tls::{
    load_server_config_from_pem_bytes, seal_tls_key_file, spki_sha256_hex_from_cert_bytes,
    spki_sha256_hex_from_cert_path, TlsAcceptor, TlsConfig,
};
pub use upstream::{parse_http_base_url, HttpEndpoint, TcpHttpUpstream};
