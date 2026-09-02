//! Fortanix EDP SGX platform backend for teechat-openapi.

mod acme_ceremony;
mod attest;
mod ceremony_helper;
mod dcap;
mod edge_upstream;
mod env;
mod gateway_ope_api;
mod ope_upstream;
mod ope_wrap;
mod remote_client;
mod report;
mod run;
mod seal;
mod seal_sync;
mod sgx_channel_identity;
mod tls;
mod tls_key_policy;
mod upstream;

#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub use acme_ceremony::{
    assert_acme_ceremony_policy, run_acme_ceremony, seal_from_acme_outcome, AcmeMode,
    HelperChallengeSink, HelperDnsResolver, HelperHttpsRelayTransport,
};
pub use attest::SgxAttestationPlatform;
pub use ceremony_helper::{CeremonyHelperClient, DEFAULT_CEREMONY_HELPER_URL};
pub use edge_upstream::EdgeUpstream;
pub use env::{
    load_sgx_edge_env, parse_seal_root_hex, write_dev_catalog, OpenApiAuthMode, SgxEdgeEnv,
};
pub use gateway_ope_api::{
    probe_gateway_ope_api_at_startup, require_gateway_ope_api_healthy, DispatchRequest,
    DispatchResponse, GatewayOpeApiClient, GatewayOpeApiConfig, GatewayOpeApiError, HealthResponse,
    InventoryEngine, InventoryResponse, PreassignRequest, PreassignResponse, PreassignTrust,
};
pub use ope_upstream::{clear_http_break_glass_enabled, OpeDispatchUpstream};
pub use remote_client::{spawn_revocation_poller, TcpL0Client};
pub use run::run;
pub use seal::{local_mrenclave_hex, SgxSealer, SGX_SEAL_ROOT_LABEL, SGX_TLS_SEAL_LABEL};
pub use seal_sync::{
    maybe_start_seal_sync, run_seal_sync_client, spawn_seal_sync_server, DcapChannelAttestor,
    EdgeSealSyncAttestor, SealSyncConfig, SgxLocalSealer,
};
pub use tls::{
    load_server_config_from_pem_bytes, seal_tls_key_file, spki_sha256_hex_from_cert_bytes,
    spki_sha256_hex_from_cert_path, TlsAcceptor, TlsConfig,
};
pub use tls_key_policy::{resolve_tls_key_policy, resolve_tls_key_policy_optional, TlsKeyPolicy};
pub use upstream::{parse_http_base_url, HttpEndpoint, TcpHttpUpstream};
