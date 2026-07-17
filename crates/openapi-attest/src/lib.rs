//! Independent verifier for TeeChat OpenAPI edge attestation challenges.
//!
//! Trust order (fail-closed):
//! 1. **GitHub Releases** (primary) — `openapi-edge-attest.json` + optional `SHA256SUMS`
//!    from `Lightec-AI/teechat-openapi`.
//! 2. **teechat.ai signed manifest** — only when GitHub is unreachable; verdict includes a tip.
//! 3. Local `--manifest` / `--sig` override for ops.
//!
//! Then: TLS SPKI, challenge nonce, `report_data` binding, SGX DCAP or SEV-SNP quote crypto,
//! and allowlist pin (build / code_hash / measurement).

pub mod challenge_client;
pub mod error;
pub mod github_release;
pub mod manifest;
pub mod sgx;
pub mod snp;
pub mod tls_spki;
pub mod verify;

pub use error::{AttestError, Result};
pub use github_release::{
    DEFAULT_GITHUB_OWNER, DEFAULT_GITHUB_REPO, ATTEST_ASSET_NAME, SHA256SUMS_ASSET_NAME,
};
pub use manifest::{
    fetch_signed_manifest, load_signed_manifest_files, verify_signed_manifest_bytes,
    OpenApiEdgeManifest, PINNED_KEY_ID, PINNED_PUBLIC_KEY_HEX, DEFAULT_MANIFEST_URL,
};
pub use verify::{verify_openapi_edge, AttestationVerdict, VerifyOptions};
