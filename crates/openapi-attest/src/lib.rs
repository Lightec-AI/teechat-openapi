//! Independent verifier for TeeChat OpenAPI edge attestation challenges.
//!
//! Trust order (fail-closed):
//! 1. **Golden digests** — `Lightec-AI/teechat-golden-digests` → www `.well-known/teechat/golden/`.
//! 2. **App GitHub Releases** — `openapi-edge-attest.json` + `SHA256SUMS` from `teechat-openapi`.
//! 3. **teechat.ai signed app manifest** — only when GitHub is unreachable.
//! 4. Local `--manifest` / `--sig` (and golden local) override for ops.
//!
//! Live challenge is evidence only. See TeeChat `docs/design/golden-digests-publish.md`.

pub mod ceremony;
pub mod challenge_client;
pub mod error;
pub mod github_release;
pub mod golden;
pub mod manifest;
pub mod sgx;
pub mod snp;
pub mod tls_spki;
pub mod verify;

pub use error::{AttestError, Result};
pub use github_release::{
    ATTEST_ASSET_NAME, DEFAULT_GITHUB_OWNER, DEFAULT_GITHUB_REPO, SHA256SUMS_ASSET_NAME,
};
pub use manifest::{
    fetch_signed_manifest, load_signed_manifest_files, verify_signed_manifest_bytes,
    OpenApiEdgeManifest, DEFAULT_MANIFEST_URL, PINNED_KEY_ID, PINNED_PUBLIC_KEY_HEX,
};
pub use verify::{verify_openapi_edge, AttestationVerdict, VerifyOptions};
