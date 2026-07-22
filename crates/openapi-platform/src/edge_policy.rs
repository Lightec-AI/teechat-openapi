//! Runtime edge policy digest for challenge + app allowlist binding.
//!
//! Not part of SNP `report_data` v1 preimage (locked). Honest measured binaries
//! report `policy_hash` in the challenge JSON; verifiers pin it on allowlist rows.
//! See TeeChat `docs/design/openapi-edge-blue-green.md` / attestation challenge docs.
//!
//! **Secrets are never included** (tokens, PEM keys). Cert material is excluded
//! (SPKI is bound separately).

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Canonical fields that shape who the edge trusts and where it sends traffic.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EdgeRuntimePolicy {
    /// Always `"remote"` in production builds (catalog mode is `catalog-auth` only).
    pub auth: String,
    pub region: String,
    pub catalog_verify_key_hex: String,
    pub l0_authorize_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub l0_revocations_url: Option<String>,
    /// F′ gateway OPE API base (prod hard cutover).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_ope_api_url: Option<String>,
    /// Clear-HTTP upstream base (dev / break-glass only; still hashed when set).
    pub upstream_base_url: String,
}

impl EdgeRuntimePolicy {
    /// Stable SHA-256 over compact JSON with sorted keys (serde field order).
    pub fn policy_hash_hex(&self) -> String {
        let bytes = serde_json::to_vec(self).expect("EdgeRuntimePolicy serializes");
        hex::encode(Sha256::digest(&bytes))
    }
}

/// Build policy from common edge env knobs (no secrets).
pub fn edge_runtime_policy_from_parts(
    auth: &str,
    region: &str,
    catalog_verify_key_hex: &str,
    l0_authorize_url: Option<&str>,
    l0_revocations_url: Option<&str>,
    gateway_ope_api_url: Option<&str>,
    upstream_base_url: &str,
) -> EdgeRuntimePolicy {
    EdgeRuntimePolicy {
        auth: auth.to_ascii_lowercase(),
        region: region.to_string(),
        catalog_verify_key_hex: catalog_verify_key_hex.to_ascii_lowercase(),
        l0_authorize_url: l0_authorize_url.unwrap_or("").to_string(),
        l0_revocations_url: l0_revocations_url
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty()),
        gateway_ope_api_url: gateway_ope_api_url
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty()),
        upstream_base_url: upstream_base_url.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_hash_stable() {
        let a = edge_runtime_policy_from_parts(
            "remote",
            "global",
            "aa",
            Some("https://l0/authorize"),
            Some("https://l0/revocations"),
            Some("https://gw:8791"),
            "http://unused",
        );
        let b = edge_runtime_policy_from_parts(
            "remote",
            "global",
            "AA",
            Some("https://l0/authorize"),
            Some("https://l0/revocations"),
            Some("https://gw:8791"),
            "http://unused",
        );
        assert_eq!(a.policy_hash_hex(), b.policy_hash_hex());
        assert_eq!(a.policy_hash_hex().len(), 64);
    }

    #[test]
    fn policy_hash_changes_on_upstream() {
        let a = edge_runtime_policy_from_parts(
            "remote",
            "global",
            "aa",
            Some("https://l0/a"),
            None,
            None,
            "http://one",
        );
        let b = edge_runtime_policy_from_parts(
            "remote",
            "global",
            "aa",
            Some("https://l0/a"),
            None,
            None,
            "http://two",
        );
        assert_ne!(a.policy_hash_hex(), b.policy_hash_hex());
    }
}
