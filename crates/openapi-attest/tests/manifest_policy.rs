//! Manifest signature + allowlist policy fixtures (offline).

use ed25519_dalek::{Signer, SigningKey};
use openapi_attest::manifest::{
    find_matching_release, parse_and_validate_manifest, verify_manifest_signature,
    verifying_key_from_hex, OpenApiEdgeManifest, PINNED_KEY_ID, PINNED_PUBLIC_KEY_HEX,
};
use openapi_platform::{Measurement, QuoteFormat};
use rand::rngs::OsRng;

const POLICY_HASH: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

fn sample_manifest_json(not_after: &str, launch: &str) -> Vec<u8> {
    format!(
        r#"{{
  "schema": "teechat-openapi-edge-manifest/v1",
  "key_id": "{PINNED_KEY_ID}",
  "published_at": "2026-07-16T00:00:00Z",
  "epoch": 1,
  "not_after": "{not_after}",
  "policy": {{
    "reject_debug": true,
    "max_quote_age_ms": 3600000,
    "require_session_spki_bind": true,
    "require_runtime_policy_pin": true
  }},
  "regions": [{{
    "region": "global",
    "hostnames": ["openapi.teechat.ai"],
    "active": [{{
      "build_version": "0.1.1",
      "code_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "policy_hash": "{POLICY_HASH}",
      "quote_formats": ["snp_report"],
      "measurement": {{
        "kind": "launch_digest",
        "launch_digest": "{launch}",
        "image_digest": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
      }}
    }}],
    "retired": []
  }}]
}}"#
    )
    .into_bytes()
}

#[test]
fn rejects_expired_manifest() {
    let bytes = sample_manifest_json(
        "2020-01-01T00:00:00Z",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let err = parse_and_validate_manifest(&bytes, Some(PINNED_KEY_ID)).unwrap_err();
    assert!(err.to_string().contains("expired"), "{err}");
}

#[test]
fn rejects_unknown_measurement() {
    let bytes = sample_manifest_json(
        "2099-01-01T00:00:00Z",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let m: OpenApiEdgeManifest = serde_json::from_slice(&bytes).unwrap();
    let err = find_matching_release(
        &m,
        "openapi.teechat.ai",
        "0.1.1",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        &Measurement::LaunchDigest {
            launch_digest: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                .into(),
            image_digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
        },
        QuoteFormat::SnpReport,
        Some(POLICY_HASH),
    )
    .unwrap_err();
    assert!(err.to_string().contains("allowlist"), "{err}");
}

#[test]
fn accepts_allowlisted_release() {
    let launch = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let bytes = sample_manifest_json("2099-01-01T00:00:00Z", launch);
    let m: OpenApiEdgeManifest = serde_json::from_slice(&bytes).unwrap();
    find_matching_release(
        &m,
        "openapi.teechat.ai",
        "0.1.1",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        &Measurement::LaunchDigest {
            launch_digest: launch.into(),
            image_digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
        },
        QuoteFormat::SnpReport,
        Some(POLICY_HASH),
    )
    .unwrap();
}

#[test]
fn rejects_active_release_without_required_policy_hash() {
    let bytes = sample_manifest_json(
        "2099-01-01T00:00:00Z",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["regions"][0]["active"][0]
        .as_object_mut()
        .unwrap()
        .remove("policy_hash");
    let bytes = serde_json::to_vec(&value).unwrap();
    let err = parse_and_validate_manifest(&bytes, Some(PINNED_KEY_ID)).unwrap_err();
    assert!(err.to_string().contains("policy_hash required"), "{err}");
}

#[test]
fn rejects_manifest_policy_opt_out() {
    let bytes = sample_manifest_json(
        "2099-01-01T00:00:00Z",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["policy"]["require_runtime_policy_pin"] = serde_json::Value::Bool(false);
    let bytes = serde_json::to_vec(&value).unwrap();
    let err = parse_and_validate_manifest(&bytes, Some(PINNED_KEY_ID)).unwrap_err();
    assert!(
        err.to_string()
            .contains("require_runtime_policy_pin must be true"),
        "{err}"
    );
}

#[test]
fn rejects_runtime_policy_hash_mismatch() {
    let launch = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let bytes = sample_manifest_json("2099-01-01T00:00:00Z", launch);
    let m = parse_and_validate_manifest(&bytes, Some(PINNED_KEY_ID)).unwrap();
    let err = find_matching_release(
        &m,
        "openapi.teechat.ai",
        "0.1.1",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        &Measurement::LaunchDigest {
            launch_digest: launch.into(),
            image_digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
        },
        QuoteFormat::SnpReport,
        Some("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
    )
    .unwrap_err();
    assert!(err.to_string().contains("policy_hash"), "{err}");
}

#[test]
fn rejects_bad_signature_against_pinned_key() {
    let sk = SigningKey::generate(&mut OsRng);
    let body = br#"{"schema":"teechat-openapi-edge-manifest/v1"}"#;
    let sig = sk.sign(body);
    let pinned = verifying_key_from_hex(PINNED_PUBLIC_KEY_HEX).unwrap();
    assert!(verify_manifest_signature(body, &hex::encode(sig.to_bytes()), &pinned).is_err());
}
