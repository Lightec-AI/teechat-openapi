//! Engine attestation challenge (ARCH-CHAL) — `teechat-engine-challenge-v1`.
//!
//! Shared by OpenAPI CVM and SGX edges. Pin:
//! `docs/design/engine-attestation-challenge.md` (TeaChat) / IE
//! `engine_challenge::report_data` (byte-exact).

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const ENGINE_CHALLENGE_MAGIC: &str = "teechat-engine-challenge-v1";
pub const ENGINE_CHALLENGE_REPORT_DATA_VERSION: u8 = 1;
pub const ENGINE_CHALLENGE_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EngineChallengeError {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("nonce_echo_mismatch")]
    NonceEchoMismatch,
    #[error("report_data_mismatch")]
    ReportDataMismatch,
    #[error("schema_unsupported")]
    SchemaUnsupported,
    #[error("decode: {0}")]
    Decode(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EngineChallengeMeasurement {
    LaunchDigest {
        launch_digest: String,
        image_digest: String,
    },
    Mrenclave {
        mrenclave: String,
    },
}

pub struct EngineChallengeReportDataInput<'a> {
    pub nonce: &'a [u8],
    pub engine_id: &'a str,
    pub epoch_id: &'a str,
    pub not_before: &'a str,
    pub not_after: &'a str,
    pub usage_signing_public_raw: &'a [u8],
    pub mlkem_encap_key_raw: &'a [u8],
    pub x25519_public_raw: &'a [u8],
    pub gpu_evidence_sha256: &'a [u8],
    pub policy_hash: &'a [u8],
    pub measurement: &'a EngineChallengeMeasurement,
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn decode_hex_32(raw: &str, label: &'static str) -> Result<[u8; 32], EngineChallengeError> {
    let cleaned = raw.trim().to_ascii_lowercase();
    if cleaned.len() != 64 || !cleaned.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(EngineChallengeError::Invalid(label));
    }
    let bytes = hex::decode(cleaned).map_err(|_| EngineChallengeError::Invalid(label))?;
    bytes
        .try_into()
        .map_err(|_| EngineChallengeError::Invalid(label))
}

fn measurement_body(
    measurement: &EngineChallengeMeasurement,
) -> Result<Vec<u8>, EngineChallengeError> {
    match measurement {
        EngineChallengeMeasurement::Mrenclave { mrenclave } => {
            let mut body = Vec::with_capacity(33);
            body.push(0x01);
            body.extend_from_slice(&decode_hex_32(mrenclave, "invalid_mrenclave")?);
            Ok(body)
        }
        EngineChallengeMeasurement::LaunchDigest {
            launch_digest,
            image_digest,
        } => {
            let mut body = Vec::with_capacity(65);
            body.push(0x02);
            body.extend_from_slice(&decode_hex_32(launch_digest, "invalid_launch_digest")?);
            body.extend_from_slice(&decode_hex_32(image_digest, "invalid_image_digest")?);
            Ok(body)
        }
    }
}

pub fn build_engine_challenge_preimage(
    input: &EngineChallengeReportDataInput<'_>,
) -> Result<Vec<u8>, EngineChallengeError> {
    if input.nonce.len() != 32 {
        return Err(EngineChallengeError::Invalid("nonce_must_be_32_bytes"));
    }
    if input.gpu_evidence_sha256.len() != 32 {
        return Err(EngineChallengeError::Invalid("gpu_hash_must_be_32_bytes"));
    }
    if input.policy_hash.len() != 32 {
        return Err(EngineChallengeError::Invalid(
            "policy_hash_must_be_32_bytes",
        ));
    }

    let mut window = Vec::with_capacity(input.not_before.len() + input.not_after.len() + 1);
    window.extend_from_slice(input.not_before.as_bytes());
    window.push(0);
    window.extend_from_slice(input.not_after.as_bytes());

    let measurement = measurement_body(input.measurement)?;
    let mut preimage = Vec::with_capacity(315 + measurement.len());
    preimage.extend_from_slice(ENGINE_CHALLENGE_MAGIC.as_bytes());
    preimage.extend_from_slice(input.nonce);
    preimage.extend_from_slice(&sha256(input.engine_id.as_bytes()));
    preimage.extend_from_slice(&sha256(input.epoch_id.as_bytes()));
    preimage.extend_from_slice(&sha256(&window));
    preimage.extend_from_slice(&sha256(input.usage_signing_public_raw));
    preimage.extend_from_slice(&sha256(input.mlkem_encap_key_raw));
    preimage.extend_from_slice(&sha256(input.x25519_public_raw));
    preimage.extend_from_slice(input.gpu_evidence_sha256);
    preimage.extend_from_slice(input.policy_hash);
    preimage.extend_from_slice(&measurement);
    Ok(preimage)
}

/// SNP REPORT_DATA = SHA-256(preimage) || 32 zero bytes.
pub fn build_engine_challenge_report_data(
    input: &EngineChallengeReportDataInput<'_>,
) -> Result<[u8; 64], EngineChallengeError> {
    let digest = sha256(&build_engine_challenge_preimage(input)?);
    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&digest);
    Ok(report_data)
}

pub fn encode_nonce_b64_url(nonce: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(nonce)
}

pub fn decode_nonce_b64_url(raw: &str) -> Result<[u8; 32], EngineChallengeError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(raw.trim())
        .map_err(|_| EngineChallengeError::Invalid("invalid_nonce_b64"))?;
    decoded
        .try_into()
        .map_err(|_| EngineChallengeError::Invalid("nonce_must_be_32_bytes"))
}

fn decode_b64(raw: &str) -> Result<Vec<u8>, EngineChallengeError> {
    let trimmed = raw.trim();
    URL_SAFE_NO_PAD
        .decode(trimmed)
        .or_else(|_| STANDARD.decode(trimmed))
        .map_err(|e| EngineChallengeError::Decode(e.to_string()))
}

/// Wire response from F′ / engine challenge (subset used by edges).
#[derive(Debug, Clone, Deserialize)]
pub struct EngineChallengeWireResponse {
    pub schema_version: u8,
    pub report_data_version: u8,
    pub engine: EngineChallengeWireEngine,
    pub epoch: EngineChallengeWireEpoch,
    pub challenge_nonce_b64: String,
    pub cpu: EngineChallengeWireCpu,
    pub gpu: Option<EngineChallengeWireGpu>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EngineChallengeWireEngine {
    pub engine_id: String,
    pub policy_hash: String,
    pub measurement: EngineChallengeWireMeasurement,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EngineChallengeWireMeasurement {
    pub kind: String,
    pub launch_digest: Option<String>,
    pub image_digest: Option<String>,
    pub mrenclave: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EngineChallengeWireEpoch {
    pub epoch_id: String,
    pub not_before: String,
    pub not_after: String,
    pub mlkem_encapsulation_key: String,
    pub x25519_public: String,
    pub usage_signing_public: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EngineChallengeWireCpu {
    pub quote_b64: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EngineChallengeWireGpu {
    pub evidence_sha256: String,
}

fn measurement_from_wire(
    m: &EngineChallengeWireMeasurement,
) -> Result<EngineChallengeMeasurement, EngineChallengeError> {
    if m.kind == "mrenclave" {
        let mr = m
            .mrenclave
            .as_deref()
            .ok_or(EngineChallengeError::Invalid("invalid_measurement"))?;
        return Ok(EngineChallengeMeasurement::Mrenclave {
            mrenclave: mr.to_string(),
        });
    }
    let ld = m
        .launch_digest
        .as_deref()
        .ok_or(EngineChallengeError::Invalid("invalid_measurement"))?;
    let id = m
        .image_digest
        .as_deref()
        .ok_or(EngineChallengeError::Invalid("invalid_measurement"))?;
    Ok(EngineChallengeMeasurement::LaunchDigest {
        launch_digest: ld.to_string(),
        image_digest: id.to_string(),
    })
}

/// Verify nonce echo + report_data binding against the challenge response.
/// Does not perform AMD KDS / DCAP crypto (callers may do that separately).
pub fn verify_engine_challenge_response(
    expected_nonce: &[u8; 32],
    doc: &EngineChallengeWireResponse,
) -> Result<(), EngineChallengeError> {
    if doc.schema_version != ENGINE_CHALLENGE_SCHEMA_VERSION
        || doc.report_data_version != ENGINE_CHALLENGE_REPORT_DATA_VERSION
    {
        return Err(EngineChallengeError::SchemaUnsupported);
    }
    let echoed = decode_nonce_b64_url(&doc.challenge_nonce_b64)?;
    if &echoed != expected_nonce {
        return Err(EngineChallengeError::NonceEchoMismatch);
    }

    let usage = decode_b64(&doc.epoch.usage_signing_public)?;
    let mlkem = decode_b64(&doc.epoch.mlkem_encapsulation_key)?;
    let x25519 = decode_b64(&doc.epoch.x25519_public)?;
    let policy_hash = decode_hex_32(&doc.engine.policy_hash, "invalid_policy_hash")?;
    let gpu_hash = match &doc.gpu {
        Some(g) => decode_hex_32(&g.evidence_sha256, "invalid_gpu_hash")?,
        None => [0u8; 32],
    };
    let measurement = measurement_from_wire(&doc.engine.measurement)?;
    let expected = build_engine_challenge_report_data(&EngineChallengeReportDataInput {
        nonce: expected_nonce,
        engine_id: &doc.engine.engine_id,
        epoch_id: &doc.epoch.epoch_id,
        not_before: &doc.epoch.not_before,
        not_after: &doc.epoch.not_after,
        usage_signing_public_raw: &usage,
        mlkem_encap_key_raw: &mlkem,
        x25519_public_raw: &x25519,
        gpu_evidence_sha256: &gpu_hash,
        policy_hash: &policy_hash,
        measurement: &measurement,
    })?;

    // Prefer explicit report_data_b64 on the quote wrapper when present; else
    // extract from SNP report bytes (offset 0x50).
    let quote = decode_b64(&doc.cpu.quote_b64)?;
    let actual = extract_report_data_from_quote(&quote)?;
    if actual != expected {
        return Err(EngineChallengeError::ReportDataMismatch);
    }
    Ok(())
}

fn report_data_from_raw_snp(raw: &[u8]) -> Result<[u8; 64], EngineChallengeError> {
    // AMD SEV-SNP attestation report: REPORT_DATA at offset 0x50 (64 bytes).
    const SNP_REPORT_DATA_OFFSET: usize = 0x50;
    if raw.len() < SNP_REPORT_DATA_OFFSET + 64 {
        return Err(EngineChallengeError::Invalid("quote_missing_report_data"));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&raw[SNP_REPORT_DATA_OFFSET..SNP_REPORT_DATA_OFFSET + 64]);
    Ok(out)
}

fn extract_report_data_from_quote(quote: &[u8]) -> Result<[u8; 64], EngineChallengeError> {
    // TeeChat engine quotes are JSON wrappers (`{"v":2,"report_data_b64",…}`). Prefer the
    // explicit field (and nested `report_b64`) before treating bytes as a raw SNP report —
    // wrappers are longer than 0x50+64, so a raw-first path misreads ASCII as report_data
    // and fails closed with report_data_mismatch (matches TS engine-challenge-client).
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(quote) {
        if let Some(b64) = v.get("report_data_b64").and_then(|x| x.as_str()) {
            let bytes = decode_b64(b64)?;
            return bytes
                .try_into()
                .map_err(|_| EngineChallengeError::Invalid("report_data_len"));
        }
        if let Some(rb64) = v.get("report_b64").and_then(|x| x.as_str()) {
            let raw = decode_b64(rb64)?;
            return report_data_from_raw_snp(&raw);
        }
    }
    report_data_from_raw_snp(quote)
}

/// Whether production profiles must challenge before encrypt (default on).
/// Unit tests default off unless explicitly enabled.
pub fn require_engine_challenge_from_env() -> bool {
    match std::env::var("OPENAPI_OPE_REQUIRE_ENGINE_CHALLENGE") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !(v == "0" || v == "false" || v == "no" || v == "off")
        }
        Err(_) => !cfg!(test),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch_measurement() -> EngineChallengeMeasurement {
        EngineChallengeMeasurement::LaunchDigest {
            launch_digest: "a".repeat(64),
            image_digest: "b".repeat(64),
        }
    }

    #[test]
    fn report_data_matches_typescript_reference_vector() {
        let nonce = [1u8; 32];
        let usage = [2u8; 32];
        let mlkem = [3u8; 1184];
        let x25519 = [4u8; 32];
        let gpu_hash = [0u8; 32];
        let policy_hash = [5u8; 32];
        let measurement = launch_measurement();
        let input = EngineChallengeReportDataInput {
            nonce: &nonce,
            engine_id: "eng-1",
            epoch_id: "ep-1",
            not_before: "2026-08-01T00:00:00.000Z",
            not_after: "2026-08-02T00:00:00.000Z",
            usage_signing_public_raw: &usage,
            mlkem_encap_key_raw: &mlkem,
            x25519_public_raw: &x25519,
            gpu_evidence_sha256: &gpu_hash,
            policy_hash: &policy_hash,
            measurement: &measurement,
        };
        let report_data = build_engine_challenge_report_data(&input).unwrap();
        assert_eq!(
            hex::encode(report_data),
            concat!(
                "de0fbdb204520b8d945f7286f4881ddee31f196ca5d0fe34ead2cfae6a272ff2",
                "0000000000000000000000000000000000000000000000000000000000000000"
            )
        );
    }

    #[test]
    fn extract_prefers_json_wrapper_report_data_b64_over_raw_offset() {
        let expected = [0xABu8; 64];
        // Long JSON so a naive raw-at-0x50 path would succeed with wrong bytes.
        let pad = "x".repeat(200);
        let wrapper = serde_json::json!({
            "v": 2,
            "kind": "sev-snp",
            "report_b64": STANDARD.encode([0u8; 128]),
            "report_data_b64": STANDARD.encode(expected),
            "pad": pad,
        });
        let bytes = serde_json::to_vec(&wrapper).unwrap();
        assert!(bytes.len() >= 0x50 + 64);
        let got = extract_report_data_from_quote(&bytes).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn verify_engine_challenge_accepts_json_wrapped_quote() {
        let nonce = [1u8; 32];
        let usage = [2u8; 32];
        let mlkem = [3u8; 1184];
        let x25519 = [4u8; 32];
        let gpu_hash = [0u8; 32];
        let policy_hash = [5u8; 32];
        let measurement = launch_measurement();
        let report_data = build_engine_challenge_report_data(&EngineChallengeReportDataInput {
            nonce: &nonce,
            engine_id: "eng-1",
            epoch_id: "ep-1",
            not_before: "2026-08-01T00:00:00.000Z",
            not_after: "2026-08-02T00:00:00.000Z",
            usage_signing_public_raw: &usage,
            mlkem_encap_key_raw: &mlkem,
            x25519_public_raw: &x25519,
            gpu_evidence_sha256: &gpu_hash,
            policy_hash: &policy_hash,
            measurement: &measurement,
        })
        .unwrap();
        let quote = serde_json::to_vec(&serde_json::json!({
            "v": 2,
            "kind": "sev-snp",
            "report_b64": STANDARD.encode([0u8; 128]),
            "report_data_b64": STANDARD.encode(report_data),
        }))
        .unwrap();
        let doc: EngineChallengeWireResponse = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "report_data_version": 1,
            "engine": {
                "engine_id": "eng-1",
                "build_version": "0.15.0",
                "measurement": {
                    "kind": "launch_digest",
                    "launch_digest": "a".repeat(64),
                    "image_digest": "b".repeat(64),
                },
                "policy_hash": hex::encode(policy_hash),
            },
            "epoch": {
                "epoch_id": "ep-1",
                "not_before": "2026-08-01T00:00:00.000Z",
                "not_after": "2026-08-02T00:00:00.000Z",
                "usage_signing_public": STANDARD.encode(usage),
                "mlkem_encapsulation_key": STANDARD.encode(mlkem),
                "x25519_public": STANDARD.encode(x25519),
            },
            "challenge_nonce_b64": encode_nonce_b64_url(&nonce),
            "cpu": { "quote_b64": STANDARD.encode(quote) },
        }))
        .unwrap();
        verify_engine_challenge_response(&nonce, &doc).unwrap();
    }
}
