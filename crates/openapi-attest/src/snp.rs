//! AMD SEV-SNP attestation report verification (VCEK + ARK/ASK).
//!
//! References:
//! - AMD Pub 57230 — VCEK Certificate and KDS Interface
//! - AMD Pub 56860 — SEV-SNP Firmware ABI
//! - AMD UG 58217 — Platform attestation using VirTEE/SNP

use std::io::Read;

use openapi_platform::{snp_report_reportdata, QuoteFormat};
use sev::certs::snp::{builtin, Certificate, Chain, Verifiable};
use sev::firmware::guest::AttestationReport;
use sha2::{Digest, Sha256};

use crate::error::{AttestError, Result};

const KDS_BASE: &str = "https://kdsintf.amd.com";

#[derive(Debug, Clone)]
pub struct SnpVerifyReport {
    pub product_name: String,
    pub launch_measurement_hex: String,
    pub report_data_hex: String,
    pub chip_id_hex: String,
    pub policy_debug: bool,
    pub guest_svn: u32,
}

/// Challenge-canonical composed LD encoding used by OpenAPI challenge / app-verity bake:
/// `sha256(ascii_hex(raw_MEASUREMENT))` where `raw_MEASUREMENT` is 48 bytes (96 hex).
///
/// Input is the hex encoding of the SNP report MEASUREMENT field (typically lowercase).
/// Hash is over the **ASCII hex string bytes**, not the decoded binary.
pub fn challenge_canonical_launch_digest(raw_measurement_hex: &str) -> String {
    let normalized = raw_measurement_hex.trim().to_ascii_lowercase();
    hex::encode(Sha256::digest(normalized.as_bytes()))
}

pub fn verify_snp_report(quote_b64: &str, reject_debug: bool) -> Result<SnpVerifyReport> {
    let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, quote_b64.trim())
        .map_err(|e| AttestError::Quote(format!("quote_b64: {e}")))?;

    let report = AttestationReport::from_bytes(&raw)
        .map_err(|e| AttestError::Quote(format!("parse SNP report: {e}")))?;

    let policy_debug = report.policy.debug_allowed();
    if reject_debug && policy_debug {
        return Err(AttestError::Policy(
            "SNP report has debug policy bit set".into(),
        ));
    }
    if report.policy.migrate_ma_allowed() {
        return Err(AttestError::Policy(
            "SNP report allows migration agent (policy MIGRATE_MA)".into(),
        ));
    }

    let product = snp_product_name(&report);
    let chip_id = hex::encode(report.chip_id);
    let tcb = report.reported_tcb;
    let vcek_url = format!(
        "{KDS_BASE}/vcek/v1/{product}/{chip_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
        tcb.bootloader, tcb.tee, tcb.snp, tcb.microcode
    );
    let vcek_der = http_get(&vcek_url)?;
    let vcek = Certificate::from_der(&vcek_der)
        .map_err(|e| AttestError::Quote(format!("VCEK parse: {e}")))?;

    let (ark, ask) = builtin_ca(&product)?;
    let chain = Chain {
        ca: sev::certs::snp::ca::Chain { ark, ask },
        vek: vcek,
    };
    (&chain, &report)
        .verify()
        .map_err(|e| AttestError::Quote(format!("SNP VCEK/chain verify: {e}")))?;

    // Cross-check report_data extractor used by binding layer.
    let _ = snp_report_reportdata(quote_b64).map_err(|e| AttestError::Quote(e.to_string()))?;

    Ok(SnpVerifyReport {
        product_name: product,
        launch_measurement_hex: hex::encode(report.measurement),
        report_data_hex: hex::encode(report.report_data),
        chip_id_hex: chip_id,
        policy_debug,
        guest_svn: report.guest_svn,
    })
}

fn builtin_ca(product: &str) -> Result<(Certificate, Certificate)> {
    match product {
        "Milan" => Ok((
            builtin::milan::ark().map_err(|e| AttestError::Quote(format!("Milan ARK: {e}")))?,
            builtin::milan::ask().map_err(|e| AttestError::Quote(format!("Milan ASK: {e}")))?,
        )),
        "Genoa" => Ok((
            builtin::genoa::ark().map_err(|e| AttestError::Quote(format!("Genoa ARK: {e}")))?,
            builtin::genoa::ask().map_err(|e| AttestError::Quote(format!("Genoa ASK: {e}")))?,
        )),
        "Turin" => Ok((
            builtin::turin::ark().map_err(|e| AttestError::Quote(format!("Turin ARK: {e}")))?,
            builtin::turin::ask().map_err(|e| AttestError::Quote(format!("Turin ASK: {e}")))?,
        )),
        other => Err(AttestError::Quote(format!(
            "unsupported SNP product {other}"
        ))),
    }
}

fn snp_product_name(report: &AttestationReport) -> String {
    match report.cpuid_fam_id {
        Some(0x19) => {
            // Family 19h: Milan (models 0x00-0x0f) vs Genoa (0x10+)
            match report.cpuid_mod_id {
                Some(m) if m < 0x10 => "Milan".to_string(),
                _ => "Genoa".to_string(),
            }
        }
        Some(0x1A) => "Turin".to_string(),
        _ => "Genoa".to_string(),
    }
}

fn http_get(url: &str) -> Result<Vec<u8>> {
    // Disk cache: seal-sync importer+exporter both challenge the VIP within ~1s and
    // each verify_snp_report hits AMD KDS; without a cache the second call 429s.
    let cache_dir = std::env::var("OPENAPI_KDS_CACHE_DIR")
        .unwrap_or_else(|_| "/var/tmp/teechat-kds-cache".into());
    let cache_key: String = url
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let cache_path = std::path::Path::new(&cache_dir).join(&cache_key);
    if let Ok(bytes) = std::fs::read(&cache_path) {
        if !bytes.is_empty() {
            return Ok(bytes);
        }
    }

    // Retry 429s — KDS rate-limits aggressively; seal-sync peers share one public IP.
    let mut last_err = None;
    for (attempt, sleep_ms) in [0_u64, 5_000, 15_000, 30_000, 60_000]
        .into_iter()
        .enumerate()
    {
        if sleep_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
        }
        match ureq::get(url).call() {
            Ok(resp) => {
                let status = resp.status();
                if status == 429 {
                    last_err = Some(AttestError::Http(format!("GET {url}: HTTP 429")));
                    continue;
                }
                if !(200..300).contains(&status) {
                    return Err(AttestError::Http(format!("GET {url}: HTTP {status}")));
                }
                let mut buf = Vec::new();
                resp.into_reader()
                    .read_to_end(&mut buf)
                    .map_err(|e| AttestError::Http(e.to_string()))?;
                let _ = std::fs::create_dir_all(&cache_dir);
                let _ = std::fs::write(&cache_path, &buf);
                return Ok(buf);
            }
            Err(e) => {
                last_err = Some(AttestError::Http(format!("GET {url}: {e}")));
                // Network blips: retry; non-retryable failures still exhaust the loop.
                let _ = attempt;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| AttestError::Http(format!("GET {url}: exhausted retries"))))
}

pub fn expected_quote_format() -> QuoteFormat {
    QuoteFormat::SnpReport
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_canonical_is_sha256_of_ascii_hex() {
        let raw = "00".repeat(48);
        let got = challenge_canonical_launch_digest(&raw);
        // sha256(utf8("00" * 48))
        assert_eq!(
            got,
            "cb0216e7ae909ac5f758bc9bc9de34a36e93432ae178dea5a43fcdbf67202c76"
        );
        // Uppercase input normalizes to the same digest.
        assert_eq!(
            challenge_canonical_launch_digest(&raw.to_ascii_uppercase()),
            got
        );
    }
}
