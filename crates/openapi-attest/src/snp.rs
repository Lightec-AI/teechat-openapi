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
    let resp = ureq::get(url)
        .call()
        .map_err(|e| AttestError::Http(format!("GET {url}: {e}")))?;
    if !(200..300).contains(&resp.status()) {
        return Err(AttestError::Http(format!(
            "GET {url}: HTTP {}",
            resp.status()
        )));
    }
    let mut buf = Vec::new();
    resp.into_reader()
        .read_to_end(&mut buf)
        .map_err(|e| AttestError::Http(e.to_string()))?;
    Ok(buf)
}

pub fn expected_quote_format() -> QuoteFormat {
    QuoteFormat::SnpReport
}
