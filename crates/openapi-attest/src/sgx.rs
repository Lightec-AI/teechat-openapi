//! Intel SGX DCAP Quote3 verification (pure Rust via dcap-qvl).
//!
//! Collateral is fetched from Intel PCS by default. Debug enclaves are rejected
//! when `reject_debug` is true.

use std::time::{SystemTime, UNIX_EPOCH};

use dcap_qvl::collateral::get_collateral_from_pcs;
use dcap_qvl::quote::Report;
use dcap_qvl::verify::rustcrypto::verify as dcap_verify;
use openapi_platform::QuoteFormat;

use crate::error::{AttestError, Result};

#[derive(Debug, Clone)]
pub struct SgxVerifyReport {
    pub mrenclave_hex: String,
    pub mrsigner_hex: String,
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    pub debug: bool,
    pub tcb_status: String,
}

pub fn verify_sgx_dcap_quote(quote_b64: &str, reject_debug: bool) -> Result<SgxVerifyReport> {
    let quote =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, quote_b64.trim())
            .map_err(|e| AttestError::Quote(format!("quote_b64: {e}")))?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| AttestError::Quote(format!("tokio: {e}")))?;

    let collateral = runtime
        .block_on(async { get_collateral_from_pcs(&quote).await })
        .map_err(|e| AttestError::Quote(format!("PCS collateral: {e}")))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let report = dcap_verify(&quote, &collateral, now)
        .map_err(|e| AttestError::Quote(format!("DCAP verify: {e}")))?;

    let status = report.status.clone();
    if status.to_ascii_lowercase().contains("revoked") {
        return Err(AttestError::Policy(format!("TCB revoked: {status}")));
    }

    let enclave = match &report.report {
        Report::SgxEnclave(r) => r,
        other => {
            return Err(AttestError::Quote(format!(
                "expected SGX enclave report, got {other:?}"
            )));
        }
    };

    let debug = (enclave.attributes[0] & 0x02) != 0;
    if reject_debug && debug {
        return Err(AttestError::Policy(
            "SGX quote indicates debug enclave".into(),
        ));
    }

    Ok(SgxVerifyReport {
        mrenclave_hex: hex::encode(enclave.mr_enclave),
        mrsigner_hex: hex::encode(enclave.mr_signer),
        isv_prod_id: enclave.isv_prod_id,
        isv_svn: enclave.isv_svn,
        debug,
        tcb_status: status,
    })
}

pub fn expected_quote_format() -> QuoteFormat {
    QuoteFormat::SgxDcapEcdsa
}
