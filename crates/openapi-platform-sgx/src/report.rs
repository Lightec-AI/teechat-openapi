//! SGX REPORT generation with Option A `report_data` binding.

use openapi_platform::PlatformError;

/// Generate a local SGX REPORT whose `reportdata` equals `report_data` (64 bytes).
///
/// Uses `Report::for_target` after deriving self `Targetinfo` — never mutates REPORT bytes
/// after EREPORT. Host builds return an error (no enclave).
#[cfg(target_env = "sgx")]
pub fn enclave_report_with_data(report_data: &[u8; 64]) -> Result<Vec<u8>, PlatformError> {
    use sgx_isa::{Report, Targetinfo};

    let target = Targetinfo::from(Report::for_self());
    let report = Report::for_target(&target, report_data);
    if &report.reportdata != report_data {
        return Err(PlatformError::Attestation(
            "EREPORT reportdata mismatch after for_target".into(),
        ));
    }
    Ok(<Report as AsRef<[u8]>>::as_ref(&report).to_vec())
}

#[cfg(not(target_env = "sgx"))]
pub fn enclave_report_with_data(_report_data: &[u8; 64]) -> Result<Vec<u8>, PlatformError> {
    Err(PlatformError::Attestation(
        "SGX REPORT requires target_env=sgx (enclave build)".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_build_errors_without_enclave() {
        let err = enclave_report_with_data(&[0u8; 64]).unwrap_err();
        assert!(err.to_string().contains("sgx"));
    }
}
