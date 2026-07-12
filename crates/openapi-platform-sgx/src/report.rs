//! SGX REPORT generation with Option A `report_data` binding.

use openapi_platform::PlatformError;

/// Generate an SGX REPORT for `target_info` whose `reportdata` equals `report_data`.
///
/// Never mutates REPORT bytes after EREPORT. Host builds return an error (no enclave).
#[cfg(target_env = "sgx")]
pub fn enclave_report_for_target(
    target_info: &[u8],
    report_data: &[u8; 64],
) -> Result<Vec<u8>, PlatformError> {
    use sgx_isa::{Report, Targetinfo};

    let target = Targetinfo::try_copy_from(target_info).ok_or_else(|| {
        PlatformError::Attestation(format!(
            "invalid QE Targetinfo ({} bytes)",
            target_info.len()
        ))
    })?;
    let report = Report::for_target(&target, report_data);
    if &report.reportdata != report_data {
        return Err(PlatformError::Attestation(
            "EREPORT reportdata mismatch after for_target".into(),
        ));
    }
    Ok(<Report as AsRef<[u8]>>::as_ref(&report).to_vec())
}

/// Local self-targeted REPORT (lab / debug only — not remotely verifiable).
#[cfg(target_env = "sgx")]
#[allow(dead_code)]
pub fn enclave_report_with_data(report_data: &[u8; 64]) -> Result<Vec<u8>, PlatformError> {
    use sgx_isa::{Report, Targetinfo};

    let target = Targetinfo::from(Report::for_self());
    enclave_report_for_target(target.as_ref(), report_data)
}

#[cfg(not(target_env = "sgx"))]
pub fn enclave_report_for_target(
    _target_info: &[u8],
    _report_data: &[u8; 64],
) -> Result<Vec<u8>, PlatformError> {
    Err(PlatformError::Attestation(
        "SGX REPORT requires target_env=sgx (enclave build)".into(),
    ))
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
