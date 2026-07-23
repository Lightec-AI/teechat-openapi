//! SEV-SNP attestation report with Option A `report_data` binding.

use openapi_platform::{PlatformError, REPORT_DATA_LEN};

#[cfg(target_os = "linux")]
use openapi_platform::SNP_REPORT_DATA_OFFSET;

/// Fetch an SNP attestation report that embeds `report_data` at offset 0x50.
///
/// Uses `snpguest report` when available. Returns [`PlatformError::Attestation`] when the
/// platform cannot produce hardware evidence (CI, non-SNP hosts).
pub fn snp_report_with_data(report_data: &[u8; REPORT_DATA_LEN]) -> Result<Vec<u8>, PlatformError> {
    #[cfg(target_os = "linux")]
    {
        snp_report_linux(report_data)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = report_data;
        Err(PlatformError::Attestation(
            "SNP report requires Linux with snpguest / SEV-SNP guest".into(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn snpguest_bin() -> String {
    // Prefer explicit path (Talos data-disk layout) — do not rely on PATH alone.
    if let Ok(p) = std::env::var("OPENAPI_SNPGUEST_BIN") {
        let p = p.trim();
        if !p.is_empty() {
            return p.to_string();
        }
    }
    std::process::Command::new("sh")
        .arg("-c")
        .arg("command -v snpguest")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "snpguest".into())
}

#[cfg(target_os = "linux")]
fn snp_report_linux(report_data: &[u8; REPORT_DATA_LEN]) -> Result<Vec<u8>, PlatformError> {
    use std::path::Path;
    use std::process::Command;

    let snpguest = snpguest_bin();
    let snpguest_ok = Path::new(&snpguest).is_file()
        || Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {snpguest}"))
            .output()
            .ok()
            .filter(|o| o.status.success())
            .is_some();

    if !snpguest_ok {
        let hint = if Path::new("/dev/sev-guest").exists() {
            "install snpguest (device present but CLI missing); set OPENAPI_SNPGUEST_BIN"
        } else {
            "/dev/sev-guest missing and snpguest not in PATH"
        };
        return Err(PlatformError::Attestation(format!(
            "SNP report unavailable: {hint}"
        )));
    }

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = std::env::temp_dir().join(format!(
        "teechat-openapi-snp-report-{}-{stamp}.bin",
        std::process::id()
    ));
    let request = std::env::temp_dir().join(format!(
        "teechat-openapi-snp-request-{}-{stamp}.bin",
        std::process::id()
    ));
    std::fs::write(&request, report_data).map_err(|e| PlatformError::Io(e.to_string()))?;
    let out = Command::new(&snpguest)
        .args([
            "report",
            // snpguest 0.10: report <att-report-path> <request-file>
            tmp.to_str().unwrap_or("/dev/null"),
            request.to_str().unwrap_or("/dev/null"),
            "-v",
            "0",
        ])
        .output()
        .map_err(|e| PlatformError::Attestation(format!("snpguest spawn: {e}")))?;
    let _ = std::fs::remove_file(&request);
    if !out.status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(PlatformError::Attestation(format!(
            "snpguest report failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    let bytes = std::fs::read(&tmp).map_err(|e| PlatformError::Io(e.to_string()))?;
    let _ = std::fs::remove_file(&tmp);
    if bytes.len() < SNP_REPORT_DATA_OFFSET + REPORT_DATA_LEN {
        return Err(PlatformError::Attestation(format!(
            "snpguest report too short: {} bytes",
            bytes.len()
        )));
    }
    if &bytes[SNP_REPORT_DATA_OFFSET..SNP_REPORT_DATA_OFFSET + REPORT_DATA_LEN] != report_data {
        return Err(PlatformError::Attestation(
            "snpguest report REPORT_DATA does not match request".into(),
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_hardware_returns_attestation_error() {
        let err = snp_report_with_data(&[0u8; 64]).unwrap_err();
        assert!(
            err.to_string().contains("SNP") || err.to_string().contains("attestation"),
            "{err}"
        );
    }
}
