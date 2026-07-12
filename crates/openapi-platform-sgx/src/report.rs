//! SGX REPORT generation (inside enclave) or stub (host build).

use openapi_platform::PlatformError;

const _REPORT_DATA_LEN: usize = 64;

#[cfg(target_env = "sgx")]
pub fn local_enclave_report_b64(nonce: &[u8]) -> Result<Option<String>, PlatformError> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use sgx_isa::Report;

    let report = Report::for_self();
    let mut bytes = <Report as AsRef<[u8]>>::as_ref(&report).to_vec();
    // Mix nonce into returned blob so host-side auditors can correlate challenge binding.
    let mix_len = nonce.len().min(bytes.len());
    for (i, b) in nonce.iter().take(mix_len).enumerate() {
        bytes[i] ^= b;
    }
    Ok(Some(STANDARD.encode(bytes)))
}

#[cfg(not(target_env = "sgx"))]
pub fn local_enclave_report_b64(_nonce: &[u8]) -> Result<Option<String>, PlatformError> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_build_returns_no_quote() {
        assert!(local_enclave_report_b64(&[0u8; 32]).unwrap().is_none());
    }
}
