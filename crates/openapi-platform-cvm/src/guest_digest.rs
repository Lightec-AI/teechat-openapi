//! Guest attested launch digest for CVM sealing policy.
//!
//! **Target path:** vTPM guest-seal (see repo `SECURITY.md`).
//! **Minimum today:** cross-check `OPENAPI_LAUNCH_DIGEST` against SNP attestation.

use std::path::Path;
use std::process::{Command, Stdio};

use openapi_platform::PlatformError;

/// Test hook: bypass hardware when set (dev/CI only).
const ATTESTED_DIGEST_ENV: &str = "OPENAPI_ATTESTED_LAUNCH_DIGEST";

/// Read launch digest attested by guest hardware.
///
/// Order: test env → `snpguest` report → error.
pub fn read_attested_launch_digest() -> Result<String, PlatformError> {
    if let Ok(v) = std::env::var(ATTESTED_DIGEST_ENV) {
        if !v.is_empty() && v != "unknown" {
            return Ok(v);
        }
    }

    if Path::new("/dev/sev-guest").exists() {
        return read_launch_digest_via_snpguest();
    }

    Err(PlatformError::Attestation(
        "no attested launch digest source (/dev/sev-guest or OPENAPI_ATTESTED_LAUNCH_DIGEST)".into(),
    ))
}

fn snpguest_bin() -> String {
    std::env::var("OPENAPI_SNPGUEST_BIN").unwrap_or_else(|_| "snpguest".into())
}

fn read_launch_digest_via_snpguest() -> Result<String, PlatformError> {
    let dir = std::env::temp_dir().join(format!("openapi-snp-{}", std::process::id()));
    std::fs::create_dir_all(&dir)
        .map_err(|e| PlatformError::Attestation(format!("temp dir: {e}")))?;
    let request_path = dir.join("request.bin");
    let report_path = dir.join("report.bin");

    let result = (|| {
        std::fs::write(&request_path, [0u8; 64])
            .map_err(|e| PlatformError::Attestation(format!("write request: {e}")))?;
        let bin = snpguest_bin();
        let status = Command::new(&bin)
            .args([
                "report",
                report_path.to_str().unwrap(),
                request_path.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .status()
            .map_err(|e| PlatformError::Attestation(format!("snpguest report: {e}")))?;
        if !status.success() {
            return Err(PlatformError::Attestation(format!(
                "snpguest report failed (exit {status})"
            )));
        }

        let output = Command::new(&bin)
            .args(["display", "report", report_path.to_str().unwrap()])
            .output()
            .map_err(|e| PlatformError::Attestation(format!("snpguest display: {e}")))?;
        if !output.status.success() {
            return Err(PlatformError::Attestation(format!(
                "snpguest display failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        parse_launch_measurement_from_display(&String::from_utf8_lossy(&output.stdout))
    })();

    let _ = std::fs::remove_dir_all(&dir);
    result
}

fn parse_launch_measurement_from_display(text: &str) -> Result<String, PlatformError> {
    let mut lines = text.lines().map(str::trim).peekable();
    while let Some(line) = lines.next() {
        let rest = line
            .strip_prefix("Launch Measurement:")
            .or_else(|| line.strip_prefix("Measurement:"));
        if let Some(after_label) = rest {
            let mut hex = String::new();
            let inline = after_label
                .split_whitespace()
                .filter(|t| t.chars().all(|c| c.is_ascii_hexdigit()))
                .collect::<String>();
            hex.push_str(&inline);
            while let Some(&next) = lines.peek() {
                if next.is_empty() || next.contains(':') {
                    break;
                }
                let chunk: String = next
                    .split_whitespace()
                    .filter(|t| t.chars().all(|c| c.is_ascii_hexdigit()))
                    .collect();
                if chunk.is_empty() {
                    break;
                }
                hex.push_str(&chunk);
                lines.next();
            }
            if hex.len() >= 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return Ok(hex.to_ascii_lowercase());
            }
        }
    }
    Err(PlatformError::Attestation(
        "snpguest display output missing Measurement".into(),
    ))
}

/// Refuse unseal when env launch digest does not match attested guest digest (prod minimum).
pub fn verify_launch_digest_attested(env_launch_digest: &str) -> Result<(), PlatformError> {
    if env_launch_digest.is_empty() || env_launch_digest == "unknown" {
        return Err(PlatformError::Seal(
            "OPENAPI_LAUNCH_DIGEST must be set to attested value in prod".into(),
        ));
    }
    let attested = read_attested_launch_digest()?;
    if attested != env_launch_digest.to_ascii_lowercase() {
        return Err(PlatformError::Seal(format!(
            "OPENAPI_LAUNCH_DIGEST mismatch: env={env_launch_digest} attested={attested}"
        )));
    }
    Ok(())
}

/// Serializes tests that mutate `OPENAPI_ATTESTED_LAUNCH_DIGEST`.
#[cfg(test)]
pub(crate) static ATTESTED_ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    fn with_attested_env(f: impl FnOnce()) {
        let _guard = ATTESTED_ENV_TEST_LOCK.lock().unwrap();
        std::env::remove_var("OPENAPI_ATTESTED_LAUNCH_DIGEST");
        f();
        std::env::remove_var("OPENAPI_ATTESTED_LAUNCH_DIGEST");
    }

    #[test]
    fn parse_launch_measurement_line() {
        let text = "Launch Measurement: ABCD0123ef567890abcd0123ef567890abcd0123ef567890abcd0123ef567890\n";
        let digest = parse_launch_measurement_from_display(text).unwrap();
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn parse_snpguest_multiline_measurement() {
        let text = r"Measurement:
3D 9B 4D DB B3 1F BF 6D F0 6E C3 6E 9A C6 B8 39
B1 1B 47 5C 6B EC FA B0 18 5A A0 8A CC FD 14 46
65 38 55 A9 19 8F 75 B5 CE 14 24 BB C5 89 76 73
";
        let digest = parse_launch_measurement_from_display(text).unwrap();
        assert_eq!(digest.len(), 96);
        assert_eq!(
            digest,
            "3d9b4ddbb31fbf6df06ec36e9ac6b839b11b475c6becfab0185aa08accfd1446653855a9198f75b5ce1424bbc5897673"
        );
    }

    #[test]
    fn attested_digest_from_test_env() {
        with_attested_env(|| {
            std::env::set_var("OPENAPI_ATTESTED_LAUNCH_DIGEST", "a".repeat(64));
            let d = read_attested_launch_digest().unwrap();
            assert_eq!(d, "a".repeat(64));
        });
    }

    #[test]
    fn verify_launch_digest_mismatch_fails() {
        with_attested_env(|| {
            std::env::set_var("OPENAPI_ATTESTED_LAUNCH_DIGEST", "b".repeat(64));
            assert!(verify_launch_digest_attested(&("a".repeat(64))).is_err());
        });
    }

    #[test]
    fn verify_launch_digest_match_ok() {
        with_attested_env(|| {
            let d = "c".repeat(64);
            std::env::set_var("OPENAPI_ATTESTED_LAUNCH_DIGEST", &d);
            verify_launch_digest_attested(&d).unwrap();
        });
    }
}
