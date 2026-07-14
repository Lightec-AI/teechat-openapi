//! In-guest TLS issuance ceremony: seal ACME private key, install cert chain, shred plaintext.
//!
//! **Production rule:** run only inside the attested SNP guest (`OPENAPI_PROFILE=prod`).
//! Ops must never copy `privkey.pem` off the guest.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use openapi_platform::{load_edge_profile, PlatformError};

use crate::guest_digest::verify_launch_digest_attested;
use crate::seal::CvmSealer;
use crate::tls::{seal_tls_key_file, TlsError};

/// Default layout under `/etc/teechat` on prod-openapi guests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsCeremonyPaths {
    pub cert_path: PathBuf,
    pub sealed_key_path: PathBuf,
    pub launch_digest: String,
    pub image_digest: String,
}

impl TlsCeremonyPaths {
    pub fn prod_defaults() -> Self {
        Self {
            cert_path: PathBuf::from("/etc/teechat/openapi-tls.crt"),
            sealed_key_path: PathBuf::from("/etc/teechat/openapi-tls-key.sealed.json"),
            launch_digest: String::new(),
            image_digest: String::new(),
        }
    }

    pub fn from_env() -> Result<Self, CeremonyError> {
        let launch = std::env::var("OPENAPI_LAUNCH_DIGEST")
            .map_err(|_| CeremonyError::MissingEnv("OPENAPI_LAUNCH_DIGEST"))?;
        let image = std::env::var("OPENAPI_IMAGE_DIGEST")
            .map_err(|_| CeremonyError::MissingEnv("OPENAPI_IMAGE_DIGEST"))?;
        let cert = std::env::var("OPENAPI_TLS_CERT_PATH")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/etc/teechat/openapi-tls.crt"));
        let sealed = std::env::var("OPENAPI_TLS_SEALED_KEY_PATH")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/etc/teechat/openapi-tls-key.sealed.json"));
        Ok(Self {
            cert_path: cert,
            sealed_key_path: sealed,
            launch_digest: launch,
            image_digest: image,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CeremonyError {
    #[error("missing env var {0}")]
    MissingEnv(&'static str),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("platform: {0}")]
    Platform(#[from] PlatformError),
    #[error("profile: {0}")]
    Profile(String),
    #[error("ceremony: {0}")]
    Policy(String),
    #[error("acme: {0}")]
    Acme(String),
}

/// Refuse ceremony outside prod profile or when host-supplied secrets are configured.
pub fn assert_prod_ceremony_policy() -> Result<(), CeremonyError> {
    let profile = load_edge_profile();
    if !profile.is_prod() {
        return Err(CeremonyError::Policy(
            "TLS ceremony requires OPENAPI_PROFILE=prod".into(),
        ));
    }
    if std::env::var("OPENAPI_TLS_KEY_PATH")
        .ok()
        .filter(|s| !s.is_empty())
        .is_some()
    {
        return Err(CeremonyError::Policy(
            "OPENAPI_TLS_KEY_PATH must not be set during ceremony".into(),
        ));
    }
    if std::env::var("OPENAPI_SEAL_ROOT_HEX")
        .ok()
        .filter(|s| !s.is_empty())
        .is_some()
    {
        return Err(CeremonyError::Policy(
            "OPENAPI_SEAL_ROOT_HEX must not be set during ceremony".into(),
        ));
    }
    // OPS-001: test hook must not be present on prod ceremony units.
    if std::env::var("OPENAPI_ATTESTED_LAUNCH_DIGEST")
        .ok()
        .filter(|s| !s.is_empty() && s != "unknown")
        .is_some()
    {
        return Err(CeremonyError::Policy(
            "OPENAPI_ATTESTED_LAUNCH_DIGEST is forbidden during prod ceremony (OPS-001)".into(),
        ));
    }
    Ok(())
}

/// Resolve Let's Encrypt `live/<cert-name>/` directory.
pub fn acme_live_dir(letsencrypt_root: &Path, cert_name: &str) -> PathBuf {
    letsencrypt_root.join("live").join(cert_name)
}

/// Collect privkey paths for a cert (live symlink target + archive versions).
pub fn discover_acme_privkey_paths(
    letsencrypt_root: &Path,
    cert_name: &str,
) -> Result<Vec<PathBuf>, CeremonyError> {
    let live_dir = acme_live_dir(letsencrypt_root, cert_name);
    let privkey_link = live_dir.join("privkey.pem");
    if !privkey_link.exists() {
        return Err(CeremonyError::Acme(format!(
            "missing {}",
            privkey_link.display()
        )));
    }
    let mut paths = vec![privkey_link.clone()];
    if let Ok(resolved) = fs::canonicalize(&privkey_link) {
        if resolved != privkey_link {
            paths.push(resolved);
        }
    }
    let archive_dir = letsencrypt_root.join("archive").join(cert_name);
    if archive_dir.is_dir() {
        for entry in fs::read_dir(&archive_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("privkey") && name.ends_with(".pem") {
                paths.push(entry.path());
            }
        }
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

pub fn acme_fullchain_path(live_dir: &Path) -> PathBuf {
    live_dir.join("fullchain.pem")
}

/// Copy PEM chain to `cert_path` (public material).
pub fn install_cert_chain(source_fullchain: &Path, cert_path: &Path) -> Result<(), CeremonyError> {
    if !source_fullchain.is_file() {
        return Err(CeremonyError::Acme(format!(
            "missing fullchain {}",
            source_fullchain.display()
        )));
    }
    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(source_fullchain, cert_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(cert_path, fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}

/// Overwrite file with zeros then remove (best-effort secure delete for PEM).
pub fn shred_path(path: &Path) -> Result<(), CeremonyError> {
    if !path.exists() {
        return Ok(());
    }
    let meta = fs::metadata(path)?;
    let len = meta.len() as usize;
    if len > 0 {
        let mut f = OpenOptions::new().write(true).open(path)?;
        let zeros = vec![0u8; len.min(64 * 1024)];
        let mut written = 0usize;
        while written < len {
            let chunk = zeros.len().min(len - written);
            f.write_all(&zeros[..chunk])?;
            written += chunk;
        }
        f.sync_all()?;
    }
    fs::remove_file(path)?;
    Ok(())
}

/// Seal plaintext key, install fullchain, shred all discovered privkey copies.
pub fn seal_from_acme_live(
    paths: &TlsCeremonyPaths,
    live_dir: &Path,
    letsencrypt_root: &Path,
    cert_name: &str,
) -> Result<(), CeremonyError> {
    assert_prod_ceremony_policy()?;
    verify_launch_digest_attested(&paths.launch_digest)?;

    let privkey_paths = discover_acme_privkey_paths(letsencrypt_root, cert_name)?;
    let primary_key = privkey_paths
        .first()
        .ok_or_else(|| CeremonyError::Acme("no privkey path".into()))?;

    let sealer = CvmSealer::with_profile(
        &paths.launch_digest,
        &paths.image_digest,
        true,
    );

    if let Some(parent) = paths.sealed_key_path.parent() {
        fs::create_dir_all(parent)?;
    }
    seal_tls_key_file(
        &sealer,
        primary_key,
        &paths.sealed_key_path,
        None,
    )
    .map_err(map_tls_error)?;

    install_cert_chain(&acme_fullchain_path(live_dir), &paths.cert_path)?;

    for key_path in &privkey_paths {
        shred_path(key_path)?;
    }

    Ok(())
}

fn map_tls_error(err: TlsError) -> CeremonyError {
    match err {
        TlsError::Seal(p) => CeremonyError::Platform(p),
        TlsError::Io(e) => CeremonyError::Io(e),
        TlsError::Rustls(s) => CeremonyError::Policy(s),
    }
}

/// Post-ceremony check: no plaintext privkey at configured path or under ACME tree.
pub fn assert_no_plaintext_privkey_on_disk(
    letsencrypt_root: &Path,
    cert_name: &str,
    extra_plain_paths: &[PathBuf],
) -> Result<(), CeremonyError> {
    for path in extra_plain_paths {
        if path.exists() {
            return Err(CeremonyError::Policy(format!(
                "plaintext key still present: {}",
                path.display()
            )));
        }
    }
    if letsencrypt_root.exists() {
        for path in discover_acme_privkey_paths(letsencrypt_root, cert_name).unwrap_or_default() {
            if path.exists() {
                return Err(CeremonyError::Policy(format!(
                    "ACME privkey still present: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_digest::{
        set_test_attested_launch_digest, ATTESTED_ENV_TEST_LOCK,
    };
    use openapi_platform::Sealer;
    use std::env;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_env(f: impl FnOnce()) {
        let _g = ENV_LOCK.lock().unwrap();
        let _a = ATTESTED_ENV_TEST_LOCK.lock().unwrap();
        env::remove_var("OPENAPI_PROFILE");
        env::remove_var("OPENAPI_TLS_SEALED_KEY_PATH");
        env::remove_var("OPENAPI_TLS_KEY_PATH");
        env::remove_var("OPENAPI_SEAL_ROOT_HEX");
        env::remove_var("OPENAPI_ATTESTED_LAUNCH_DIGEST");
        set_test_attested_launch_digest(None);
        f();
        env::remove_var("OPENAPI_PROFILE");
        env::remove_var("OPENAPI_TLS_SEALED_KEY_PATH");
        env::remove_var("OPENAPI_TLS_KEY_PATH");
        env::remove_var("OPENAPI_SEAL_ROOT_HEX");
        env::remove_var("OPENAPI_ATTESTED_LAUNCH_DIGEST");
        set_test_attested_launch_digest(None);
    }

    fn write_pem(dir: &Path, name: &str, body: &str) {
        fs::write(dir.join(name), body).unwrap();
    }

    fn setup_acme_tree(root: &Path, cert_name: &str) -> PathBuf {
        let archive = root.join("archive").join(cert_name);
        let live = root.join("live").join(cert_name);
        fs::create_dir_all(&archive).unwrap();
        fs::create_dir_all(&live).unwrap();
        write_pem(
            &archive,
            "privkey1.pem",
            "-----BEGIN PRIVATE KEY-----\nline1\n-----END PRIVATE KEY-----\n",
        );
        write_pem(
            &archive,
            "fullchain1.pem",
            "-----BEGIN CERTIFICATE-----\nfull\n-----END CERTIFICATE-----\n",
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let _ = fs::remove_file(live.join("privkey.pem"));
            let _ = fs::remove_file(live.join("fullchain.pem"));
            symlink(
                format!("../../archive/{cert_name}/privkey1.pem"),
                live.join("privkey.pem"),
            )
            .unwrap();
            symlink(
                format!("../../archive/{cert_name}/fullchain1.pem"),
                live.join("fullchain.pem"),
            )
            .unwrap();
        }
        #[cfg(not(unix))]
        {
            fs::copy(
                archive.join("privkey1.pem"),
                live.join("privkey.pem"),
            )
            .unwrap();
            fs::copy(
                archive.join("fullchain1.pem"),
                live.join("fullchain.pem"),
            )
            .unwrap();
        }
        live
    }

    #[test]
    fn discover_acme_privkey_paths_finds_archive_and_live() {
        let dir = std::env::temp_dir().join(format!("ceremony-disc-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let live = setup_acme_tree(&dir, "openapi.teechat.ai");
        let paths = discover_acme_privkey_paths(&dir, "openapi.teechat.ai").unwrap();
        assert!(paths.iter().any(|p| p.ends_with("privkey1.pem")));
        assert!(paths.iter().any(|p| p == &live.join("privkey.pem")));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn assert_prod_ceremony_rejects_dev_profile() {
        with_env(|| {
            env::set_var("OPENAPI_TLS_SEALED_KEY_PATH", "/etc/sealed.json");
            assert!(assert_prod_ceremony_policy().is_err());
        });
    }

    #[test]
    fn assert_prod_ceremony_rejects_plaintext_key_env() {
        with_env(|| {
            env::set_var("OPENAPI_PROFILE", "prod");
            env::set_var("OPENAPI_TLS_KEY_PATH", "/etc/key.pem");
            assert!(assert_prod_ceremony_policy().is_err());
        });
    }

    #[test]
    fn assert_prod_ceremony_rejects_host_seal_root() {
        with_env(|| {
            env::set_var("OPENAPI_PROFILE", "prod");
            env::set_var("OPENAPI_SEAL_ROOT_HEX", "aa".repeat(32));
            assert!(assert_prod_ceremony_policy().is_err());
        });
    }

    #[test]
    fn assert_prod_ceremony_rejects_attested_launch_override() {
        with_env(|| {
            env::set_var("OPENAPI_PROFILE", "prod");
            env::set_var("OPENAPI_ATTESTED_LAUNCH_DIGEST", "a".repeat(64));
            let err = assert_prod_ceremony_policy().unwrap_err();
            assert!(
                err.to_string().contains("OPENAPI_ATTESTED_LAUNCH_DIGEST"),
                "got: {err}"
            );
        });
    }

    #[test]
    fn install_cert_chain_copies_fullchain() {
        let dir = std::env::temp_dir().join(format!("ceremony-cert-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let src = dir.join("fullchain.pem");
        let dst = dir.join("out").join("openapi-tls.crt");
        fs::write(&src, b"CHAIN").unwrap();
        install_cert_chain(&src, &dst).unwrap();
        assert_eq!(fs::read_to_string(&dst).unwrap(), "CHAIN");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn shred_path_removes_file() {
        let dir = std::env::temp_dir().join(format!("ceremony-shred-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let f = dir.join("key.pem");
        fs::write(&f, b"SECRET").unwrap();
        shred_path(&f).unwrap();
        assert!(!f.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn seal_from_acme_live_prod_roundtrip() {
        with_env(|| {
            let launch = "a".repeat(64);
            env::set_var("OPENAPI_PROFILE", "prod");
            // OPS-001: prod forbids env override — use test inject for hardware.
            set_test_attested_launch_digest(Some(launch.clone()));

            let dir = std::env::temp_dir().join(format!("ceremony-seal-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            let le = dir.join("letsencrypt");
            let etc = dir.join("etc");
            fs::create_dir_all(&etc).unwrap();
            let live = setup_acme_tree(&le, "openapi.teechat.ai");

            let paths = TlsCeremonyPaths {
                cert_path: etc.join("openapi-tls.crt"),
                sealed_key_path: etc.join("openapi-tls-key.sealed.json"),
                launch_digest: launch.clone(),
                image_digest: "image-id".into(),
            };

            seal_from_acme_live(&paths, &live, &le, "openapi.teechat.ai").unwrap();

            assert!(paths.sealed_key_path.is_file());
            assert!(paths.cert_path.is_file());
            assert_no_plaintext_privkey_on_disk(&le, "openapi.teechat.ai", &[]).unwrap();

            let sealer = CvmSealer::with_profile(&launch, "image-id", true);
            let plain = sealer
                .unseal_tls_key_from_file(&paths.sealed_key_path, None)
                .unwrap();
            assert!(plain.windows(b"BEGIN".len()).any(|w| w == b"BEGIN"));

            let _ = fs::remove_dir_all(&dir);
        });
    }

    #[test]
    fn seal_from_acme_fails_when_prod_env_override_set() {
        with_env(|| {
            let launch = "a".repeat(64);
            env::set_var("OPENAPI_PROFILE", "prod");
            env::set_var("OPENAPI_ATTESTED_LAUNCH_DIGEST", &launch);
            set_test_attested_launch_digest(Some(launch.clone()));

            let dir = std::env::temp_dir().join(format!("ceremony-ops001-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            let le = dir.join("letsencrypt");
            let etc = dir.join("etc");
            fs::create_dir_all(&etc).unwrap();
            let live = setup_acme_tree(&le, "openapi.teechat.ai");
            let paths = TlsCeremonyPaths {
                cert_path: etc.join("openapi-tls.crt"),
                sealed_key_path: etc.join("openapi-tls-key.sealed.json"),
                launch_digest: launch,
                image_digest: "image-id".into(),
            };
            assert!(seal_from_acme_live(&paths, &live, &le, "openapi.teechat.ai").is_err());
            let _ = fs::remove_dir_all(&dir);
        });
    }

    #[test]
    fn seal_from_acme_fails_without_attested_digest() {
        with_env(|| {
            env::set_var("OPENAPI_PROFILE", "prod");
            env::set_var("OPENAPI_TLS_SEALED_KEY_PATH", "/x");

            let dir = std::env::temp_dir().join(format!("ceremony-fail-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            let le = dir.join("letsencrypt");
            let live = setup_acme_tree(&le, "openapi.teechat.ai");
            let paths = TlsCeremonyPaths {
                cert_path: dir.join("cert.pem"),
                sealed_key_path: dir.join("sealed.json"),
                launch_digest: "b".repeat(64),
                image_digest: "id".into(),
            };
            assert!(seal_from_acme_live(&paths, &live, &le, "openapi.teechat.ai").is_err());
            let _ = fs::remove_dir_all(&dir);
        });
    }
}
