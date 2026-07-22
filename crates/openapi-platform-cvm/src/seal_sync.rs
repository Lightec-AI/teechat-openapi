//! OpenAPI edge integration for `attested-mtls-seal-sync`.
//!
//! Active: `OPENAPI_SEAL_SYNC_LISTEN=127.0.0.1:9443`  
//! Staging: `OPENAPI_SEAL_SYNC_PEER=127.0.0.1:9443` (run once at startup)
//!
//! **Prod trust:** mutual split-trust challenge via `OPENAPI_SEAL_SYNC_CHALLENGE_BASE_URL`
//! ([golden-digests-publish.md](../../../../docs/design/golden-digests-publish.md) §6).
//! `OPENAPI_SEAL_SYNC_PSK` is CI/dev only.

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use attested_mtls_seal_sync::{
    accept_one_with_gate, server_tls_config, sync_from_active_tcp_with_gate, AuditSink,
    LocalSealer, MockAttestor, PeerAttestor, PeerChallengeGate, SealSyncServerConfig,
    ServingIdentity, StderrAudit, SyncOutcome,
};
use base64::Engine as _;
use openapi_attest::verify::{verify_openapi_edge, VerifyOptions};
use openapi_attest::golden::GoldenLoadOptions;
use openapi_platform::{load_edge_profile, Sealer, REPORT_DATA_LEN};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::guest_digest::read_attested_launch_digest;
use crate::seal::CvmSealer;
use crate::snp_report::snp_report_with_data;

/// Env-driven seal-sync settings.
#[derive(Debug, Clone)]
pub struct SealSyncConfig {
    /// Bind address for active admin server (optional).
    pub listen: Option<String>,
    /// Peer address for staging client (optional).
    pub peer: Option<String>,
    /// Comma-separated allowlisted peer measurements (secondary; channel attestor).
    pub allowlist: Vec<String>,
    /// Shared secret for MockAttestor (dev / CI). Forbidden as sole trust in prod.
    pub mock_psk: Option<String>,
    /// This guest's `/v1/attestation/challenge` base URL (split-trust).
    pub challenge_base_url: Option<String>,
}

impl SealSyncConfig {
    /// Load from environment.
    pub fn from_env() -> Self {
        let allowlist = std::env::var("OPENAPI_SEAL_SYNC_ALLOWLIST")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|x| x.trim().to_ascii_lowercase())
                    .filter(|x| !x.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        Self {
            listen: std::env::var("OPENAPI_SEAL_SYNC_LISTEN")
                .ok()
                .filter(|s| !s.is_empty()),
            peer: std::env::var("OPENAPI_SEAL_SYNC_PEER")
                .ok()
                .filter(|s| !s.is_empty()),
            allowlist,
            mock_psk: std::env::var("OPENAPI_SEAL_SYNC_PSK")
                .ok()
                .filter(|s| !s.is_empty()),
            challenge_base_url: std::env::var("OPENAPI_SEAL_SYNC_CHALLENGE_BASE_URL")
                .ok()
                .filter(|s| !s.is_empty()),
        }
    }

    /// True when either server or client should run.
    pub fn enabled(&self) -> bool {
        self.listen.is_some() || self.peer.is_some()
    }

    /// Prod requires challenge URL; PSK alone is forbidden.
    pub fn validate_for_profile(&self) -> anyhow::Result<()> {
        if !self.enabled() {
            return Ok(());
        }
        if load_edge_profile().is_prod() {
            if self.mock_psk.is_some() {
                anyhow::bail!(
                    "OPENAPI_SEAL_SYNC_PSK is forbidden when OPENAPI_PROFILE=prod; \
                     use split-trust challenge (OPENAPI_SEAL_SYNC_CHALLENGE_BASE_URL)"
                );
            }
            if self.challenge_base_url.is_none() {
                anyhow::bail!(
                    "OPENAPI_SEAL_SYNC_CHALLENGE_BASE_URL required when seal-sync enabled in prod"
                );
            }
        }
        Ok(())
    }

    /// Whether to enforce mutual split-trust challenge gates.
    pub fn use_split_trust_gate(&self) -> bool {
        self.challenge_base_url.is_some() && self.mock_psk.is_none()
    }
}

/// AMD-SP / CVM local sealer for imported keys.
pub struct CvmLocalSealer {
    sealer: CvmSealer,
    sealed_path: PathBuf,
    cert_path: PathBuf,
}

impl CvmLocalSealer {
    /// Create sealer writing to the configured sealed key + cert paths.
    pub fn new(sealer: CvmSealer, sealed_path: PathBuf, cert_path: PathBuf) -> Self {
        Self {
            sealer,
            sealed_path,
            cert_path,
        }
    }
}

impl LocalSealer for CvmLocalSealer {
    fn seal_and_persist(
        &self,
        key_pem: &[u8],
        cert_pem: Option<&[u8]>,
    ) -> attested_mtls_seal_sync::Result<()> {
        if let Some(parent) = self.sealed_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| attested_mtls_seal_sync::Error::Seal(format!("mkdir sealed: {e}")))?;
        }
        self.sealer
            .seal_tls_key_to_file(key_pem, &self.sealed_path, None)
            .map_err(|e| attested_mtls_seal_sync::Error::Seal(e.to_string()))?;
        if let Some(cert) = cert_pem {
            if let Some(parent) = self.cert_path.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    attested_mtls_seal_sync::Error::Seal(format!("mkdir cert: {e}"))
                })?;
            }
            fs::write(&self.cert_path, cert)
                .map_err(|e| attested_mtls_seal_sync::Error::Seal(format!("write cert: {e}")))?;
        }
        Ok(())
    }
}

/// Split-trust peer challenge: `verify_openapi_edge` (app GitHub + golden + live challenge).
#[derive(Debug, Clone)]
pub struct SplitTrustChallengeGate {
    verify_opts_template: VerifyOptions,
}

impl SplitTrustChallengeGate {
    /// Build gate from env / defaults (GitHub primary, golden required).
    pub fn from_env() -> Self {
        let mut opts = VerifyOptions::default();
        if let Ok(tag) = std::env::var("OPENAPI_SEAL_SYNC_GITHUB_TAG") {
            if !tag.is_empty() {
                opts.github_tag = Some(tag);
            }
        }
        if let (Ok(mp), Ok(sp)) = (
            std::env::var("OPENAPI_SEAL_SYNC_APP_MANIFEST"),
            std::env::var("OPENAPI_SEAL_SYNC_APP_MANIFEST_SIG"),
        ) {
            if !mp.is_empty() && !sp.is_empty() {
                opts.manifest_path = Some(mp);
                opts.manifest_sig_path = Some(sp);
            }
        }
        let mut golden = GoldenLoadOptions::default();
        if let (Ok(gp), Ok(gs)) = (
            std::env::var("OPENAPI_SEAL_SYNC_GOLDEN_MANIFEST"),
            std::env::var("OPENAPI_SEAL_SYNC_GOLDEN_MANIFEST_SIG"),
        ) {
            if !gp.is_empty() && !gs.is_empty() {
                golden.manifest_path = Some(gp);
                golden.manifest_sig_path = Some(gs);
            }
        }
        opts.golden = golden;
        opts.require_golden_digests = true;
        Self {
            verify_opts_template: opts,
        }
    }

    /// Test/ops: fully specified options.
    pub fn with_options(opts: VerifyOptions) -> Self {
        Self {
            verify_opts_template: opts,
        }
    }
}

impl PeerChallengeGate for SplitTrustChallengeGate {
    fn verify_peer_challenge(&self, challenge_base_url: &str) -> attested_mtls_seal_sync::Result<()> {
        let mut opts = self.verify_opts_template.clone();
        opts.endpoint = challenge_base_url.trim_end_matches('/').to_string();
        match verify_openapi_edge(opts) {
            Ok(v) if v.ok => {
                info!(
                    endpoint = %v.endpoint,
                    build = %v.build_version,
                    code_hash = %v.code_hash,
                    golden = ?v.golden_version,
                    trust = %v.trust_source,
                    golden_trust = ?v.golden_trust_source,
                    "seal-sync split-trust challenge ok"
                );
                Ok(())
            }
            Ok(v) => Err(attested_mtls_seal_sync::Error::Attestation(format!(
                "split-trust challenge returned ok=false for {}",
                v.endpoint
            ))),
            Err(e) => Err(attested_mtls_seal_sync::Error::Attestation(format!(
                "split-trust challenge failed: {e}"
            ))),
        }
    }
}

/// Attestor: MockAttestor when PSK set; otherwise SNP report bound to channel SPKI.
pub enum EdgeSealSyncAttestor {
    /// Dev/CI mock.
    Mock(MockAttestor),
    /// SNP report_data = SHA-256(magic‖channel_spki) ‖ zeros.
    Snp(SnpChannelAttestor),
}

impl PeerAttestor for EdgeSealSyncAttestor {
    fn produce(
        &self,
        channel_spki_sha256: &str,
    ) -> attested_mtls_seal_sync::Result<attested_mtls_seal_sync::AttestationEvidence> {
        match self {
            Self::Mock(m) => m.produce(channel_spki_sha256),
            Self::Snp(s) => s.produce(channel_spki_sha256),
        }
    }

    fn verify(
        &self,
        evidence: &attested_mtls_seal_sync::AttestationEvidence,
        expected_channel_spki: &str,
    ) -> attested_mtls_seal_sync::Result<()> {
        match self {
            Self::Mock(m) => m.verify(evidence, expected_channel_spki),
            Self::Snp(s) => s.verify(evidence, expected_channel_spki),
        }
    }

    fn allowlisted(&self, measurement: &str) -> bool {
        match self {
            Self::Mock(m) => m.allowlisted(measurement),
            Self::Snp(s) => s.allowlisted(measurement),
        }
    }
}

/// SNP-backed channel attestor (measurement = launch digest) — secondary binding only.
#[derive(Debug, Clone)]
pub struct SnpChannelAttestor {
    measurement: String,
    allowlist: Vec<String>,
}

impl SnpChannelAttestor {
    fn report_data_for_channel(channel_spki_sha256: &str) -> [u8; REPORT_DATA_LEN] {
        let mut data = [0u8; REPORT_DATA_LEN];
        let mut h = Sha256::new();
        h.update(b"teechat-seal-sync-v1");
        h.update(channel_spki_sha256.as_bytes());
        let dig = h.finalize();
        data[..32].copy_from_slice(&dig);
        data
    }
}

impl PeerAttestor for SnpChannelAttestor {
    fn produce(
        &self,
        channel_spki_sha256: &str,
    ) -> attested_mtls_seal_sync::Result<attested_mtls_seal_sync::AttestationEvidence> {
        let rd = Self::report_data_for_channel(channel_spki_sha256);
        let report = snp_report_with_data(&rd)
            .map_err(|e| attested_mtls_seal_sync::Error::Attestation(e.to_string()))?;
        Ok(attested_mtls_seal_sync::AttestationEvidence {
            measurement: self.measurement.clone(),
            channel_spki_sha256: channel_spki_sha256.to_ascii_lowercase(),
            evidence_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&report),
        })
    }

    fn verify(
        &self,
        evidence: &attested_mtls_seal_sync::AttestationEvidence,
        expected_channel_spki: &str,
    ) -> attested_mtls_seal_sync::Result<()> {
        if !evidence
            .channel_spki_sha256
            .eq_ignore_ascii_case(expected_channel_spki)
        {
            return Err(attested_mtls_seal_sync::Error::Attestation(
                "channel_spki_sha256 mismatch".into(),
            ));
        }
        if !self.allowlisted(&evidence.measurement) {
            return Err(attested_mtls_seal_sync::Error::Attestation(format!(
                "measurement not allowlisted: {}",
                evidence.measurement
            )));
        }
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&evidence.evidence_b64)
            .map_err(|e| attested_mtls_seal_sync::Error::Attestation(format!("evidence: {e}")))?;
        const SNP_REPORT_DATA_OFFSET: usize = 0x50;
        let expect = Self::report_data_for_channel(expected_channel_spki);
        if raw.len() >= SNP_REPORT_DATA_OFFSET + REPORT_DATA_LEN {
            let got = &raw[SNP_REPORT_DATA_OFFSET..SNP_REPORT_DATA_OFFSET + REPORT_DATA_LEN];
            if got != expect.as_slice() {
                return Err(attested_mtls_seal_sync::Error::Attestation(
                    "SNP report_data does not bind channel SPKI".into(),
                ));
            }
        } else if raw.len() < 32 {
            return Err(attested_mtls_seal_sync::Error::Attestation(
                "SNP evidence too short".into(),
            ));
        }
        Ok(())
    }

    fn allowlisted(&self, measurement: &str) -> bool {
        let m = measurement.to_ascii_lowercase();
        self.allowlist.iter().any(|a| a == &m) || self.measurement.eq_ignore_ascii_case(&m)
    }
}

fn build_attestor(cfg: &SealSyncConfig, local_measurement: &str) -> EdgeSealSyncAttestor {
    let mut allow = cfg.allowlist.clone();
    if !allow
        .iter()
        .any(|a| a.eq_ignore_ascii_case(local_measurement))
    {
        allow.push(local_measurement.to_ascii_lowercase());
    }
    if let Some(psk) = &cfg.mock_psk {
        let mut mock = MockAttestor::new(local_measurement, psk.clone());
        for a in allow {
            mock = mock.allow(a);
        }
        return EdgeSealSyncAttestor::Mock(mock);
    }
    EdgeSealSyncAttestor::Snp(SnpChannelAttestor {
        measurement: local_measurement.to_ascii_lowercase(),
        allowlist: allow,
    })
}

/// Spawn active seal-sync admin server (background thread).
pub fn spawn_seal_sync_server(
    listen: &str,
    serving_cert_pem: &str,
    serving_key_pem: Vec<u8>,
    serving_cert_path: PathBuf,
    identity: ServingIdentity,
    attestor: EdgeSealSyncAttestor,
    challenge_gate: Option<SplitTrustChallengeGate>,
    challenge_base_url: Option<String>,
    export_key: Arc<dyn Fn() -> attested_mtls_seal_sync::Result<Vec<u8>> + Send + Sync>,
) -> attested_mtls_seal_sync::Result<()> {
    let (tls_cfg, channel_spki) = server_tls_config(serving_cert_pem.as_bytes(), &serving_key_pem)?;
    let listener = TcpListener::bind(listen)?;
    info!(%listen, channel_spki = %channel_spki, "seal-sync admin listening");

    let identity = identity.clone();
    let audit = StderrAudit;
    let cert_path = serving_cert_path;
    thread::spawn(move || {
        let attestor = attestor;
        let gate = challenge_gate;
        loop {
            let cfg = SealSyncServerConfig {
                identity: identity.clone(),
                tls_config: tls_cfg.clone(),
                channel_spki_sha256: channel_spki.clone(),
                challenge_base_url: challenge_base_url.clone(),
            };
            let export_cert = {
                let cert_path = cert_path.clone();
                move || {
                    let pem =
                        fs::read(&cert_path).map_err(|e| attested_mtls_seal_sync::Error::Io(e))?;
                    Ok(Some(pem))
                }
            };
            let gate_ref = gate.as_ref().map(|g| g as &dyn PeerChallengeGate);
            if let Err(e) = accept_one_with_gate(
                &listener,
                &cfg,
                &attestor,
                gate_ref,
                export_key.as_ref(),
                &export_cert,
                &audit as &dyn AuditSink,
            ) {
                warn!(error = %e, "seal-sync accept/serve failed");
            }
        }
    });
    Ok(())
}

/// Run staging sync once against active peer.
pub fn run_seal_sync_client(
    peer: &str,
    local: &ServingIdentity,
    attestor: &EdgeSealSyncAttestor,
    sealer: &CvmLocalSealer,
    challenge_gate: Option<&SplitTrustChallengeGate>,
    local_challenge_base_url: Option<&str>,
) -> attested_mtls_seal_sync::Result<SyncOutcome> {
    let audit = StderrAudit;
    info!(%peer, local_spki = %local.spki_sha256, "seal-sync staging → active");
    let gate = challenge_gate.map(|g| g as &dyn PeerChallengeGate);
    let outcome = sync_from_active_tcp_with_gate(
        peer,
        local,
        attestor,
        sealer,
        &audit,
        gate,
        local_challenge_base_url,
    )?;
    match &outcome {
        SyncOutcome::AlreadyAligned { peer } => {
            info!(
                peer_spki = %peer.spki_sha256,
                "seal-sync already_aligned"
            );
        }
        SyncOutcome::Migrated { peer } => {
            info!(
                peer_spki = %peer.spki_sha256,
                "seal-sync migrated — sealed and persisted"
            );
        }
    }
    Ok(outcome)
}

/// Wire seal-sync from edge env after TLS material is available.
pub fn maybe_start_seal_sync(
    cfg: &SealSyncConfig,
    launch_digest: &str,
    cert_path: &Path,
    sealed_path: &Path,
    sealer: CvmSealer,
    unsealed_key_pem: Vec<u8>,
) -> anyhow::Result<()> {
    if !cfg.enabled() {
        return Ok(());
    }
    cfg.validate_for_profile()?;

    let cert_pem = fs::read_to_string(cert_path)?;
    let measurement =
        read_attested_launch_digest().unwrap_or_else(|_| launch_digest.to_ascii_lowercase());
    let identity = ServingIdentity::from_cert_pem(&cert_pem, measurement.clone())?;
    let attestor = build_attestor(cfg, &measurement);

    let gate = if cfg.use_split_trust_gate() {
        Some(SplitTrustChallengeGate::from_env())
    } else {
        None
    };
    let challenge_url = cfg.challenge_base_url.clone();

    if let Some(peer) = &cfg.peer {
        let local_sealer = CvmLocalSealer::new(
            sealer.clone(),
            sealed_path.to_path_buf(),
            cert_path.to_path_buf(),
        );
        run_seal_sync_client(
            peer,
            &identity,
            &attestor,
            &local_sealer,
            gate.as_ref(),
            challenge_url.as_deref(),
        )?;
    }

    if let Some(listen) = &cfg.listen {
        let key = unsealed_key_pem.clone();
        let export_key: Arc<dyn Fn() -> attested_mtls_seal_sync::Result<Vec<u8>> + Send + Sync> =
            Arc::new(move || Ok(key.clone()));
        spawn_seal_sync_server(
            listen,
            &cert_pem,
            unsealed_key_pem,
            cert_path.to_path_buf(),
            identity,
            attestor,
            gate,
            challenge_url,
            export_key,
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn prod_forbids_psk_alone() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("OPENAPI_PROFILE", "prod");
        let cfg = SealSyncConfig {
            listen: Some("127.0.0.1:9443".into()),
            peer: None,
            allowlist: vec![],
            mock_psk: Some("secret".into()),
            challenge_base_url: Some("https://127.0.0.1:8443".into()),
        };
        let err = cfg.validate_for_profile().unwrap_err().to_string();
        assert!(err.contains("PSK") || err.contains("prod"), "got {err}");
        std::env::remove_var("OPENAPI_PROFILE");
    }

    #[test]
    fn prod_requires_challenge_url() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("OPENAPI_PROFILE", "prod");
        let cfg = SealSyncConfig {
            listen: Some("127.0.0.1:9443".into()),
            peer: None,
            allowlist: vec![],
            mock_psk: None,
            challenge_base_url: None,
        };
        let err = cfg.validate_for_profile().unwrap_err().to_string();
        assert!(err.contains("CHALLENGE_BASE_URL"), "got {err}");
        std::env::remove_var("OPENAPI_PROFILE");
    }

    #[test]
    fn prod_ok_with_challenge_url() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("OPENAPI_PROFILE", "prod");
        let cfg = SealSyncConfig {
            listen: Some("127.0.0.1:9443".into()),
            peer: None,
            allowlist: vec![],
            mock_psk: None,
            challenge_base_url: Some("https://127.0.0.1:8443".into()),
        };
        cfg.validate_for_profile().unwrap();
        assert!(cfg.use_split_trust_gate());
        std::env::remove_var("OPENAPI_PROFILE");
    }

    #[test]
    fn gate_maps_verify_errors() {
        let mut opts = VerifyOptions::default();
        opts.endpoint = "https://127.0.0.1:1".into();
        opts.require_golden_digests = false;
        let gate = SplitTrustChallengeGate::with_options(opts);
        let err = gate
            .verify_peer_challenge("https://127.0.0.1:1")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("split-trust") || err.contains("challenge") || err.contains("Http"),
            "got {err}"
        );
    }

    #[test]
    fn psk_disables_split_trust_gate_for_ci() {
        let cfg = SealSyncConfig {
            listen: Some("127.0.0.1:9443".into()),
            peer: None,
            allowlist: vec![],
            mock_psk: Some("ci-psk".into()),
            challenge_base_url: Some("https://127.0.0.1:8443".into()),
        };
        assert!(!cfg.use_split_trust_gate());
    }

    #[test]
    fn from_env_reads_challenge_base_url() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var(
            "OPENAPI_SEAL_SYNC_CHALLENGE_BASE_URL",
            "https://127.0.0.1:8443",
        );
        std::env::remove_var("OPENAPI_SEAL_SYNC_LISTEN");
        std::env::remove_var("OPENAPI_SEAL_SYNC_PEER");
        std::env::remove_var("OPENAPI_SEAL_SYNC_PSK");
        let cfg = SealSyncConfig::from_env();
        assert_eq!(
            cfg.challenge_base_url.as_deref(),
            Some("https://127.0.0.1:8443")
        );
        std::env::remove_var("OPENAPI_SEAL_SYNC_CHALLENGE_BASE_URL");
    }
}
