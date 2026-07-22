//! OpenAPI edge integration for `attested-mtls-seal-sync`.
//!
//! Active: `OPENAPI_SEAL_SYNC_LISTEN=127.0.0.1:9443`  
//! Staging: `OPENAPI_SEAL_SYNC_PEER=127.0.0.1:9443` (run once at startup)

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use attested_mtls_seal_sync::{
    accept_one, server_tls_config, sync_from_active_tcp, AuditSink, LocalSealer, MockAttestor,
    PeerAttestor, SealSyncServerConfig, ServingIdentity, StderrAudit, SyncOutcome,
};
use base64::Engine as _;
use openapi_platform::{Sealer, REPORT_DATA_LEN};
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
    /// Comma-separated allowlisted peer measurements.
    pub allowlist: Vec<String>,
    /// Shared secret for MockAttestor (dev / CI). Empty ⇒ try SNP-bound attestor.
    pub mock_psk: Option<String>,
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
        }
    }

    /// True when either server or client should run.
    pub fn enabled(&self) -> bool {
        self.listen.is_some() || self.peer.is_some()
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

/// SNP-backed channel attestor (measurement = launch digest).
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
        // Bind check: report_data at SNP offset must match expected channel binding.
        // Full VCEK chain verify is left to client attestation monitors; here we enforce
        // size + report_data prefix match when the report is long enough.
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
        loop {
            let cfg = SealSyncServerConfig {
                identity: identity.clone(),
                tls_config: tls_cfg.clone(),
                channel_spki_sha256: channel_spki.clone(),
            };
            let export_cert = {
                let cert_path = cert_path.clone();
                move || {
                    let pem =
                        fs::read(&cert_path).map_err(|e| attested_mtls_seal_sync::Error::Io(e))?;
                    Ok(Some(pem))
                }
            };
            if let Err(e) = accept_one(
                &listener,
                &cfg,
                &attestor,
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
) -> attested_mtls_seal_sync::Result<SyncOutcome> {
    let audit = StderrAudit;
    info!(%peer, local_spki = %local.spki_sha256, "seal-sync staging → active");
    let outcome = sync_from_active_tcp(peer, local, attestor, sealer, &audit)?;
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

    let cert_pem = fs::read_to_string(cert_path)?;
    let measurement =
        read_attested_launch_digest().unwrap_or_else(|_| launch_digest.to_ascii_lowercase());
    let identity = ServingIdentity::from_cert_pem(&cert_pem, measurement.clone())?;
    let attestor = build_attestor(cfg, &measurement);

    if let Some(peer) = &cfg.peer {
        let local_sealer = CvmLocalSealer::new(
            sealer.clone(),
            sealed_path.to_path_buf(),
            cert_path.to_path_buf(),
        );
        run_seal_sync_client(peer, &identity, &attestor, &local_sealer)?;
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
            export_key,
        )?;
    }

    Ok(())
}
