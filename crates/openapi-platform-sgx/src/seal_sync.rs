//! OpenAPI SGX integration for `attested-mtls-seal-sync`.
//!
//! Same wire protocol as CVM. Persist via ceremony helper (no `std::fs`). Admin TLS
//! uses crate feature `rustcrypto` (rustls-rustcrypto) inside Fortanix EDP.
//!
//! Lab practice: `OPENAPI_SEAL_SYNC_PSK` + MockAttestor first; DCAP channel attestor
//! when PSK unset. Split-trust challenge gate is optional (host-side / later).

use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use anyhow::Context;
use attested_mtls_seal_sync::{
    accept_one_with_gate, allow_legacy_v3_import_from_env, server_tls_config,
    sync_from_active_tcp_v3_with_client_identity, AllowAllChallengeGate, AuditSink, LocalSealer,
    MockAttestor, PeerAttestor, PeerChallengeGate, SealSyncServerConfig, ServingIdentity,
    StderrAudit, SyncOutcome, V3NonceStore, V3SyncOptions,
};
use base64::Engine as _;
use openapi_platform::{load_edge_profile, SealedTlsKeyBlob, Sealer, REPORT_DATA_LEN};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::ceremony_helper::CeremonyHelperClient;
use crate::dcap::DcapHelperClient;
use crate::report::enclave_report_for_target;
use crate::seal::SgxSealer;
use crate::tls_key_policy::{resolve_tls_key_policy_optional, TlsKeyPolicy};

type OptionalTlsMaterial = (Option<Vec<u8>>, Option<Vec<u8>>);

/// Env-driven seal-sync settings (same names as CVM).
#[derive(Debug, Clone)]
pub struct SealSyncConfig {
    pub listen: Option<String>,
    pub peer: Option<String>,
    pub allowlist: Vec<String>,
    pub mock_psk: Option<String>,
    pub challenge_base_url: Option<String>,
    pub allow_legacy_v3_import: bool,
}

impl SealSyncConfig {
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
            allow_legacy_v3_import: allow_legacy_v3_import_from_env(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.listen.is_some() || self.peer.is_some()
    }

    pub fn validate_for_profile(&self) -> anyhow::Result<()> {
        if !self.enabled() {
            return Ok(());
        }
        if load_edge_profile()?.is_prod() {
            if self.mock_psk.is_some() {
                anyhow::bail!(
                    "OPENAPI_SEAL_SYNC_PSK is forbidden when OPENAPI_PROFILE=prod; \
                     use DCAP channel attestor (+ optional challenge URL)"
                );
            }
            if self.allowlist.is_empty() {
                anyhow::bail!(
                    "OPENAPI_SEAL_SYNC_ALLOWLIST required when seal-sync enabled in prod"
                );
            }
        }
        Ok(())
    }

    pub fn use_split_trust_gate(&self) -> bool {
        self.challenge_base_url.is_some() && self.mock_psk.is_none()
    }
}

/// EGETKEY sealer that persists via ceremony helper artifacts.
pub struct SgxLocalSealer {
    sealer: SgxSealer,
    helper: CeremonyHelperClient,
    seal_root: Option<[u8; 32]>,
}

impl SgxLocalSealer {
    pub fn new(
        sealer: SgxSealer,
        helper: CeremonyHelperClient,
        seal_root: Option<[u8; 32]>,
    ) -> Self {
        Self {
            sealer,
            helper,
            seal_root,
        }
    }
}

impl LocalSealer for SgxLocalSealer {
    fn seal_and_persist(
        &self,
        key_pem: &[u8],
        cert_pem: Option<&[u8]>,
    ) -> attested_mtls_seal_sync::Result<()> {
        let blob = self
            .sealer
            .seal_tls_key(key_pem, self.seal_root.as_ref())
            .map_err(|e| attested_mtls_seal_sync::Error::Seal(e.to_string()))?;
        let sealed_json = serde_json::to_vec_pretty(&blob)
            .map_err(|e| attested_mtls_seal_sync::Error::Seal(format!("encode: {e}")))?;
        self.helper
            .put_artifact("sealed-key.json", &sealed_json)
            .map_err(|e| attested_mtls_seal_sync::Error::Seal(e.to_string()))?;
        if let Some(cert) = cert_pem {
            self.helper
                .put_artifact("tls.crt", cert)
                .map_err(|e| attested_mtls_seal_sync::Error::Seal(e.to_string()))?;
        }
        Ok(())
    }
}

/// Attestor: Mock when PSK set; otherwise DCAP quote bound to channel SPKI.
pub enum EdgeSealSyncAttestor {
    Mock(MockAttestor),
    Dcap(DcapChannelAttestor),
}

impl PeerAttestor for EdgeSealSyncAttestor {
    fn produce(
        &self,
        channel_spki_sha256: &str,
    ) -> attested_mtls_seal_sync::Result<attested_mtls_seal_sync::AttestationEvidence> {
        match self {
            Self::Mock(m) => m.produce(channel_spki_sha256),
            Self::Dcap(d) => d.produce(channel_spki_sha256),
        }
    }

    fn verify(
        &self,
        evidence: &attested_mtls_seal_sync::AttestationEvidence,
        expected_channel_spki: &str,
    ) -> attested_mtls_seal_sync::Result<()> {
        match self {
            Self::Mock(m) => m.verify(evidence, expected_channel_spki),
            Self::Dcap(d) => d.verify(evidence, expected_channel_spki),
        }
    }

    fn allowlisted(&self, measurement: &str) -> bool {
        match self {
            Self::Mock(m) => m.allowlisted(measurement),
            Self::Dcap(d) => d.allowlisted(measurement),
        }
    }
}

/// DCAP-backed channel attestor (measurement = MRENCLAVE).
#[derive(Debug, Clone)]
pub struct DcapChannelAttestor {
    measurement: String,
    allowlist: Vec<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct DcapEvidenceV3 {
    schema: String,
    quote_b64: String,
    collateral: serde_json::Value,
}

impl DcapChannelAttestor {
    fn report_data_for_channel(channel_spki_sha256: &str) -> [u8; REPORT_DATA_LEN] {
        let mut data = [0u8; REPORT_DATA_LEN];
        let mut h = Sha256::new();
        h.update(b"teechat-seal-sync-v3");
        h.update(channel_spki_sha256.as_bytes());
        let dig = h.finalize();
        data[..32].copy_from_slice(&dig);
        data
    }
}

impl PeerAttestor for DcapChannelAttestor {
    fn produce(
        &self,
        channel_spki_sha256: &str,
    ) -> attested_mtls_seal_sync::Result<attested_mtls_seal_sync::AttestationEvidence> {
        let rd = Self::report_data_for_channel(channel_spki_sha256);
        let dcap = DcapHelperClient::from_env()
            .map_err(|e| attested_mtls_seal_sync::Error::Attestation(e.to_string()))?;
        let target = dcap
            .qe_targetinfo()
            .map_err(|e| attested_mtls_seal_sync::Error::Attestation(e.to_string()))?;
        let report = enclave_report_for_target(&target, &rd)
            .map_err(|e| attested_mtls_seal_sync::Error::Attestation(e.to_string()))?;
        let quote = dcap
            .quote_report(&report)
            .map_err(|e| attested_mtls_seal_sync::Error::Attestation(e.to_string()))?;
        let collateral_json = dcap
            .quote_collateral(&quote)
            .map_err(|e| attested_mtls_seal_sync::Error::Attestation(e.to_string()))?;
        let collateral = serde_json::from_slice(&collateral_json).map_err(|e| {
            attested_mtls_seal_sync::Error::Attestation(format!(
                "DCAP helper returned invalid collateral JSON: {e}"
            ))
        })?;
        let wrapped = serde_json::to_vec(&DcapEvidenceV3 {
            schema: "teechat.seal_sync.dcap_evidence.v3".into(),
            quote_b64: base64::engine::general_purpose::STANDARD.encode(&quote),
            collateral,
        })
        .map_err(|e| {
            attested_mtls_seal_sync::Error::Attestation(format!("serialize DCAP evidence: {e}"))
        })?;
        Ok(attested_mtls_seal_sync::AttestationEvidence {
            measurement: self.measurement.clone(),
            channel_spki_sha256: channel_spki_sha256.to_ascii_lowercase(),
            evidence_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wrapped),
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
        let wrapped = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&evidence.evidence_b64)
            .map_err(|e| attested_mtls_seal_sync::Error::Attestation(format!("evidence: {e}")))?;
        let wrapped: DcapEvidenceV3 = serde_json::from_slice(&wrapped).map_err(|e| {
            attested_mtls_seal_sync::Error::Attestation(format!("DCAP evidence wrapper: {e}"))
        })?;
        if wrapped.schema != "teechat.seal_sync.dcap_evidence.v3" {
            return Err(attested_mtls_seal_sync::Error::Attestation(
                "DCAP evidence v3 schema required".into(),
            ));
        }
        let collateral_json = serde_json::to_vec(&wrapped.collateral).map_err(|e| {
            attested_mtls_seal_sync::Error::Attestation(format!(
                "serialize DCAP collateral for verification: {e}"
            ))
        })?;
        let verified = openapi_attest::sgx::verify_sgx_dcap_quote_with_collateral_json(
            &wrapped.quote_b64,
            &collateral_json,
            true,
        )
        .map_err(|e| {
            attested_mtls_seal_sync::Error::Attestation(format!(
                "SGX DCAP signature/collateral verification failed: {e}"
            ))
        })?;
        let expect = Self::report_data_for_channel(expected_channel_spki);
        if !verified
            .report_data_hex
            .eq_ignore_ascii_case(&hex::encode(expect))
        {
            return Err(attested_mtls_seal_sync::Error::Attestation(
                "verified SGX report_data does not bind the seal-sync transcript".into(),
            ));
        }
        if !verified
            .mrenclave_hex
            .eq_ignore_ascii_case(&evidence.measurement)
        {
            return Err(attested_mtls_seal_sync::Error::Attestation(
                "verified SGX MRENCLAVE does not match evidence claim".into(),
            ));
        }
        if !verified.tcb_status.eq_ignore_ascii_case("UpToDate") {
            return Err(attested_mtls_seal_sync::Error::Attestation(format!(
                "SGX TCB status is not UpToDate: {}",
                verified.tcb_status
            )));
        }
        Ok(())
    }

    fn allowlisted(&self, measurement: &str) -> bool {
        let m = measurement.to_ascii_lowercase();
        if self.allowlist.iter().any(|a| a == &m) || self.measurement.eq_ignore_ascii_case(&m) {
            return true;
        }
        false
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
    EdgeSealSyncAttestor::Dcap(DcapChannelAttestor {
        measurement: local_measurement.to_ascii_lowercase(),
        allowlist: allow,
    })
}

fn serving_identity_from_cert(
    cert_pem: Option<&[u8]>,
    measurement: &str,
) -> anyhow::Result<ServingIdentity> {
    if let Some(pem) = cert_pem {
        let pem_str = std::str::from_utf8(pem).context("cert utf8")?;
        Ok(ServingIdentity::from_cert_pem(
            pem_str,
            measurement.to_owned(),
        )?)
    } else {
        warn!("seal-sync cold start: no local cert; using placeholder SPKI identity");
        Ok(ServingIdentity {
            spki_sha256: "0".repeat(64),
            cert_sha256: "0".repeat(64),
            measurement: measurement.to_owned(),
        })
    }
}

fn reload_after_import(
    helper: &CeremonyHelperClient,
    sealer: &SgxSealer,
    seal_root: Option<&[u8; 32]>,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let sealed = helper
        .get_artifact("sealed-key.json")
        .context("after seal-sync import: sealed-key.json missing")?;
    let cert = helper
        .get_artifact("tls.crt")
        .context("after seal-sync import: tls.crt missing")?;
    let blob: SealedTlsKeyBlob =
        serde_json::from_slice(&sealed).context("parse sealed-key.json after import")?;
    let key = sealer
        .unseal_tls_key(&blob, seal_root)
        .context("unseal imported TLS key")?;
    Ok((key, cert))
}

/// Spawn active seal-sync admin server (background thread).
#[allow(clippy::too_many_arguments)] // Startup wiring keeps trust inputs explicit.
pub fn spawn_seal_sync_server(
    listen: &str,
    serving_cert_pem: &[u8],
    serving_key_pem: Vec<u8>,
    helper: CeremonyHelperClient,
    identity: ServingIdentity,
    attestor: EdgeSealSyncAttestor,
    challenge_base_url: Option<String>,
    export_key: Arc<dyn Fn() -> attested_mtls_seal_sync::Result<Vec<u8>> + Send + Sync>,
) -> attested_mtls_seal_sync::Result<()> {
    let (tls_cfg, channel_spki) = server_tls_config(serving_cert_pem, &serving_key_pem)?;
    let listener = TcpListener::bind(listen)?;
    info!(%listen, channel_spki = %channel_spki, "seal-sync admin listening");

    let identity = identity.clone();
    let audit = StderrAudit;
    thread::spawn(move || {
        let attestor = attestor;
        let v3_nonces = Arc::new(V3NonceStore::default());
        loop {
            let cfg = SealSyncServerConfig {
                identity: identity.clone(),
                tls_config: tls_cfg.clone(),
                channel_spki_sha256: channel_spki.clone(),
                challenge_base_url: challenge_base_url.clone(),
                require_v3: true,
                v3_nonces: v3_nonces.clone(),
            };
            let helper = helper.clone();
            let export_cert = move || {
                let pem = helper.get_artifact("tls.crt").map_err(|e| {
                    attested_mtls_seal_sync::Error::Io(std::io::Error::other(e.to_string()))
                })?;
                Ok(Some(pem))
            };
            if let Err(e) = accept_one_with_gate(
                &listener,
                &cfg,
                &attestor,
                None::<&dyn PeerChallengeGate>,
                export_key.as_ref(),
                &export_cert,
                &audit as &dyn AuditSink,
            ) {
                warn!(error = %e, "seal-sync accept/serve failed");
                thread::sleep(std::time::Duration::from_millis(250));
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
    sealer: &SgxLocalSealer,
    challenge_gate: Option<&dyn PeerChallengeGate>,
    local_challenge_base_url: Option<&str>,
) -> attested_mtls_seal_sync::Result<SyncOutcome> {
    let audit = StderrAudit;
    info!(%peer, local_spki = %local.spki_sha256, "seal-sync staging → active");
    let allow_legacy = allow_legacy_v3_import_from_env();
    if allow_legacy {
        info!("seal-sync allowing one-shot legacy v3 import (4d403ff transcript)");
    }
    // rcgen/ring ECDSA panics (#UD) in Fortanix EDP — use pure RustCrypto identity.
    let client_identity = crate::sgx_channel_identity::generate_ephemeral_channel_identity()
        .map_err(|e| attested_mtls_seal_sync::Error::Tls(e.to_string()))?;
    let outcome = sync_from_active_tcp_v3_with_client_identity(
        peer,
        local,
        attestor,
        sealer,
        &audit,
        &client_identity,
        V3SyncOptions {
            challenge_gate: if allow_legacy { None } else { challenge_gate },
            local_challenge_base_url,
            allow_legacy_import: allow_legacy,
        },
    )?;
    match &outcome {
        SyncOutcome::AlreadyAligned { peer } => {
            info!(peer_spki = %peer.spki_sha256, "seal-sync already_aligned");
        }
        SyncOutcome::Migrated { peer } => {
            info!(peer_spki = %peer.spki_sha256, "seal-sync migrated — sealed via helper");
        }
    }
    Ok(outcome)
}

/// Wire seal-sync from edge env (call after crypto provider install).
///
/// Returns refreshed `(key_pem, cert_pem)` after a successful cold-start import so
/// the edge can serve immediately without a second restart.
pub fn maybe_start_seal_sync(
    cfg: &SealSyncConfig,
    mrenclave: &str,
    helper: CeremonyHelperClient,
    sealer: SgxSealer,
    seal_root: Option<[u8; 32]>,
    mut unsealed_key_pem: Option<Vec<u8>>,
    mut cert_pem: Option<Vec<u8>>,
) -> anyhow::Result<OptionalTlsMaterial> {
    if !cfg.enabled() {
        return Ok((unsealed_key_pem, cert_pem));
    }
    cfg.validate_for_profile()?;

    let key_policy = resolve_tls_key_policy_optional().map_err(anyhow::Error::msg)?;
    match key_policy {
        Some(TlsKeyPolicy::KeyCeremony) => {
            if cfg.peer.is_some() {
                anyhow::bail!(
                    "tls_key_policy=key_ceremony forbids OPENAPI_SEAL_SYNC_PEER (import); \
                     export listen only"
                );
            }
        }
        Some(TlsKeyPolicy::SealSync) => {
            if unsealed_key_pem.is_none() && cfg.peer.is_none() {
                anyhow::bail!(
                    "tls_key_policy=seal_sync with no sealed artifact requires \
                     OPENAPI_SEAL_SYNC_PEER"
                );
            }
        }
        None => {}
    }

    let measurement = mrenclave.to_ascii_lowercase();
    let mut identity = serving_identity_from_cert(cert_pem.as_deref(), &measurement)?;
    let attestor = build_attestor(cfg, &measurement);
    let challenge_url = cfg.challenge_base_url.clone();

    if let Some(peer) = &cfg.peer {
        let local_sealer = SgxLocalSealer::new(sealer.clone(), helper.clone(), seal_root);
        let allow = AllowAllChallengeGate;
        let gate = if cfg.use_split_trust_gate() {
            Some(&allow as &dyn PeerChallengeGate)
        } else {
            None
        };
        run_seal_sync_client(
            peer,
            &identity,
            &attestor,
            &local_sealer,
            gate,
            challenge_url.as_deref(),
        )
        .context("seal-sync import from peer")?;
        let (key, cert) = reload_after_import(&helper, &sealer, seal_root.as_ref())?;
        unsealed_key_pem = Some(key);
        cert_pem = Some(cert);
        identity = serving_identity_from_cert(cert_pem.as_deref(), &measurement)?;
    }

    if let Some(listen) = &cfg.listen {
        match (unsealed_key_pem.as_ref(), cert_pem.as_deref()) {
            (Some(key_pem), Some(cert)) => {
                let key = key_pem.clone();
                let export_key: Arc<
                    dyn Fn() -> attested_mtls_seal_sync::Result<Vec<u8>> + Send + Sync,
                > = Arc::new(move || Ok(key.clone()));
                spawn_seal_sync_server(
                    listen,
                    cert,
                    key_pem.clone(),
                    helper,
                    identity,
                    attestor,
                    challenge_url,
                    export_key,
                )
                .context("spawn seal-sync admin")?;
            }
            _ => {
                info!(
                    %listen,
                    "seal-sync listen deferred — no unsealed TLS key yet (import-only / cold start)"
                );
            }
        }
    }

    Ok((unsealed_key_pem, cert_pem))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prod_forbids_psk() {
        let _g = crate::TEST_ENV_LOCK.lock().unwrap();
        std::env::set_var("OPENAPI_PROFILE", "prod");
        let cfg = SealSyncConfig {
            listen: Some("127.0.0.1:9443".into()),
            peer: None,
            allowlist: vec![],
            mock_psk: Some("secret".into()),
            challenge_base_url: None,
            allow_legacy_v3_import: false,
        };
        let err = cfg.validate_for_profile().unwrap_err().to_string();
        assert!(err.contains("PSK") || err.contains("prod"), "got {err}");
        std::env::remove_var("OPENAPI_PROFILE");
    }

    #[test]
    fn prod_requires_measurement_allowlist() {
        let _g = crate::TEST_ENV_LOCK.lock().unwrap();
        std::env::set_var("OPENAPI_PROFILE", "prod");
        let cfg = SealSyncConfig {
            listen: Some("127.0.0.1:9443".into()),
            peer: None,
            allowlist: vec![],
            mock_psk: None,
            challenge_base_url: None,
            allow_legacy_v3_import: false,
        };
        let err = cfg.validate_for_profile().unwrap_err().to_string();
        assert!(err.contains("ALLOWLIST"), "got {err}");
        std::env::remove_var("OPENAPI_PROFILE");
    }

    #[test]
    fn from_env_reads_listen() {
        let _g = crate::TEST_ENV_LOCK.lock().unwrap();
        std::env::set_var("OPENAPI_SEAL_SYNC_LISTEN", "127.0.0.1:9444");
        std::env::remove_var("OPENAPI_SEAL_SYNC_PEER");
        std::env::remove_var("OPENAPI_SEAL_SYNC_PSK");
        let cfg = SealSyncConfig::from_env();
        assert_eq!(cfg.listen.as_deref(), Some("127.0.0.1:9444"));
        std::env::remove_var("OPENAPI_SEAL_SYNC_LISTEN");
    }

    #[test]
    fn dcap_attestor_rejects_unsigned_quote_bytes() {
        let binding = "ab".repeat(32);
        let attestor = DcapChannelAttestor {
            measurement: "cd".repeat(32),
            allowlist: vec!["cd".repeat(32)],
        };
        let wrapped = serde_json::to_vec(&DcapEvidenceV3 {
            schema: "teechat.seal_sync.dcap_evidence.v3".into(),
            quote_b64: base64::engine::general_purpose::STANDARD.encode([0_u8; 64]),
            collateral: serde_json::json!({
                "pck_crl_issuer_chain": "",
                "root_ca_crl": [],
                "pck_crl": [],
                "tcb_info_issuer_chain": "",
                "tcb_info": "",
                "tcb_info_signature": [],
                "qe_identity_issuer_chain": "",
                "qe_identity": "",
                "qe_identity_signature": [],
                "pck_certificate_chain": null
            }),
        })
        .unwrap();
        let evidence = attested_mtls_seal_sync::AttestationEvidence {
            measurement: "cd".repeat(32),
            channel_spki_sha256: binding.clone(),
            evidence_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wrapped),
        };
        assert!(attestor.verify(&evidence, &binding).is_err());
    }
}
