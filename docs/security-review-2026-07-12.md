# Security review — 2026-07-12

**Scope:** Full static security analysis of this repository (L1 OpenAI-compatible edge): authz, attestation challenge, TLS sealing, proxy surface, SGX vs CVM deltas, push revoke, metering.

**Conducted with:** Cursor **Grok 4.5 High Fast** (Composer agent session).

**Method:** Code + [`SECURITY.md`](../SECURITY.md) review. No exploit development, no live penetration of production. Findings are against tip of the module at review time, not an uncommitted patch set.

**Related:** [`SECURITY.md`](../SECURITY.md) · [`docs/streaming-contract.md`](./streaming-contract.md)

**Module tip at review:** through `7f55ca1` (Fortanix EDP bring-up: rustls+ring, CLI config, bounded SGX accept pool).

---

## 1. Summary

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 4 |
| Medium | 7 |
| Low | 1 |
| Info / positive | 1 |

**Verdict:** Crypto orientation (TLS 1.3-only, prod seal policy, CT key-hash compare) is sound. Residual high risk centers on **attestation binding vs product claims**, **unsigned/unenforced L0 policy fields**, and **push / accept hardening**.

---

## 2. Trust model (reviewed)

| In TCB (edge) | Out of TCB / separate |
|---------------|------------------------|
| TLS terminate (when configured), API key verify, usage sign | Host / hypervisor (rogue ops) |
| Sealed TLS key unseal, optional attestation challenge | L0 catalog signing and billing |
| SGX: Fortanix EDP enclave · CVM: guest + measurement | Upstream engine (HTTP, private LAN) |
| | Client skip-attestation; SGX CLI argv; push network path |

---

## 3. Findings

### ATT-001 — High — SGX challenge nonce not bound via `REPORT.report_data`

- **Location:** `crates/openapi-platform-sgx/src/report.rs`
- **Detail:** `local_enclave_report_b64()` calls `Report::for_self()` then XOR-mixes the client nonce into the serialized REPORT bytes. That mutates a measured structure after generation and is not Intel-standard `report_data` binding.
- **Impact:** Verifiers cannot prove the enclave saw the challenge nonce at REPORT generation time; recycled/host-tampered quote blobs may be accepted.
- **Remediation:** Generate REPORT with `reportdata = SHA-256(nonce ‖ SPKI ‖ build)` (or fill `report_data` before `for_self` / `for_target`). Never post-process REPORT bytes. Update `SECURITY.md` and client verifiers.

### ATT-002 — High — CVM attestation challenge returns no guest quote

- **Location:** `crates/openapi-platform-cvm/src/attest.rs`
- **Detail:** `challenge` always sets `quote_b64: None` and returns `EdgeIdentity` fields from startup env.
- **Impact:** Clients cannot cryptographically verify SNP launch digest via the public challenge API; identity is TOFU of env strings under TLS.
- **Remediation:** Embed SNP attestation report / VCEK chain in `quote_b64` (or sibling), bound to nonce + TLS SPKI. Keep env digests as hints only.

### ATT-003 — Medium — Challenge identity payload is unsigned

- **Location:** attestation challenge response path in core / platform
- **Detail:** Response fields are plain JSON over TLS; no Ed25519 signature of the challenge body.
- **Impact:** Without a hardware quote (CVM) or correct REPORT binding (SGX), strength is TLS-in-TEE + client diligence only.
- **Remediation:** Sign responses with an enclave/guest-held key published in the manifest, or rely solely on hardware quotes.

### NET-001 — High — Revocation push listener has no transport authentication

- **Location:** `crates/openapi-platform-cvm/src/push.rs`
- **Detail:** Plain TCP accept, naive HTTP body parse, Ed25519 on `SignedRevocation` only. Unbounded `thread::spawn`. No mTLS / internal Bearer / IP ACL in code.
- **Impact:** Reachable push port → DoS / parse load; catalog verify-key compromise becomes a remote revoke oracle with a larger surface than necessary.
- **Remediation:** Require `OPENAPI_L0_INTERNAL_TOKEN` (or mTLS); default bind `127.0.0.1`; bounded accept pool; reject non-POST early.

### AUTH-001 — High — L0 `SignedAuthz.policy` (models / rpm) not enforced

- **Location:** `crates/openapi-core/src/authz.rs`, `remote_auth.rs`
- **Detail:** `OpenApiKeyPolicy { models, rpm }` is inside the signed authz blob, but the edge only checks signature, expiry, hash match, and revocations. RPM uses global `OPENAPI_REQUESTS_PER_MINUTE`.
- **Impact:** Restricted keys can still hit any model / higher RPM than L0 intended.
- **Remediation:** Enforce `policy.models` on inference/proxy; `min(global rpm, policy.rpm)`; Forbidden on violation.

### PROXY-001 — Medium — Authenticated transparent `/v1/*` proxy is broad

- **Location:** `crates/openapi-core/src/routes.rs`
- **Detail:** Unknown GET/POST under `/v1/` proxy to upstream after Bearer auth, except an explicit 501 denylist.
- **Impact:** New upstream admin/debug routes become reachable to any valid API key without edge review.
- **Remediation:** Prod default-deny (`OPENAPI_PROXY_MODE=allowlist|transparent`); path normalize; keep denylist as defense-in-depth.

### DOS-001 — Medium — CVM edge unbounded `thread::spawn` per connection

- **Location:** `bins/openapi/src/main.rs`
- **Detail:** SGX path uses bounded accept pool in `openapi-edge`; CVM binary was not migrated.
- **Impact:** Connection flood can exhaust guest memory/threads.
- **Remediation:** Route CVM through `openapi_edge::run_edge_server`; cap `OPENAPI_ACCEPT_WORKERS`.

### METER-001 — Medium — Streaming inference signs usage as 0/0 tokens

- **Location:** `crates/openapi-core/src/handler.rs`
- **Detail:** For `stream:true`, `sign_report` uses token counts that always return `(0, 0)`.
- **Impact:** Billing/quota under-count if L0 trusts edge-signed reports alone.
- **Remediation:** Accumulate SSE usage before signing, or provisional + final trailer with real counts.

### OPS-001 — Medium — `OPENAPI_ATTESTED_LAUNCH_DIGEST` bypasses snpguest

- **Location:** `crates/openapi-platform-cvm/src/guest_digest.rs`
- **Detail:** Env override preferred over `snpguest` when set (documented for tests).
- **Impact:** Rogue guest env write can forge sealing policy digest without hardware attestation.
- **Remediation:** Ignore override when `OPENAPI_PROFILE=prod`; fail closed to snpguest / `/dev/sev-guest`.

### OPS-002 — Medium — `seal-tls-key-sgx` lacks prod profile refusal

- **Location:** `bins/seal-tls-key-sgx` vs `bins/seal-tls-key`
- **Detail:** CVM seal tool bails on `OPENAPI_PROFILE=prod`; SGX tool does not.
- **Impact:** Host-visible plaintext keys can enter an SGX sealing workflow labeled prod.
- **Remediation:** Mirror CVM prod bail; prefer in-enclave ceremony for prod.

### CFG-001 — Medium — SGX config via CLI args is host-attacker visible

- **Location:** `bins/openapi-enclave/src/main.rs`
- **Detail:** Fortanix empty env → `OPENAPI_*` (catalog, seeds, upstream) passed as enclave argv.
- **Impact:** Rogue host can retarget upstream / inject catalog without changing `MRENCLAVE`. TLS key still EGETKEY-bound.
- **Remediation:** Measure critical config into enclave build or sealed config; reject host overrides in prod for those fields.

### TLS-001 — Low — Plain TCP listen allowed when TLS paths unset

- **Location:** CVM/SGX run paths
- **Detail:** Prod forbids plaintext key path but does not require TLS acceptor success.
- **Impact:** Misconfigured prod unit could listen without TLS.
- **Remediation:** `OPENAPI_PROFILE=prod` → require successful TLS acceptor (fail closed).

### CRYPTO-001 — Info — Positive controls

- **Location:** platform `tls.rs` / `profile.rs` / seal paths; catalog CT compare
- **Detail:** rustls TLS 1.3-only; prod forbids `OPENAPI_TLS_KEY_PATH` and host `OPENAPI_SEAL_ROOT_HEX`; SGX `seal_version` 2 uses EGETKEY; SGX IP-only upstream; SGX accept pool.
- **Remediation:** Keep `verify-tls13-only.sh` in CI; add prod negative tests for plaintext key and `ATTESTED_LAUNCH` override.

---

## 4. Recommended fix order

| Priority | IDs | Work |
|----------|-----|------|
| P0 | ATT-001, ATT-002 | Real hardware-bound attestation quotes |
| P0 | AUTH-001 | Enforce L0 models/rpm at edge |
| P1 | NET-001, DOS-001 | Push auth + CVM bounded accept |
| P1 | METER-001, OPS-001, OPS-002 | Streaming usage + prod seal guards |
| P2 | PROXY-001, CFG-001, TLS-001, ATT-003 | Hardening and measured config |

---

## 5. Out of scope / non-findings

- No claim that this review replaces a third-party audit or formal TEE appraisal.
- Upstream engine (vLLM) and L0 billing service were not in scope.
- Lab SGX smoke (`/healthz`, auth to `/v1/models`) was prior bring-up work, not a security attestation of remediations above.
