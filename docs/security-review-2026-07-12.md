# Security review — 2026-07-12

**Scope:** Full static security analysis of this repository (L1 OpenAI-compatible edge): authz, attestation challenge, TLS sealing, proxy surface, SGX vs CVM deltas, push revoke, metering.

**Conducted with:** Cursor **Grok 4.5 High Fast** (Composer agent session).

**Method:** Code + [`SECURITY.md`](../SECURITY.md) review. No exploit development, no live penetration of production. Findings are against tip of the module at review time, not an uncommitted patch set.

**Related:** [`SECURITY.md`](../SECURITY.md) · [`docs/streaming-contract.md`](./streaming-contract.md)

**Module tip at review:** through `7f55ca1` (Fortanix EDP bring-up).  
**Remediation tip (attestation Option A):** `566d96e` — `report_data` v1 + challenge JSON fields + SGX `for_target` / CVM `snpguest`.

---

## 1. Summary

| Severity | Open at review | Status after Option A (`566d96e`) |
|----------|---------------:|-----------------------------------|
| Critical | 0 | — |
| High | 4 | **2 mitigated / partial** (ATT-001, ATT-002); **2 open** (NET-001, AUTH-001) |
| Medium | 7 | **1 mitigated** (ATT-003 via hardware binding); **6 open** |
| Low | 1 | open (TLS-001) |
| Info / positive | 1 | unchanged (CRYPTO-001) |

**Verdict (updated):** Attestation binding (ATT-001/002/003) is addressed in-tree for the Option A challenge path. Residual high risk is now **L0 policy enforcement (AUTH-001)** and **push / accept hardening (NET-001, DOS-001)**, plus metering and ops guards.

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

- **Status:** **Mitigated in-tree** — `report_data` v1 preimage + QE-targeted `Report::for_target` + host `openapi-dcap-helper` (AESM ECDSA) returns `quote_format = sgx_dcap_ecdsa`. Fail-closed if helper/PCCS/aesmd is down (no silent local-REPORT downgrade).
- **Location:** `crates/openapi-platform/src/challenge.rs`, `crates/openapi-platform-sgx/src/{attest,dcap,report}.rs`, `bins/openapi-dcap-helper`
- **Ops dependency:** Local PCCS (`deploy/sgx/setup-pccs.sh` + Intel PCS API key) and `./deploy/sgx/run-dcap-helper.sh` beside the enclave.

### ATT-002 — High — CVM attestation challenge returns no guest quote

- **Status:** **Mitigated on staging SNP guest** — challenge builds `report_data` v1 and requires an SNP report (`snpguest report` with correct arg order + VMPL 0) with matching `REPORT_DATA`. Verified live on RedSwitches `prod-openapi` (`quote_format=snp_report`, 1184-byte report, binding OK). Hosts without SNP/snpguest fail closed.
- **Location:** `crates/openapi-platform-cvm/src/{attest,snp_report}.rs`
- **Remaining:** Prefer in-process `/dev/sev-guest` ioctl (drop CLI); publish VCEK verify recipe for clients.

### ATT-003 — Medium — Challenge identity payload is unsigned

- **Status:** **Mitigated by Option A (hardware binding)** — we did **not** add an Ed25519 signature over the JSON body. The locked remediation allowed *“or rely solely on hardware quotes.”* Verifying clients recompute `report_data` from the JSON identity fields + nonce and match the quote/`REPORT` user-data; those fields are therefore covered by hardware evidence, not by a separate software signature.
- **Location:** `crates/openapi-platform/src/challenge.rs` · [`docs/attestation-challenge.md`](./attestation-challenge.md)
- **Caveat:** Clients that trust JSON fields **without** checking `report_data` still see unsigned claims. Remote internet verify must check the DCAP ECDSA quote (not a local `sgx_report`). No change for skip-attestation OpenAI clients (by product design).
- **Not done:** Manifest-published Ed25519 challenge signing (optional defense-in-depth; not required once hardware binding is verified).

### NET-001 — High — Revocation push listener has no transport authentication

- **Status:** **Open** (unchanged by Option A).
- **Location:** `crates/openapi-platform-cvm/src/push.rs`
- **Detail:** Plain TCP accept, naive HTTP body parse, Ed25519 on `SignedRevocation` only. Unbounded `thread::spawn`. No mTLS / internal Bearer / IP ACL in code.
- **Impact:** Reachable push port → DoS / parse load; catalog verify-key compromise becomes a remote revoke oracle with a larger surface than necessary.
- **Remediation:** Require `OPENAPI_L0_INTERNAL_TOKEN` (or mTLS); default bind `127.0.0.1`; bounded accept pool; reject non-POST early.

### AUTH-001 — High — L0 `SignedAuthz.policy` (models / rpm) not enforced

- **Status:** **Open** (unchanged by Option A).
- **Location:** `crates/openapi-core/src/authz.rs`, `remote_auth.rs`
- **Detail:** `OpenApiKeyPolicy { models, rpm }` is inside the signed authz blob, but the edge only checks signature, expiry, hash match, and revocations. RPM uses global `OPENAPI_REQUESTS_PER_MINUTE`.
- **Impact:** Restricted keys can still hit any model / higher RPM than L0 intended.
- **Remediation:** Enforce `policy.models` on inference/proxy; `min(global rpm, policy.rpm)`; Forbidden on violation.

### PROXY-001 — Medium — Authenticated transparent `/v1/*` proxy is broad

- **Status:** **Open** (unchanged by Option A).
- **Location:** `crates/openapi-core/src/routes.rs`
- **Detail:** Unknown GET/POST under `/v1/` proxy to upstream after Bearer auth, except an explicit 501 denylist.
- **Impact:** New upstream admin/debug routes become reachable to any valid API key without edge review.
- **Remediation:** Prod default-deny (`OPENAPI_PROXY_MODE=allowlist|transparent`); path normalize; keep denylist as defense-in-depth.

### DOS-001 — Medium — CVM edge unbounded `thread::spawn` per connection

- **Status:** **Open** (unchanged by Option A).
- **Location:** `bins/openapi/src/main.rs`
- **Detail:** SGX path uses bounded accept pool in `openapi-edge`; CVM binary was not migrated.
- **Impact:** Connection flood can exhaust guest memory/threads.
- **Remediation:** Route CVM through `openapi_edge::run_edge_server`; cap `OPENAPI_ACCEPT_WORKERS`.

### METER-001 — Medium — Streaming inference signs usage as 0/0 tokens

- **Status:** **Open** (unchanged by Option A).
- **Location:** `crates/openapi-core/src/handler.rs`
- **Detail:** For `stream:true`, `sign_report` uses token counts that always return `(0, 0)`.
- **Impact:** Billing/quota under-count if L0 trusts edge-signed reports alone.
- **Remediation:** Accumulate SSE usage before signing, or provisional + final trailer with real counts.

### OPS-001 — Medium — `OPENAPI_ATTESTED_LAUNCH_DIGEST` bypasses snpguest

- **Status:** **Open** (unchanged by Option A). Note: challenge now uses `snpguest` for quotes; this finding is about **sealing** digest override, not the challenge path.
- **Location:** `crates/openapi-platform-cvm/src/guest_digest.rs`
- **Detail:** Env override preferred over `snpguest` when set (documented for tests).
- **Impact:** Rogue guest env write can forge sealing policy digest without hardware attestation.
- **Remediation:** Ignore override when `OPENAPI_PROFILE=prod`; fail closed to snpguest / `/dev/sev-guest`.

### OPS-002 — Medium — `seal-tls-key-sgx` lacks prod profile refusal

- **Status:** **Open** (unchanged by Option A).
- **Location:** `bins/seal-tls-key-sgx` vs `bins/seal-tls-key`
- **Detail:** CVM seal tool bails on `OPENAPI_PROFILE=prod`; SGX tool does not.
- **Impact:** Host-visible plaintext keys can enter an SGX sealing workflow labeled prod.
- **Remediation:** Mirror CVM prod bail; prefer in-enclave ceremony for prod.

### CFG-001 — Medium — SGX config via CLI args is host-attacker visible

- **Status:** **Open** (unchanged by Option A). Challenge binding includes SPKI/measurement but does **not** measure catalog/upstream argv.
- **Location:** `bins/openapi-enclave/src/main.rs`
- **Detail:** Fortanix empty env → `OPENAPI_*` (catalog, seeds, upstream) passed as enclave argv.
- **Impact:** Rogue host can retarget upstream / inject catalog without changing `MRENCLAVE`. TLS key still EGETKEY-bound.
- **Remediation:** Measure critical config into enclave build or sealed config; reject host overrides in prod for those fields.

### TLS-001 — Low — Plain TCP listen allowed when TLS paths unset

- **Status:** **Open** (unchanged by Option A).
- **Location:** CVM/SGX run paths
- **Detail:** Prod forbids plaintext key path but does not require TLS acceptor success.
- **Impact:** Misconfigured prod unit could listen without TLS.
- **Remediation:** `OPENAPI_PROFILE=prod` → require successful TLS acceptor (fail closed).

### CRYPTO-001 — Info — Positive controls

- **Status:** **Still valid**; Option A adds honest `quote_format` labeling and fail-closed challenge when evidence is unavailable.
- **Location:** platform `tls.rs` / `profile.rs` / seal paths; catalog CT compare; `challenge.rs`
- **Detail:** rustls TLS 1.3-only; prod forbids `OPENAPI_TLS_KEY_PATH` and host `OPENAPI_SEAL_ROOT_HEX`; SGX `seal_version` 2 uses EGETKEY; SGX IP-only upstream; SGX accept pool.
- **Remediation:** Keep `verify-tls13-only.sh` in CI; add prod negative tests for plaintext key and `ATTESTED_LAUNCH` override; add DCAP integration tests when QE is wired.

---

## 4. Recommended fix order

| Priority | IDs | Work |
|----------|-----|------|
| P0 | ATT-001 | DCAP ECDSA wired; keep PCCS/helper healthy in ops |
| P0 | AUTH-001 | Enforce L0 models/rpm at edge |
| P1 | NET-001, DOS-001 | Push auth + CVM bounded accept |
| P1 | ATT-002 remaining, METER-001, OPS-001, OPS-002 | SNP ioctl + streaming usage + prod seal guards |
| P2 | PROXY-001, CFG-001, TLS-001 | Hardening and measured config |
| Done | ATT-003 | Satisfied by hardware `report_data` binding for verifying clients |

---

## 5. Out of scope / non-findings

- No claim that this review replaces a third-party audit or formal TEE appraisal.
- Upstream engine (vLLM) and L0 billing service were not in scope.
- Lab SGX smoke (`/healthz`, auth to `/v1/models`) was prior bring-up work, not a security attestation of remediations above.
