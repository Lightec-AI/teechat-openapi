# Security review — 2026-07-12

**Scope:** Full static security analysis of this repository (L1 OpenAI-compatible edge): authz, attestation challenge, TLS sealing, proxy surface, SGX vs CVM deltas, push revoke, metering.

**Conducted with:** Cursor **Grok 4.5 High Fast** (Composer agent session).

**Method:** Code + [`SECURITY.md`](../SECURITY.md) review. No exploit development, no live penetration of production. Findings are against tip of the module at review time, not an uncommitted patch set.

**Related:** [`SECURITY.md`](../SECURITY.md) · [`docs/streaming-contract.md`](./streaming-contract.md)

**Module tip at review:** through `7f55ca1` (Fortanix EDP bring-up).  
**Remediation tip (attestation Option A):** `566d96e` — `report_data` v1 + challenge JSON fields + SGX `for_target` / CVM `snpguest`.

---

## 1. Summary

| Severity | Open at review | Status after remediations |
|----------|---------------:|-----------------------------------|
| Critical | 0 | — |
| High | 4 | **4 mitigated** (ATT-001, ATT-002, AUTH-001, NET-001) |
| Medium | 7 | **2 mitigated** (ATT-003, DOS-001); **5 open** |
| Low | 1 | open (TLS-001) |
| Info / positive | 1 | unchanged (CRYPTO-001) |

**Verdict (updated):** Attestation, AUTH-001, NET-001 (D6-pull), and DOS-001 (bounded accept + shed + idle cut) are addressed. Residual: metering, ops/prod guards, proxy allowlist.

---

## 2. Trust model (reviewed)

| In TCB (edge) | Out of TCB / separate |
|---------------|------------------------|
| TLS terminate (when configured), API key verify, usage sign | Host / hypervisor (rogue ops) |
| Sealed TLS key unseal, optional attestation challenge | L0 catalog signing and billing |
| SGX: Fortanix EDP enclave · CVM: guest + measurement | Upstream engine (HTTP, private LAN) |
| | Client skip-attestation; SGX CLI argv; L0 (outward) revoke poll |

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

- **Status:** **Mitigated by design** — correctness path is **D6-pull** (outbound poll every 15s + convoy on `SignedAuthz.epoch`); inbound push listener is not started; `OPENAPI_PUSH_LISTEN_ADDR` unwired. L0 `push/register` returns **410**. Authz cache TTL **10 min** bounds stop-loss if pull fails. Legacy `push.rs` may remain dead code until deleted.
- **Location:** `crates/openapi-core/src/remote_auth.rs`, `openapi-platform-{cvm,sgx}/src/remote_client.rs`, L0 `server/openapi/authorize-service.ts`
- **Prior detail:** Plain TCP accept push had no mTLS / Bearer — removed from the prod path rather than hardened.

### AUTH-001 — High — L0 `SignedAuthz.policy` (models / rpm) not enforced

- **Status:** **Mitigated** — edge enforces `policy.models` on inference/proxy POST and `min(global, policy.rpm)` per `key_id` (`OpenApiKeyPolicy::effective_rpm`). Catalog auth uses unrestricted policy (`models: ["*"]`, `rpm: 0`). Disallowed model → `403` / `model_not_allowed`.
- **Location:** `crates/openapi-core/src/authz.rs`, `auth.rs`, `remote_auth.rs`, `handler.rs`, `limits.rs`
- **Detail:** `OpenApiKeyPolicy { models, rpm }` is inside the signed authz blob, but the edge only checked signature, expiry, hash match, and revocations. RPM used global `OPENAPI_REQUESTS_PER_MINUTE`.
- **Impact:** Restricted keys can still hit any model / higher RPM than L0 intended.
- **Remediation:** Enforce `policy.models` on inference/proxy; `min(global rpm, policy.rpm)`; Forbidden on violation. **Done.**

### PROXY-001 — Medium — Authenticated transparent `/v1/*` proxy is broad

- **Status:** **Open** (unchanged by Option A).
- **Location:** `crates/openapi-core/src/routes.rs`
- **Detail:** Unknown GET/POST under `/v1/` proxy to upstream after Bearer auth, except an explicit 501 denylist.
- **Impact:** New upstream admin/debug routes become reachable to any valid API key without edge review.
- **Remediation:** Prod default-deny (`OPENAPI_PROXY_MODE=allowlist|transparent`); path normalize; keep denylist as defense-in-depth.

### DOS-001 — Medium — CVM edge unbounded `thread::spawn` per connection

- **Status:** **Mitigated** — CVM uses `openapi_edge::run_edge_server` (same as SGX): bounded workers sized for **concurrent streaming sessions** (`OPENAPI_ACCEPT_WORKERS`; default **512** CVM / **8** SGX), small accept queue with **try_send shed**, and short **request-arrival idle** (`OPENAPI_CONN_IDLE_SECS`, default **3s**). After the HTTP request is fully received, idle timeouts are cleared for multi-minute streams (plain TCP and TLS via pre-accept `TcpStream::try_clone` — IDLE-001). **Capacity:** each worker ≈ one live session for TTFT+stream; set `OPENAPI_ACCEPT_WORKERS` to peak concurrency. SGX stays TCS-bound until enclave thread count is raised or I/O is demuxed.
- **Location:** `bins/openapi/src/main.rs`, `crates/openapi-edge/src/lib.rs`, `crates/openapi-http/src/server.rs`
- **Also shipped:** per-IP connection cap (`OPENAPI_IP_MAX_CONNS`, default **16**) and per-IP API RPM (`OPENAPI_IP_REQUESTS_PER_MINUTE`, default **180**) in addition to per-`key_id` RPM. Challenge remains on its own per-IP RPM. L4/network ACLs still recommended in front of public edges.

### METER-001 — Medium — Streaming inference signs usage as 0/0 tokens (**Mitigated 2026-07-14**)

- **Status:** **Mitigated** — `SseUsageAccumulator` tees the stream; trailer signed after accumulate (`sse_usage.rs` + HTTP passthrough).
- **Location:** `crates/openapi-core/src/sse_usage.rs`, `crates/openapi-http/src/server.rs`
- **Detail (historical):** For `stream:true`, `sign_report` used `(0, 0)` before upstream finished.
- **Impact (historical):** Billing/quota under-count if L0 trusted edge-signed reports alone.

### OPS-001 — Medium — `OPENAPI_ATTESTED_LAUNCH_DIGEST` bypasses snpguest

- **Status:** **Mitigated** — when `OPENAPI_PROFILE=prod`, env override is **fail-closed** (`read_attested_launch_digest`, `validate_tls_key_policy`, ceremony policy). Dev/CI may still use the override. Prod seals require `snpguest` / `/dev/sev-guest`.
- **Location:** `crates/openapi-platform-cvm/src/guest_digest.rs`, `crates/openapi-platform/src/profile.rs`, `tls_ceremony.rs`
- **Residual:** Prefer in-process `/dev/sev-guest` ioctl (ATT-002 remaining) over CLI `snpguest`.

### OPS-002 — Medium — `seal-tls-key-sgx` lacks prod profile refusal

- **Status:** **Mitigated** — shared `assert_dev_host_seal_tool` refuses host seal under prod for both `seal-tls-key` and `seal-tls-key-sgx`.
- **Location:** `bins/seal-tls-key-sgx`, `bins/seal-tls-key`, `crates/openapi-platform/src/profile.rs`
- **Residual:** Prefer in-enclave ceremony for prod key material (ops process).

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
| P0 | AUTH-001 | **Done** — enforce L0 models/rpm at edge |
| Done | **METER-001** | Streaming usage accumulate-then-sign |
| P1 | OPS-001, OPS-002 | Prod seal guards (DOS-001 done) |
| P1 | ATT-002 remaining | Prefer SNP ioctl over snpguest CLI |
| P2 | PROXY-001, CFG-001, TLS-001 | Hardening and measured config |
| Done | ATT-003 | Satisfied by hardware `report_data` binding for verifying clients |

---

## 5. Out of scope / non-findings

- No claim that this review replaces a third-party audit or formal TEE appraisal.
- Upstream engine (vLLM) and L0 billing service were not in scope.
- Lab SGX smoke (`/healthz`, auth to `/v1/models`) was prior bring-up work, not a security attestation of remediations above.
