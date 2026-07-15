# Security review — 2026-07-14 (follow-up)

**Scope:** Tip-of-module static re-review after remediations through `d8feabf` (DOS-001 accept pool / 429 shed / per-IP). Confirms prior High/Medium mitigations and hunts for regressions / residual gaps.

**Conducted with:** Cursor **Composer** (agent session; follow-up to the 2026-07-12 Grok 4.5 High Fast review).

**Method:** Code + [`SECURITY.md`](../SECURITY.md) + prior review body. No exploit development, no live penetration of production.

**Related:** [`docs/security-review-2026-07-12.md`](./security-review-2026-07-12.md) · [`SECURITY.md`](../SECURITY.md) · [`docs/streaming-contract.md`](./streaming-contract.md)

**Module tip:** `d8feabf` — `feat(edge): mitigate DOS-001 with pool, 429 shed, and per-IP limits.`

---

## 1. Summary

| Severity | New this pass | Prior still open | Mitigated (cumulative) |
|----------|--------------:|-----------------:|-----------------------:|
| Critical | 0 | 0 | — |
| High | 0 | 0 | 4 (ATT-001/002, AUTH-001, NET-001) |
| Medium | **0** new open | 2 (PROXY, CFG) + lows | 6 (+ BENCH-001) |
| Low | **1** (ROUTE-001) | 1 (TLS-001) | — |
| Info | 0 | — | CRYPTO-001 (unchanged positive) |

**Verdict:** Remediations through **BENCH-001** hold (attestation, AUTH, NET, DOS, IDLE, METER, OPS, bench token). Residual P2: proxy allowlist, measured SGX config, prod TLS-required.

---

## 2. Prior findings — revalidated

| ID | Severity | Status at tip | Evidence / residual |
|----|----------|---------------|---------------------|
| ATT-001 | High | **Mitigated** | SGX `report_data` v1 + DCAP helper; fail-closed if helper/PCCS down |
| ATT-002 | High | **Mitigated** | CVM SNP report with matching `REPORT_DATA`; CLI `snpguest` still preferred path |
| ATT-003 | Medium | **Mitigated** | Hardware `report_data` binding (no Ed25519 JSON sig) |
| AUTH-001 | High | **Mitigated** | Edge enforces `policy.models` + `min(global, policy.rpm)` |
| NET-001 | High | **Mitigated by design** | D6-pull + convoy; push unwired. Stop-loss is L0 `exp_ms` (not a separate edge cache TTL) |
| DOS-001 | Medium | **Mitigated** | Bounded pool + 429 shed + per-IP caps; TLS idle clear via socket `try_clone` (IDLE-001) |
| PROXY-001 | Medium | **Mitigated** | Default `ProxyMode::Allowlist`; prod forbids `OPENAPI_PROXY_MODE=transparent` |
| METER-001 | Medium | **Mitigated** | Stream path accumulates SSE `usage` then signs |
| OPS-001 | Medium | **Mitigated** | Prod forbids `OPENAPI_ATTESTED_LAUNCH_DIGEST`; hardware-only |
| OPS-002 | Medium | **Mitigated** | Host seal tools refuse `OPENAPI_PROFILE=prod` |
| CFG-001 | Medium | **Open** | SGX `OPENAPI_*` via argv still host-visible / unmeasured |
| TLS-001 | Low | **Mitigated** | Prod requires `OPENAPI_TLS_CERT_PATH` + successful acceptor; plain listen fail-closed |
| CRYPTO-001 | Info | **Valid** | TLS 1.3-only, prod sealed-key rules, honest quote labels |

---

## 3. New findings

### IDLE-001 — Medium — TLS accept path does not clear request-arrival idle

- **Status:** **Mitigated** — before TLS accept, `handle_stream` `try_clone`s the `TcpStream` and passes it to `serve_connection`; after `ParsedRequest` completes, clears read/write timeouts on that clone (same kernel socket as the TLS-owned fd). Matches plain `handle_connection` behavior.
- **Location:** `crates/openapi-edge/src/lib.rs` (`handle_stream`, `serve_connection`, `clear_idle_timeouts`)
- **Residual:** If `try_clone` fails, arrival idle is still applied but cannot be cleared (logged); rare on normal OS sockets.

### BENCH-001 — Medium — Challenge bench token has no prod refusal

- **Status:** **Mitigated** — `validate_tls_key_policy` fails closed if `OPENAPI_CHALLENGE_BENCH_TOKEN` is set under prod; CVM/SGX `limits()` strip the token; handler never bypasses when `OPENAPI_PROFILE=prod`.
- **Location:** `crates/openapi-platform/src/profile.rs`, `openapi-platform-{cvm,sgx}/src/env.rs`, `crates/openapi-core/src/handler.rs`
- **Residual:** Keep bench token out of prod unit files; rotate if ever leaked in lab.

### ROUTE-001 — Low — Exact-string route classify (query / trailing slash)

- **Status:** **Mitigated** — `normalize_path` strips query/fragment and trailing `/` before classify (folded into PROXY-001).
- **Location:** `crates/openapi-core/src/routes.rs`
- **Detail (historical):** `POST /v1/chat/completions?...` or trailing `/` became `ProxyPost`.
- **Remediation:** Path normalize + allowlist — **done**.

---

## 4. Recommended fix order

| Priority | IDs | Work |
|----------|-----|------|
| Done | **IDLE-001** | TLS arrival idle cleared via socket `try_clone` |
| Done | **METER-001** | Accumulate SSE usage before signing trailer |
| Done | **OPS-001, OPS-002** | Prod forbids attested-digest override; host seal tools refuse prod |
| Done | **BENCH-001** | Prod forbids / ignores challenge bench token |
| Done | **PROXY-001 + ROUTE-001** | Allowlist default + path normalize; prod forbids transparent |
| Done | **TLS-001** | Prod requires TLS cert + acceptor |
| P2 | CFG-001 | Measured config when EDP ships |
| Hold | ATT-* remaining | Prefer SNP ioctl over `snpguest`; keep PCCS/helper healthy |

---

## 5. Out of scope / non-findings

- Same bounds as the 2026-07-12 review: not a third-party audit; L0 billing and upstream engine out of scope.
- No claim that D6-pull eliminates all revoke latency — stop-loss remains `SignedAuthz.exp_ms` plus outbound poll health.
