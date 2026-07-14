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
| Medium | **1** (BENCH-001) | 3 (PROXY, CFG + prior residual) | 5 (ATT-003, DOS-001, IDLE-001, OPS-001/002) |
| Low | **1** (ROUTE-001) | 1 (TLS-001) | — |
| Info | 0 | — | CRYPTO-001 (unchanged positive) |

**Verdict:** Remediations for attestation, AUTH-001, D6-pull (NET-001), DOS-001, IDLE-001, and **OPS-001/002** hold. Residual P1: **BENCH-001** (+ METER if not yet shipped). P2: proxy allowlist, measured SGX config, prod TLS-required.

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
| PROXY-001 | Medium | **Open** | Transparent `/v1/*` default-allow remains |
| METER-001 | Medium | **Mitigated** | Stream path accumulates SSE `usage` then signs |
| OPS-001 | Medium | **Mitigated** | Prod forbids `OPENAPI_ATTESTED_LAUNCH_DIGEST`; hardware-only |
| OPS-002 | Medium | **Mitigated** | Host seal tools refuse `OPENAPI_PROFILE=prod` |
| CFG-001 | Medium | **Open** | SGX `OPENAPI_*` via argv still host-visible / unmeasured |
| TLS-001 | Low | **Open** | Prod does not require successful TLS acceptor |
| CRYPTO-001 | Info | **Valid** | TLS 1.3-only, prod sealed-key rules, honest quote labels |

---

## 3. New findings

### IDLE-001 — Medium — TLS accept path does not clear request-arrival idle

- **Status:** **Mitigated** — before TLS accept, `handle_stream` `try_clone`s the `TcpStream` and passes it to `serve_connection`; after `ParsedRequest` completes, clears read/write timeouts on that clone (same kernel socket as the TLS-owned fd). Matches plain `handle_connection` behavior.
- **Location:** `crates/openapi-edge/src/lib.rs` (`handle_stream`, `serve_connection`, `clear_idle_timeouts`)
- **Residual:** If `try_clone` fails, arrival idle is still applied but cannot be cleared (logged); rare on normal OS sockets.

### BENCH-001 — Medium — Challenge bench token has no prod refusal

- **Status:** **Open**.
- **Location:** `crates/openapi-core/src/handler.rs` (`OPENAPI_CHALLENGE_BENCH_TOKEN` + `X-TeeChat-Challenge-Bench`); env wire-up in `openapi-platform-{cvm,sgx}/src/env.rs`.
- **Detail:** Matching header skips per-IP challenge RPM and in-flight quote caps (constant-time compare is fine). No `OPENAPI_PROFILE=prod` refusal at load or use.
- **Impact:** Token left set or leaked in prod bypasses challenge DoS controls → SNP/DCAP exhaustion.
- **Remediation:** Forbid / ignore bench token when `profile.is_prod()`; fail closed at env load for production units.

### ROUTE-001 — Low — Exact-string route classify (query / trailing slash)

- **Status:** **Open** (reinforces PROXY-001).
- **Location:** `crates/openapi-core/src/routes.rs`
- **Detail:** `POST /v1/chat/completions?...` or trailing `/` becomes `ProxyPost` (authz/model/RPM still applied; skips chat-specific empty-messages validation).
- **Impact:** Minor validation gap until path normalize + allowlist.
- **Remediation:** Strip query / normalize path before `classify`; fold into PROXY-001 hardening.

---

## 4. Recommended fix order

| Priority | IDs | Work |
|----------|-----|------|
| Done | **IDLE-001** | TLS arrival idle cleared via socket `try_clone` |
| Done | **METER-001** | Accumulate SSE usage before signing trailer |
| Done | **OPS-001, OPS-002** | Prod forbids attested-digest override; host seal tools refuse prod |
| P1 | **BENCH-001** | Prod-forbid challenge bench token |
| P2 | PROXY-001 + ROUTE-001 | Prod allowlist + path normalize |
| P2 | CFG-001, TLS-001 | Measured config; require TLS acceptor in prod |
| Hold | ATT-* remaining | Prefer SNP ioctl over `snpguest`; keep PCCS/helper healthy |

---

## 5. Out of scope / non-findings

- Same bounds as the 2026-07-12 review: not a third-party audit; L0 billing and upstream engine out of scope.
- No claim that D6-pull eliminates all revoke latency — stop-loss remains `SignedAuthz.exp_ms` plus outbound poll health.
