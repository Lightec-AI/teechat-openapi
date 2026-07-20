# Security review — 2026-07-20 (OPE-EDGE-001)

**Scope:** Focused review of the privileged OpenAPI edge → gateway **F′** OPE hard-cutover path (inventory → P1 pre-assign → Rust OPE wrap → `/v1/ope/dispatch`). Not a full-module re-audit.

**In scope:**
- `crates/openapi-platform-cvm` — `ope_upstream`, `gateway_ope_api`, `edge_upstream`, `ope_wrap`
- TeeChat gateway `server/gateway/ope-api/**` (F′ admit, preassign, dispatch, usage bind)
- Prod fail-closed gates (`OPENAPI_PROFILE=prod`, F′ TLS/mTLS)

**Out of scope:** Chat/JWT plane; SGX CFG-001; full ATT residual backlog.

**Method:** Static code + design contract (TeeChat internal `openapi-edge-ope-dispatch.md`). No exploit development, no live penetration.

**Conducted with:** Cursor Composer (security-review agent + trust-path map).

**Prior:** [2026-07-12](./security-review-2026-07-12.md) · [2026-07-14](./security-review-2026-07-14.md) · [2026-07-15](./security-review-2026-07-15.md)

**Related:** [`SECURITY.md`](../SECURITY.md)

---

## 1. Verdict

**0 critical / 0 high · 7 medium.**

Well mitigated on this path: **`traffic_class` spoof** (gateway strips client meta, stamps `api`), edge **clear-HTTP → vLLM** and **TLS skip-verify** fail-closed in prod, empty **CLIENT_PINS** refused at startup when mTLS required, engine **Ed25519 usage** verified before ledger persist.

Main gaps: **gateway dispatch admission** (optional / racing `assign_id`, no matrix re-check) and **prod F′ TLS/mTLS / `https://` fail-closed**, plus **unbound billing `key_id`** after F′ admit.

---

## 2. Findings

| ID | Sev | Location | Finding |
|----|-----|----------|---------|
| **OPE-001** | Medium | `server/gateway/ope-api/server.ts` (~317) | `assign_id` optional on dispatch — P1 gate bypass |
| **OPE-002** | Medium | `preassign-store.ts` (~71); `server.ts` (~317–377) | `assign_id` TOCTOU — concurrent reuse before `consume` |
| **OPE-003** | Medium | `server/gateway/ope-api/server.ts` (~308–375) | No key_set×engine_set matrix re-check on dispatch |
| **OPE-004** | Medium | `server/gateway/ope-api/config.ts` (~87–91) | `REQUIRE_MTLS=0` overrides pin harden |
| **OPE-005** | Medium | `create-plane.ts` (~56); `config.ts` assert | Prod can start F′ without TLS/mTLS |
| **OPE-006** | Medium | `gateway_ope_api.rs` `validate_for_profile` | Edge prod allows `http://` F′ URL |
| **OPE-007** | Medium | `server.ts` (~334–381); usage-ingest | Billing `key_id` unbound after F′ admit |

### OPE-001 — assign_id optional

`x-ope-assign-id` is validated only when present. An admitted F′ peer can `POST /v1/ope/dispatch` without preassign, skipping design P1 step 7 (“validate assign still live”).

**Remediation:** Require non-empty `assign_id` on dispatch in prod; fail closed (`assign_required`).

### OPE-002 — assign_id TOCTOU

`requireLive()` peeks; `consume()` runs only after dispatch succeeds. Concurrent dispatches with the same id can both pass.

**Remediation:** Atomic reserve-on-admit (mark/delete in `requireLive`, or consume at start with rollback on failure).

### OPE-003 — matrix not re-checked on dispatch

Matrix is enforced on `/preassign` only. Dispatch accepts any `x-ope-engine-id` after F′ admit (design §2.2: re-check matrix).

**Remediation:** Require live assign and verify `keySet`/`engineSet` against matrix on dispatch.

### OPE-004 — mTLS override via env

`TEECHAT_GATEWAY_OPE_API_REQUIRE_MTLS=0` disables client cert checks even when `CLIENT_PINS` is set.

**Remediation:** Prod fail-closed: non-empty pins ⇒ `requireMtls` (ignore override or refuse startup).

### OPE-005 — gateway prod F′ without TLS/mTLS

Production build can enable F′ with plain HTTP + bearer-only. Edge forbids skip-verify in prod; gateway has no symmetric F′ harden check in `ope-prod-config`.

**Remediation:** F′ enabled in prod ⇒ TLS 1.3 + `requireMtls` + non-empty pins (or explicit staging waiver).

### OPE-006 — edge `http://` F′ URL in prod

`validate_for_profile` rejects `INSECURE_SKIP_VERIFY` but not `http://` schemes. Cleartext carries bearer + OPE bodies.

**Remediation:** Prod requires `https://` for `OPENAPI_GATEWAY_OPE_API_URL`.

### OPE-007 — unbound billing key_id

`x-teechat-openapi-key-id` is taken from the F′ request with no binding to preassign / L0. Engine sig still verifies; attribution follows the header.

**Remediation:** Bind `key_id` in preassign; ingest only that id; reject mismatch. (Overlaps **METER-002**.)

---

## 3. Well mitigated (this path)

| Control | Notes |
|---------|--------|
| `traffic_class` spoof | Gateway deletes client `meta.traffic_class`; stamps `api` from admitted F′ handler |
| Clear-HTTP → vLLM in prod | `OPENAPI_UPSTREAM_CLEAR_HTTP` + `OPENAPI_PROFILE=prod` fail closed |
| TLS skip-verify in prod | Forbidden on edge dialer |
| Empty CLIENT_PINS + requireMtls | Startup `ope_api_missing_pins` |
| Engine usage forge | Ledger verifies engine Ed25519 before persist |

---

## 4. Residual (not medium+)

| Topic | Assessment |
|-------|------------|
| `ALLOW_NON_PRIVATE` + `0.0.0.0` | Depends on hypervisor / WG isolation; not a standalone code bug |
| `usage_from_header_or_estimate` | Client-visible OpenAI `usage` shape; ledger uses engine-signed report |
| `assign_id` not AEAD-bound | HTTP header only; honesty assumes F′ channel integrity |
| Edge does not verify epoch `identity_signature` | Trusts F′ trust JSON over admitted channel |

---

## 5. Fix order

1. **P1** — OPE-001 + OPE-002 (require + atomic `assign_id`)
2. **P1** — OPE-003 (matrix on dispatch; follows from required assign)
3. **P1** — OPE-005 + OPE-006 + OPE-004 (prod F′ TLS/mTLS / `https://` fail-closed)
4. **P1** — OPE-007 / METER-002 (bind `key_id` through preassign)
5. **P2** — CFG-001 (EDP); ATT residual; Bearer retire on F′

---

## 6. Tracker status after this review

| ID | Status |
|----|--------|
| **OPE-EDGE-001** | **Reviewed** — 7 medium open (OPE-001…007); path no longer “pending when built” |
| **TOPO-001** | **Mostly mitigated** in live prod (`mtls_bearer` + pins); residual = OPE-004/005 + private-bind ops |
| **METER-002** | **Partial** — engine-signed ingest exists; OPE-007 + Slice D remain |
| **QUOTA-001** | Edge gate done; L0 `remaining_tokens` feed follow-on |
| **CFG-001** | Still deferred (EDP / SGX) |
