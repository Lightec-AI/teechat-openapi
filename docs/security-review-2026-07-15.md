# Security review — 2026-07-15 (re-eval)

**Scope:** Re-score prior findings ([2026-07-12](./security-review-2026-07-12.md), [2026-07-14](./security-review-2026-07-14.md)) after an **updated product / architecture design** (2026-07-15). Design detail is **out of scope** for this public note; teaChat internal design docs are authoritative.

**Method:** Design/code posture review. Not a new full-module penetration test.

**Related:** [`SECURITY.md`](../SECURITY.md) · [2026-07-14 follow-up](./security-review-2026-07-14.md) · [**2026-07-20 OPE-EDGE-001**](./security-review-2026-07-20.md)

---

## 1. Summary

The prior reviews remain valid against the code and mitigations they described. An **updated design** changes residual **priority** and **end-state remediation** for some items:

| Effect | IDs |
|--------|-----|
| Elevated to **launch P0** (now mitigated) | PROXY-001, ROUTE-001 |
| Prior mitigation **interim** vs new metering end-state | METER-001 → track **METER-002** (partial after F′ cutover) |
| F′ / OPE path | **TOPO-001** mostly mitigated live; **OPE-EDGE-001** reviewed 2026-07-20 (**7 medium**) |
| Deferred for first SKU | CFG-001 (and SGX-oriented ATT polish) |
| Mitigated | TLS-001; QUOTA-001 (edge gate) |

**Verdict:** Prior High remediations still hold. After Slice C hard cutover, **OPE-001…007** remediations landed — see [2026-07-20](./security-review-2026-07-20.md).

---

## 2. Scoreboard

| ID | Status vs updated design |
|----|--------------------------|
| ATT-001 | Mitigated; lower launch priority |
| ATT-002 / ATT-003 | Mitigated |
| AUTH-001 / NET-001 / DOS-001 / IDLE-001 | Mitigated (further admission controls still owed) |
| OPS-001 / OPS-002 / BENCH-001 | Mitigated |
| PROXY-001 + ROUTE-001 | **Mitigated** — allowlist default + path normalize; prod forbids transparent |
| METER-001 | Mitigated for prior model; **not** final metering authority |
| METER-002 | **Mostly mitigated** — key_id bound at P1; Slice D optional |
| TOPO-001 | **Mitigated** (F′ harden fail-closed) |
| OPE-EDGE-001 | **Mitigated** — OPE-001…007 remediations landed |
| CFG-001 | Open; **deferred** |
| TLS-001 | **Mitigated** — prod requires cert + TLS acceptor |
| CRYPTO-001 | Still valid positives |

---

## 3. Fix order (updated)

1. **Done** — PROXY-001 + ROUTE-001  
2. **Done** — TLS-001  
3. **Done** — QUOTA-001 (edge gate; L0 remaining feed follow-on)  
4. **Done** — F′ harden land + Slice C hard cutover (code)  
5. **Done** — OPE-001…007  
6. **P2** — ATT residual; CFG-001; Bearer retire; Slice D polish  
