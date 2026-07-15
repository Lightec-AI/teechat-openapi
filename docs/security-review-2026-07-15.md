# Security review — 2026-07-15 (re-eval)

**Scope:** Re-score prior findings ([2026-07-12](./security-review-2026-07-12.md), [2026-07-14](./security-review-2026-07-14.md)) after an **updated product / architecture design** (2026-07-15). Design detail is **out of scope** for this public note; teaChat internal design docs are authoritative.

**Method:** Design/code posture review. Not a new full-module penetration test.

**Related:** [`SECURITY.md`](../SECURITY.md) · [2026-07-14 follow-up](./security-review-2026-07-14.md)

---

## 1. Summary

The prior reviews remain valid against the code and mitigations they described. An **updated design** changes residual **priority** and **end-state remediation** for some items:

| Effect | IDs |
|--------|-----|
| Elevated to **launch P0** (now mitigated) | PROXY-001, ROUTE-001 |
| Prior mitigation **interim** vs new metering end-state | METER-001 → track **METER-002** |
| New open trackers (spec/code not landed) | TOPO-001, QUOTA-001 |
| Deferred for first SKU | CFG-001 (and SGX-oriented ATT polish) |
| Still **P1** before public prod | TLS-001 |

**Verdict:** Prior High remediations still hold. Do **not** treat the residual queue as “P2 proxy/cfg/tls only.” Ship PROXY/ROUTE before public claim; then align metering / dispatch / admission with the updated design; require TLS acceptor in prod.

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
| METER-002 / TOPO-001 | **Open** |
| CFG-001 | Open; **deferred** |
| TLS-001 | **Mitigated** — prod requires cert + TLS acceptor |
| CRYPTO-001 | Still valid positives |

---

## 3. Fix order (updated)

1. **Done** — PROXY-001 + ROUTE-001  
2. **Done** — TLS-001  
3. **Done** — QUOTA-001 (edge gate; L0 remaining feed follow-on)  
4. **P1** — METER-002, TOPO-001  
5. **P2** — ATT residual; CFG-001 with later SKU  
