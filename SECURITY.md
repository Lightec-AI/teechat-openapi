# Security

## Reporting vulnerabilities

- **Email:** security@teechat.ai
- **GitHub:** [Security Advisories](https://github.com/Lightec-AI/teechat-openapi/security/advisories) on this repository

Please include reproduction steps, affected commit or release, and impact assessment.

---

## Edge TLS key sealing

Production edge nodes seal the TLS private key to a TEE measurement. Operators set **`OPENAPI_PROFILE=prod`**.

| `seal_version` | When | Mechanism |
|----------------|------|-----------|
| **1** | Dev, CVM staging | HKDF + AES-256-GCM bound to a measurement label in the sealed JSON blob |
| **2** | SGX (Fortanix EDP) | Intel **EGETKEY** / MRENCLAVE sealing ([Fortanix docs](https://edp.fortanix.com/docs/examples/sealing/)) |

### Production rules (`OPENAPI_PROFILE=prod`)

- **`OPENAPI_TLS_SEALED_KEY_PATH`** required — no plaintext private key on disk.
- **`OPENAPI_TLS_CERT_PATH`** required — successful TLS acceptor (TLS-001); plain TCP listen forbidden in prod.
- **`OPENAPI_TLS_KEY_PATH`** forbidden.
- **`OPENAPI_SEAL_ROOT_HEX`** forbidden — seal root is derived inside the TEE, not supplied by the host.
- **`OPENAPI_ATTESTED_LAUNCH_DIGEST`** forbidden — CVM dev/CI hook only; prod must use `snpguest` / `/dev/sev-guest` (OPS-001).
- Host-side **`seal-tls-key`** / **`seal-tls-key-sgx`** forbidden — use in-TEE ceremony (OPS-002).
- **`OPENAPI_CHALLENGE_BENCH_TOKEN`** forbidden — lab-only bypass of challenge RPM / in-flight caps (BENCH-001).
- **`OPENAPI_PROXY_MODE=transparent`** forbidden — prod is **allowlist-only** for `/v1/*` (PROXY-001 / ROUTE-001).
- **SGX:** runtime **MRENCLAVE** from enclave report must match the sealed blob (fail closed).
- **CVM:** **`OPENAPI_LAUNCH_DIGEST`** must match the guest-attested launch digest (`snpguest` / `/dev/sev-guest`).

### Sealed blob format

JSON schema: [`manifest/schema/sealed-tls-key.v1.json`](manifest/schema/sealed-tls-key.v1.json)

Seal tooling:

```bash
# CVM guest
OPENAPI_LAUNCH_DIGEST=... OPENAPI_IMAGE_DIGEST=... ./scripts/seal-tls-key.sh key.pem tls-key.sealed.json

# SGX enclave
OPENAPI_MRENCLAVE=... ./scripts/seal-tls-key-sgx.sh key.pem tls-key.sealed.json
```

### Attestation challenge

**Canonical pin:** [`docs/attestation-challenge.md`](docs/attestation-challenge.md) (request/response JSON, `report_data` preimage, quote formats).

`POST /v1/attestation/challenge` is the **Option A** path: clients send a **32-byte** nonce; the edge returns identity fields plus hardware evidence whose **64-byte `report_data`** embeds:

```text
report_data[0..32]  = SHA-256(preimage)
report_data[32..64] = 0x00 × 32
```

`preimage` (version 1) binds magic `teechat-openapi-challenge-v1` (28 ASCII bytes), the nonce, TLS SPKI SHA-256, build/code digests, and measurement (`MRENCLAVE` or launch/image digests). **Never** XOR or otherwise mutate quote bytes after generation.

Production SGX evidence must be a remotely verifiable **`sgx_dcap_ecdsa`** quote (not a local-only `sgx_report`). CVM uses `snp_report`. On Fortanix EDP, quote generation uses host `openapi-dcap-helper` (AESM/QE) plus a local PCCS (`deploy/sgx/setup-pccs.sh`).

#### Three-step verification

1. **Challenge** — Client generates a 32-byte nonce; `POST /v1/attestation/challenge` with `nonce_b64` (URL-safe, no pad). Prefer the same TLS session used for API calls when session-binding matters.
2. **Attest** — Edge fills `report_data`, obtains a DCAP/SNP quote (QE/aesmd or SNP device). Quote generation is typically tens to hundreds of milliseconds warm; cold PCCS/aesmd failures should surface as `5xx`, not a fake quote.
3. **Verify** — Client (a) verifies the Intel/AMD quote signature and TCB policy, (b) recomputes `report_data` and checks freshness/binding, (c) pins measurement / `code_hash` / `build_version` to the published allowlist, and optionally requires `edge.tls_cert_spki_sha256` to match **this** connection’s peer SPKI.

**Full verifier (recommended):** `teechat-openapi-attest verify https://openapi.teechat.ai` (crate `bins/teechat-openapi-attest`, library `openapi-attest`).

**Trust order:**

1. **GitHub Releases (primary)** — download `openapi-edge-attest.json` + `SHA256SUMS` from [Lightec-AI/teechat-openapi releases](https://github.com/Lightec-AI/teechat-openapi/releases). The challenged `code_hash` must match the allowlist and (when present) appear in `SHA256SUMS`.
2. **teechat.ai Ed25519-signed mirror (fallback)** — only if GitHub is unreachable. The verdict sets `trust_source=teechat_fallback` and includes `trust_fallback_tip` explaining how to re-check the GitHub release page when connectivity returns.
3. Local `--manifest` / `--sig` for ops.

Then: capture peer TLS identity over rustls, challenge the edge, verify SNP/VCEK or SGX DCAP+PCS, reject `sgx_report` for internet clients.

**Evidence-only curl** (`openssl rand` + `POST /v1/attestation/challenge`) saves a JSON response for inspection — it does **not** validate quote collateral, TCB, GitHub hashes, or session SPKI. Prefer the CLI or TeeChat desktop **Settings → Account → Verify OpenAPI edge**.

**OPE / InferenceEngine:** the same open-source pattern applies — GitHub CI publishes release binaries and `SHA256SUMS`; teechat.ai mirrors (if any) are network fallbacks only.

Step 3(b) is what makes a separate Ed25519 signature over the challenge JSON unnecessary for verifying clients (security review ATT-003): identity fields that matter are covered by hardware `report_data`.

JSON schemas: [`attestation-challenge-request.v1.json`](manifest/schema/attestation-challenge-request.v1.json), [`attestation-challenge-response.v1.json`](manifest/schema/attestation-challenge-response.v1.json).

### Integrator reminder — attestation

**OpenAI-compatible default:** most `base_url` + API key clients **skip** attestation. That is **normally acceptable** for this product: TLS still terminates in the TEE, and **`POST /v1/attestation/challenge` is public** (no API key, no TeeChat JWT) so anyone can independently check the live measurement against the published manifest. Skipping does **not** prove *your* connection was verified — only that verification is optional and externally auditable.

**DoS control:** the challenge endpoint is rate-limited by **client IP** (`OPENAPI_CHALLENGE_RPM`, default 10/min) and capped for **in-flight quotes** (`OPENAPI_CHALLENGE_MAX_INFLIGHT`, default 4). Do **not** require TeeChat login JWTs for challenge — that would break independent monitors and still not stop account-farmed abuse. Optional `OPENAPI_CHALLENGE_BENCH_TOKEN` (header `X-TeeChat-Challenge-Bench`) may bypass those caps for **dev/lab benches only** — forbidden when `OPENAPI_PROFILE=prod` (BENCH-001).

**If your client verifies attestation** (auditors, monitors, custom integrators), use the **hybrid** policy — not a challenge on every prompt:

Edge upgrades may use **in-place restart** or (future) **blue/green** connection drain. Either path **can change the TEE measurement** (and during a soak window the published manifest may allowlist more than one). Watching TLS peer SPKI alone is **not** enough (same cert can span measurement changes).

1. On each new TLS session, read **peer SPKI** from the handshake.
2. Run `POST /v1/attestation/challenge` when SPKI is **unknown or changed**, when the published **manifest allowlist/epoch** changed, or when trust **TTL** expired (recommend ≤ 1 hour).
3. Require the challenge response’s TLS SPKI hash to match **this connection’s** peer SPKI; pin measurement to the allowlist; cache `(SPKI → measurement, expiry)`.
4. If SPKI is unchanged and cache is valid, **skip** the challenge for that session.
5. Do **not** cache “hostname → measurement” without SPKI; do **not** treat another connection’s (or a public monitor’s) challenge as proof for yours.
6. Do **not** re-challenge on every prompt once the session is trusted.

### TLS wire protocol

The edge **server** negotiates **TLS 1.3 only**:

- rustls `ServerConfig::builder_with_protocol_versions([&TLS13])` in `openapi-platform::tls`
- Workspace `rustls` dependency built **without** the `tls12` feature (compile-time guard)

TLS 1.2 handshakes are rejected. This matches production gateway posture and limits legacy cipher exposure on the prompt path.

**Verify after deploy:**

```bash
bash scripts/verify-tls13-only.sh
# or against public hostname:
OPENAPI_TLS_VERIFY_HOST=openapi.teechat.ai OPENAPI_TLS_VERIFY_PORT=443 bash scripts/verify-tls13-only.sh
```

**Note:** Upstream calls to the inference engine (`OPENAPI_UPSTREAM_BASE_URL`, typically plain HTTP on a private LAN) are separate from client-facing edge TLS.

### Gateway OPE API dialer (F′)

The CVM edge may dial the TeaChat gateway **privileged OPE API plane** (private fabric listener; Bearer and/or pinned client mTLS). Env vars: `OPENAPI_GATEWAY_OPE_API_*` (see README). Rules:

- URL unset → no dialer / startup probe skipped (non-fatal).
- URL set + health fail under `OPENAPI_PROFILE=prod` → **fail-closed warn** (OPE dispatch treated as unavailable; process still starts for OpenAI surface).
- `OPENAPI_GATEWAY_OPE_API_TLS_INSECURE_SKIP_VERIFY=1` is **forbidden in prod**.
- Client cert/key PEMs should be measurement-sealed in the edge TEE for harden (same ceremony posture as server TLS sealing); gateway stores **pins only**.

---

## Scope

This repository implements the **Edge OpenAI proxy** (L1 Edge KMS). It does **not** hold user prompts at rest, Platform KMS keys, or billing/catalog signing keys — those live in separate TeaChat control-plane services.

**Security reviews:**
- [docs/security-review-2026-07-12.md](docs/security-review-2026-07-12.md) (static review · Cursor Grok 4.5 High Fast)
- [docs/security-review-2026-07-14.md](docs/security-review-2026-07-14.md) (follow-up at tip `d8feabf` · Cursor Composer)
- [docs/security-review-2026-07-15.md](docs/security-review-2026-07-15.md) (re-eval after updated design · residual priorities)

Product documentation: [openapi.teechat.ai](https://openapi.teechat.ai) (when published).
