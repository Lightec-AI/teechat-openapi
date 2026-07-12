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
- **`OPENAPI_TLS_KEY_PATH`** forbidden.
- **`OPENAPI_SEAL_ROOT_HEX`** forbidden — seal root is derived inside the TEE, not supplied by the host.
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

`POST /v1/attestation/challenge` returns edge identity (measurement, code hash, TLS SPKI, build version) bound to a client nonce. SGX deployments include an enclave REPORT in `quote_b64` when running on hardware.

### Integrator reminder — attestation

**OpenAI-compatible default:** most `base_url` + API key clients **skip** attestation. That is **normally acceptable** for this product: TLS still terminates in the TEE, and **`POST /v1/attestation/challenge` is public** (no API key) so anyone can independently check the live measurement against the published manifest. Skipping does **not** prove *your* connection was verified — only that verification is optional and externally auditable.

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

---

## Scope

This repository implements the **Edge OpenAI proxy** (L1 Edge KMS). It does **not** hold user prompts at rest, Platform KMS keys, or billing/catalog signing keys — those live in separate TeaChat control-plane services.

**Security reviews:** [docs/security-review-2026-07-12.md](docs/security-review-2026-07-12.md) (static review · Cursor Grok 4.5 High Fast).

Product documentation: [openapi.teechat.ai](https://openapi.teechat.ai) (when published).
