# Attestation challenge — wire format (v1)

**Status:** Locked contract for Option A (challenge-bound `report_data`). Implementation must match this document; do not invent alternate hashes.

**Related:** [`SECURITY.md`](../SECURITY.md) · product docs at [openapi.teechat.ai](https://openapi.teechat.ai)

This is the public, researcher-facing pin for:

1. Client → `POST /v1/attestation/challenge`
2. Edge → hardware evidence with bound `report_data`
3. Client → verify quote signature, freshness, and measurements

---

## 1. Three-step verification (summary)

| Step | Actor | Action |
|------|--------|--------|
| **1. Challenge** | Client | Generate a **32-byte** random nonce; `POST /v1/attestation/challenge` with `nonce_b64` (URL-safe, no padding). Prefer the **same TLS connection** you will use for API calls if you need session binding. |
| **2. Attest** | Edge | Build `report_data` per §3; generate a **remotely verifiable** quote (SGX: DCAP ECDSA via QE; CVM: SNP attestation report); return JSON per §2. |
| **3. Verify** | Client | (a) Verify hardware quote / cert chain (DCAP or AMD VCEK). (b) Recompute `report_data` and match the quote’s user-data field. (c) Pin measurement + build against the published regional manifest; optionally require `edge.tls_cert_spki_sha256` == this connection’s peer SPKI. |

**OpenAI-compatible default:** skip steps 1–3. That is intentional — openapi is **verifiable**, not fail-closed. Fail-closed per-prompt security is **`ope.*` + TeeChat SDK**.

**Hybrid policy (if you verify):** challenge when peer SPKI is unknown/changed, when the manifest allowlist/epoch changes, or when trust TTL expires (recommend ≤ 1 hour). Never re-challenge every prompt. Details in `SECURITY.md`.

---

## 2. JSON request / response

### 2.1 Request

`POST /v1/attestation/challenge`  
`Content-Type: application/json`  
**No** `Authorization` required.

```json
{
  "nonce_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}
```

| Field | Rule |
|-------|------|
| `nonce_b64` | URL-safe Base64, **no padding**. Decodes to **exactly 32 bytes**. Other lengths → `400`. |

Schema: [`manifest/schema/attestation-challenge-request.v1.json`](../manifest/schema/attestation-challenge-request.v1.json)

### 2.2 Response (`200`)

```json
{
  "schema_version": 1,
  "report_data_version": 1,
  "edge": {
    "build_version": "0.1.1",
    "code_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "measurement": {
      "kind": "mrenclave",
      "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    "tls_cert_spki_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  },
  "challenge_nonce_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "quote_format": "sgx_dcap_ecdsa",
  "quote_b64": "<standard Base64 of quote bytes>"
}
```

| Field | Type | Rule |
|-------|------|------|
| `schema_version` | u32 | Must be `1` for this document. |
| `report_data_version` | u32 | Must be `1` — selects §3 preimage. |
| `edge.build_version` | string | UTF-8 build id published in the regional manifest. |
| `edge.code_hash` | string | **64** lowercase hex chars = SHA-256 of the measured software artifact (as published). |
| `edge.measurement` | object | Discriminated by `kind` (see below). |
| `edge.tls_cert_spki_sha256` | string | **64** lowercase hex = SHA-256(DER **SubjectPublicKeyInfo** of the **serving** TLS leaf). |
| `challenge_nonce_b64` | string | Echo of the request nonce (same encoding). Must equal the client’s nonce. |
| `quote_format` | string | See §2.3. |
| `quote_b64` | string | **Standard** Base64 (with padding allowed) of the raw quote/report bytes. |

#### `edge.measurement`

| `kind` | Fields | Meaning |
|--------|--------|---------|
| `mrenclave` | `value` (64 hex) | Intel SGX enclave measurement (Fortanix EDP). |
| `launch_digest` | `launch_digest` (64 hex), `image_digest` (64 hex) | SEV-SNP / TDX CVM launch digest + guest image digest. |

Wire shape matches serde `tag = "kind"` used in `openapi-platform::Measurement` (snake_case kinds). For `mrenclave`, JSON is:

```json
{ "kind": "mrenclave", "value": "<64 hex>" }
```

For CVM:

```json
{
  "kind": "launch_digest",
  "launch_digest": "<64 hex>",
  "image_digest": "<64 hex>"
}
```

Schema: [`manifest/schema/attestation-challenge-response.v1.json`](../manifest/schema/attestation-challenge-response.v1.json)

### 2.3 `quote_format`

| Value | Remotely verifiable? | Notes |
|-------|----------------------|--------|
| `sgx_dcap_ecdsa` | **Yes** | **Production SGX target** for Option A. ECDSA quote from Quoting Enclave. |
| `sgx_report` | **No** | Local `REPORT` only (same-platform). Interim / lab; verifiers must **reject** for internet clients. |
| `snp_report` | **Yes** (with VCEK chain) | AMD SEV-SNP attestation report bytes. |
| omitted / null | — | No evidence; treat as failure for verifying clients. |

Encoding note: `quote_b64` uses **standard** Base64; `nonce_b64` / `challenge_nonce_b64` use **URL-safe, no pad**.

---

## 3. `report_data` byte layout (v1)

Intel SGX / SNP user-data fields are **64 bytes**. TeeChat binds a SHA-256 digest into the first half.

### 3.1 Output field

```text
report_data[0..32]  = SHA-256(preimage)
report_data[32..64] = 0x00 × 32
```

The quote’s `report_data` (SGX) or `REPORT_DATA` (SNP) **must** equal this 64-byte value. Clients recompute `preimage` from the JSON + their nonce and compare.

### 3.2 Preimage (`report_data_version = 1`)

All integers below are **unsigned big-endian**. Concatenation is raw bytes (no extra delimiters beyond what is specified).

```text
preimage =
    magic
 || nonce
 || spki_sha256
 || build_digest
 || code_hash
 || measurement_body
```

| Component | Size | Content |
|-----------|------|---------|
| `magic` | 28 | ASCII `teechat-openapi-challenge-v1` (exactly 28 bytes, no trailing NUL) |
| `nonce` | 32 | Raw challenge nonce |
| `spki_sha256` | 32 | Raw bytes of `edge.tls_cert_spki_sha256` (hex-decoded) |
| `build_digest` | 32 | `SHA-256(UTF-8 bytes of edge.build_version)` |
| `code_hash` | 32 | Raw bytes of `edge.code_hash` (hex-decoded) |
| `measurement_body` | variable | See §3.3 |

### 3.3 `measurement_body`

**SGX (`kind = mrenclave`):**

```text
measurement_body =
    0x01
 || mrenclave           // 32 bytes, hex-decode of measurement.value
```

**CVM (`kind = launch_digest`):**

```text
measurement_body =
    0x02
 || launch_digest       // 32 bytes
 || image_digest        // 32 bytes
```

### 3.4 Pseudocode (verify)

```text
assert decode_urlsafe(challenge_nonce_b64) == my_nonce
assert len(my_nonce) == 32
assert report_data_version == 1

preimage = magic || my_nonce || spki || sha256(build_version) || code_hash || measurement_body
expected = sha256(preimage) || zeroes(32)

assert quote.report_data == expected
# then DCAP / VCEK verify quote, then pin MRENCLAVE / launch_digest to manifest
```

### 3.5 Why this shape

- **Fixed 32-byte nonce** — unambiguous; matches common RA practice.
- **SPKI in the hash** — binds evidence to the serving TLS identity (session binding when the client also checks peer SPKI).
- **Hashes of variable strings** (`build_version`) — avoids length-prefix footguns in hand-rolled parsers.
- **Tagged measurement** — one preimage recipe for SGX and CVM.
- **Second 32 bytes zero** — leaves room for a future v2 without changing the first-half convention used by ITA-style verifiers.

---

## 4. Server duties (edge)

1. Reject nonce ≠ 32 bytes.
2. Use the **currently serving** TLS leaf SPKI (not a stale env copy that can drift from the acceptor).
3. Fill `report_data` **before** REPORT/quote generation — **never** post-process quote bytes.
4. Prefer `quote_format = sgx_dcap_ecdsa` (or `snp_report` on CVM) for any deployment that claims remote verifiability. SGX production path uses host `openapi-dcap-helper` + AESM/QE; without PCCS/helper the challenge fails closed (no silent `sgx_report` downgrade).
5. Canonicalize identity digests before hashing: 64-hex fields are lowercased; non-hex staging values (e.g. `code_hash=unknown`) become `hex(SHA-256(utf8))` in both `report_data` and the JSON response.
6. On quote infrastructure failure (aesmd / QE / PCCS / snpguest), return a clear `5xx` with a stable error code — do not return a local REPORT labeled as a DCAP quote.
7. Rate-limit the public challenge endpoint by client IP (`OPENAPI_CHALLENGE_RPM`) and cap concurrent quotes (`OPENAPI_CHALLENGE_MAX_INFLIGHT`). Do not require TeeChat JWTs.

---

## 5. Client duties (verifying integrator / monitor)

1. **Quote signature** — DCAP ECDSA (+ collateral) or AMD VCEK chain.
2. **TCB policy** — reject debug enclaves; apply your TCB/advisory policy.
3. **`report_data`** — §3 recompute must match.
4. **Manifest pin** — `mrenclave` / `launch_digest` (+ `code_hash`, `build_version`) ∈ published allowlist for that region/epoch.
5. **Session bind (serious clients)** — `edge.tls_cert_spki_sha256` equals SHA-256(SPKI) of **this** TLS peer. Monitors probing the VIP may omit session bind and only check live measurement.
6. **Cache** — `(peer_SPKI → measurement, expiry)` per hybrid policy; do not treat another connection’s challenge as proof for yours.

---

## 6. Latency and failure (ops expectations)

| Phase | Typical | Failure modes |
|-------|---------|----------------|
| Build preimage + `EREPORT` | µs–ms | Logic bugs only |
| SGX DCAP quote (warm) | ~10–100+ ms | aesmd down, QE load, out of EPC, attestation key not init |
| Quote cold / PCCS miss | 100 ms–seconds | PCCS/PCS unreachable, platform not registered |
| Client verify + collateral | 10 ms–seconds | Collateral fetch, outdated TCB |

Challenge is appropriate for hybrid/rare verification — **not** per prompt.
