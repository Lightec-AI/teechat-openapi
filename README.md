# TeeChat OpenAPI Edge Proxy

Apache-2.0 open-source edge proxy for [`openapi.<region>.teechat.ai`](https://teechat.ai) — OpenAI-compatible HTTP API with API-key auth, signed usage reports, and optional attestation challenge.

## Supported routes

Drop-in OpenAI SDK compatibility: authenticate, rate-limit, forward to `OPENAPI_UPSTREAM_BASE_URL` (engine root, e.g. `http://127.0.0.1:8000`).

| Tier | Routes | Usage report |
|------|--------|--------------|
| **Inference (metered)** | `POST /v1/chat/completions`, `/v1/completions`, `/v1/embeddings`, `/v1/responses`, `/v1/moderations` | Yes (`X-TeeChat-Usage-Report` or SSE trailer) |
| **Discovery** | `GET /v1/models` | No |
| **Transparent proxy** | Other `GET`/`POST /v1/*` not listed below | No |
| **Attestation** | `POST /v1/attestation/challenge` | No |
| **Not supported (501)** | `/v1/files`, `/v1/batches`, `/v1/assistants`, `/v1/threads`, `/v1/fine_tuning`, `/v1/vector_stores`, `/v1/audio`, `/v1/images`, `/v1/videos`, `/v1/realtime`, … | — |

Ephemeral in-memory state (TTL, no disk) may be added later for batch/file compat. Process restart clears all ephemeral IDs.

Non-streaming inference responses include `X-TeeChat-Usage-Report`. Streaming (`stream: true`) uses **chunked SSE passthrough** (upstream bytes forwarded incrementally) and appends a final signed usage event.

`GET /v1/models` always proxies the upstream engine list; the edge does not substitute a static catalog when upstream is reachable.

## Endpoints (minimum)

| Method | Path | Auth |
|--------|------|------|
| `GET` | `/healthz` | none (liveness) |
| `GET` | `/v1/status` | none — `mode: ok\|maintenance`, optional `retry_after` |
| `GET` | `/v1/models` | Bearer API key |
| `POST` | `/v1/chat/completions` | Bearer API key |
| `POST` | `/v1/attestation/challenge` | none |

**Planned maintenance:** when a verified ops-signed window is loaded (`OPENAPI_MAINTENANCE_MANIFEST_PATH` + `.sig`), inference/models/proxy return HTTP **503** with `error.code: "maintenance"` and `Retry-After`. `/healthz` and attestation stay up. Same contract on `openapi.teechat.ai` and `lab.openapi.teechat.ai`.

**Attestation (verifying clients):** three-step challenge → quote → verify. Locked wire format: [`docs/attestation-challenge.md`](docs/attestation-challenge.md) · summary in [`SECURITY.md`](SECURITY.md).

## Build

```bash
cargo test --workspace
cargo build --release -p openapi
```

### Compile-time features (mandatory disclosure)

Any Cargo `feature = "…"` that changes **runtime** behavior (auth path, seal policy, etc.) must:

1. Be listed in the crate’s `log_compile_time_features()` helper (or equivalent).
2. Be **logged on every process start** immediately after the tracing subscriber is installed — before accepting traffic.
3. Stay **off** in production release builds unless the feature is an intentional prod train.

Current edge (`openapi` / `openapi-platform-cvm`) gates:

| Feature | Default | Effect |
|---------|---------|--------|
| `catalog-auth` | off | Enables file-catalog `OPENAPI_AUTH_MODE=catalog` (lab only). Prod is remote-only. |

Startup log target: `openapi_compile_features` (fields include each gate as a bool). Example:

```text
INFO openapi_compile_features: compile-time feature gates (logged every start) crate_name="openapi-platform-cvm" catalog_auth=false
```

Lab: `cargo build -p openapi --features catalog-auth`.

## Run (dev)

```bash
./scripts/dev-run.sh
./scripts/smoke-openapi-agent.sh   # health, models, stream + UTF-8 (see docs/streaming-contract.md)
```

Required env vars:

| Variable | Description |
|----------|-------------|
| `OPENAPI_UPSTREAM_BASE_URL` | Inference engine root URL (e.g. `http://127.0.0.1:8000`) |
| `OPENAPI_CATALOG_PATH` | Path to signed key catalog JSON |
| `OPENAPI_CATALOG_VERIFY_KEY_HEX` | Ed25519 public key (32 bytes, hex) |
| `OPENAPI_USAGE_SIGN_SEED_HEX` | Ed25519 signing seed (32 bytes, hex) |

Optional: `OPENAPI_LISTEN_ADDR` (default `0.0.0.0:8443`), `OPENAPI_REGION`, attestation identity fields (`OPENAPI_BUILD_VERSION`, `OPENAPI_CODE_HASH`, `OPENAPI_LAUNCH_DIGEST`, `OPENAPI_IMAGE_DIGEST`).

### Gateway OPE API plane (F′ — privileged edge→gateway)

Optional dialer for the gateway private OPE API listener (`GET /v1/ope/api/health`, `POST /v1/ope/dispatch`). CVM edge probes health at startup when the URL is set (log-only; prod logs a fail-closed warning if health fails).

| Variable | Description |
|----------|-------------|
| `OPENAPI_GATEWAY_OPE_API_URL` | Base URL, e.g. `https://10.x.x.x:8791` (unset = skip plane) |
| `OPENAPI_GATEWAY_OPE_API_TOKEN` | Bearer `DISPATCH_TOKEN` for F′ launch auth |
| `OPENAPI_GATEWAY_OPE_API_TLS_CLIENT_CERT_PEM` | Client cert PEM path or inline (mTLS harden) |
| `OPENAPI_GATEWAY_OPE_API_TLS_CLIENT_KEY_PEM` | Client key PEM path or inline |
| `OPENAPI_GATEWAY_OPE_API_TLS_CA_PEM` | Optional CA PEM to verify gateway server cert |
| `OPENAPI_GATEWAY_OPE_API_TLS_INSECURE_SKIP_VERIFY` | `0` default; `1` skips server verify (**dev only**, forbidden in `OPENAPI_PROFILE=prod`) |
| `OPENAPI_ENGINE_IDENTITY_PINS_JSON` | Legacy anchor, required with OPE dispatch **unless** `OPENAPI_OPE_REQUIRE_EPOCH_EVIDENCE=1`: JSON map of engine id to attestation-approved Ed25519 identity key; its canonical SHA-256 is included in `policy_hash` |
| `OPENAPI_OPE_EPOCH_CLOCK_SKEW_SEC` | Engine epoch validity skew; default `300` |

**Engine recipient policy.** These decide which epoch key a customer request is encrypted to, so they replace the identity pin rather than supplementing it. Generate them from the signed golden manifest with `pnpm ops:openapi-engine-recipient-env` in the TeaChat repo instead of writing them by hand.

| Variable | Description |
|----------|-------------|
| `OPENAPI_OPE_REQUIRE_EPOCH_EVIDENCE` | `1` requires an attestation binding the epoch's own ML-KEM, X25519, and usage keys (bind v2) and refuses to fall back to the pin; `0` default during fleet cutover |
| `OPENAPI_ENGINE_LAUNCH_DIGEST_ALLOWLIST` | Comma-separated composed launch digests, derived from `MEASUREMENT` inside the report rather than from any claim the engine sends |
| `OPENAPI_OPE_REQUIRE_ENGINE_LAUNCH_DIGEST` | `1` refuses an engine whose measurement is absent from the allowlist |
| `OPENAPI_OPE_VERIFY_ENGINE_SNP_CHAIN` | `1` verifies the AMD ARK/ASK/VCEK chain over the engine report, cached per report so KDS stays off the request path. CVM only — the SGX build has no route to KDS under Fortanix EDP |

TLS to this plane is **TLS 1.3 only** (ureq + rustls). See [SECURITY.md](SECURITY.md) § Gateway OPE API dialer.

### TLS (production)

| Variable | Description |
|----------|-------------|
| `OPENAPI_TLS_CERT_PATH` | Server certificate PEM (public) |
| `OPENAPI_TLS_SEALED_KEY_PATH` | Measurement-bound sealed private key JSON (**production**) |
| `OPENAPI_PROFILE` | Required: explicit `dev` or **`prod`**; missing/unknown values abort startup |
| `OPENAPI_SEAL_ROOT_HEX` | Dev-only optional 32-byte HKDF input; **forbidden in prod** (derived in TEE) |
| `OPENAPI_TLS_KEY_PATH` | Plaintext private key PEM (**dev only**) |

**Wire protocol:** the edge listener is **TLS 1.3 only** (rustls `builder_with_protocol_versions([&TLS13])`; `tls12` feature disabled). Verify after deploy: `bash scripts/verify-tls13-only.sh`. Hypervisor nginx uses TCP passthrough — it does not terminate TLS for openapi.

Seal a key for the current guest measurement:

```bash
OPENAPI_LAUNCH_DIGEST=... OPENAPI_IMAGE_DIGEST=... ./scripts/seal-tls-key.sh key.pem tls-key.sealed.json
```

### SGX (Fortanix EDP)

See [deploy/sgx/README.md](deploy/sgx/README.md) for physical-machine bring-up.

```bash
./deploy/sgx/build-enclave.sh
./scripts/dev-run-sgx.sh
```

## Workspace layout

```
crates/openapi-core           # routes, auth, catalog, usage (no TEE I/O)
crates/openapi-http           # HTTP/1.1 + SSE
crates/openapi-platform       # platform traits
crates/openapi-platform-cvm   # Linux CVM guest (production default)
crates/openapi-platform-sgx   # Fortanix EDP (optional)
bins/openapi                  # CVM edge binary
bins/openapi-enclave          # SGX EDP enclave binary
bins/seal-tls-key-sgx         # Seal TLS key to MRENCLAVE
bins/seal-tls-key             # seal TLS private key for CVM guest
manifest/schema/              # signed catalog + sealed TLS key JSON Schema
deploy/cvm/                   # CVM guest packaging
deploy/sgx/                   # EDP build notes
SECURITY.md                   # vulnerability reporting + sealing summary
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
