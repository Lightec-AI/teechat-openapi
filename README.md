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
| `GET` | `/healthz` | none |
| `GET` | `/v1/models` | Bearer API key |
| `POST` | `/v1/chat/completions` | Bearer API key |
| `POST` | `/v1/attestation/challenge` | none |

**Attestation (verifying clients):** three-step challenge → quote → verify. Locked wire format: [`docs/attestation-challenge.md`](docs/attestation-challenge.md) · summary in [`SECURITY.md`](SECURITY.md).

## Build

```bash
cargo test --workspace
cargo build --release -p openapi
```

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

TLS to this plane is **TLS 1.3 only** (ureq + rustls). See [SECURITY.md](SECURITY.md) § Gateway OPE API dialer.

### TLS (production)

| Variable | Description |
|----------|-------------|
| `OPENAPI_TLS_CERT_PATH` | Server certificate PEM (public) |
| `OPENAPI_TLS_SEALED_KEY_PATH` | Measurement-bound sealed private key JSON (**production**) |
| `OPENAPI_PROFILE` | `dev` (default) or **`prod`** — see [SECURITY.md](SECURITY.md) |
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
