# TeeChat OpenAPI Edge Proxy

Apache-2.0 open-source edge proxy for [`openapi.<region>.teechat.ai`](https://teechat.ai) — OpenAI-compatible HTTP API with API-key auth, signed usage reports, and optional attestation challenge.

## Endpoints

| Method | Path | Auth |
|--------|------|------|
| `GET` | `/healthz` | none |
| `GET` | `/v1/models` | Bearer API key |
| `POST` | `/v1/chat/completions` | Bearer API key |
| `POST` | `/v1/attestation/challenge` | none |

Non-streaming responses include `X-TeeChat-Usage-Report`. Streaming (`stream: true`) appends a final SSE event with signed usage.

## Build

```bash
cargo test --workspace
cargo build --release -p openapi
```

## Run (dev)

```bash
./scripts/dev-run.sh
```

Required env vars:

| Variable | Description |
|----------|-------------|
| `OPENAPI_UPSTREAM_BASE_URL` | Inference engine base URL |
| `OPENAPI_CATALOG_PATH` | Path to signed key catalog JSON |
| `OPENAPI_CATALOG_VERIFY_KEY_HEX` | Ed25519 public key (32 bytes, hex) |
| `OPENAPI_USAGE_SIGN_SEED_HEX` | Ed25519 signing seed (32 bytes, hex) |

Optional: `OPENAPI_LISTEN_ADDR` (default `0.0.0.0:8443`), `OPENAPI_REGION`, attestation identity fields (`OPENAPI_BUILD_VERSION`, `OPENAPI_CODE_HASH`, `OPENAPI_LAUNCH_DIGEST`, `OPENAPI_IMAGE_DIGEST`).

### TLS (production)

| Variable | Description |
|----------|-------------|
| `OPENAPI_TLS_CERT_PATH` | Server certificate PEM (public) |
| `OPENAPI_TLS_SEALED_KEY_PATH` | Measurement-bound sealed private key JSON (**production**) |
| `OPENAPI_SEAL_ROOT_HEX` | Optional 32-byte platform seal root (hex) mixed into HKDF |
| `OPENAPI_TLS_KEY_PATH` | Plaintext private key PEM (**dev only**) |

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
manifest/schema/              # signed catalog + edge manifest JSON Schema
deploy/cvm/                   # CVM guest packaging
deploy/sgx/                   # EDP build notes
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
