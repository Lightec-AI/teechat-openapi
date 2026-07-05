# TeeChat OpenAPI Edge Proxy

Apache-2.0 open-source edge proxy for [`openapi.<region>.teechat.ai`](https://teechat.ai) — OpenAI-compatible HTTP API with API-key auth, signed usage reports, and optional attestation challenge.

Architecture and KMS context live in the private [TeaChat](https://github.com/Lightec-AI/TeaChat) repo (`docs/design/teechat-openapi.md`, `docs/design/public-api-surfaces.md`).

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

Optional: `OPENAPI_LISTEN_ADDR` (default `0.0.0.0:8443`), `OPENAPI_TLS_CERT_PATH`, `OPENAPI_TLS_KEY_PATH`, `OPENAPI_REGION`, attestation identity fields (`OPENAPI_BUILD_VERSION`, `OPENAPI_CODE_HASH`, `OPENAPI_LAUNCH_DIGEST`, `OPENAPI_IMAGE_DIGEST`).

## Workspace layout

```
crates/openapi-core           # routes, auth, catalog, usage (no TEE I/O)
crates/openapi-http           # HTTP/1.1 + SSE
crates/openapi-platform       # platform traits
crates/openapi-platform-cvm   # Linux CVM guest (production default)
crates/openapi-platform-sgx   # Fortanix EDP (optional)
bins/openapi                  # edge binary
manifest/schema/              # signed catalog + edge manifest JSON Schema
deploy/cvm/                   # CVM guest packaging
deploy/sgx/                   # EDP build notes
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
