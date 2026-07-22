# Fortanix EDP (Intel SGX) — physical machine bring-up

Production SGX builds use **`x86_64-fortanix-unknown-sgx`**. The whole Rust binary runs inside the enclave (`ftxsgx-runner`); this is **not** Gramine/Occlum and **not** WASM.

Product docs: [openapi.teechat.ai](https://openapi.teechat.ai). Sealing: [SECURITY.md](../../SECURITY.md).

## 1. Host prerequisites (SGX-capable Linux)

On your SGX machine (e.g. Xeon E-2388G / E-2374G with 512 MiB EPC):

```bash
# BIOS: enable SGX + FLC; set EPC size if configurable
# Ubuntu 22.04+ example:
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev openssl curl

# Intel AESM / DCAP (distro packages vary)
# See Intel SGX driver + aesmd install guide for your OS

# Rust (nightly required for Fortanix EDP `sgx_platform`)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install nightly
rustup target add x86_64-fortanix-unknown-sgx --toolchain nightly
# Optional (CN / slow uplink): RUSTUP_DIST_SERVER=https://rsproxy.cn

# Fortanix EDP tools
cargo install fortanix-sgx-tools sgxs-tools

# Repo already ships .cargo/config.toml with:
#   runner = "ftxsgx-runner-cargo"
```

Verify hardware:

```bash
./deploy/sgx/sgx-preflight.sh
# or: sgx-detect
```

## 2. Build + sign enclave

```bash
cd /path/to/teechat-openapi
./deploy/sgx/build-enclave.sh
# or: ./scripts/dev-run-sgx.sh   # builds, signs, runs with inline catalog
```

**Fortanix EDP notes (lab):**

- Enclave starts with an **empty environment** — pass `OPENAPI_*=…` as `ftxsgx-runner` enclave args (see `run-enclave.sh`). Host `export` does not inject.
- No host filesystem — use **`OPENAPI_CATALOG_JSON`** (inline), not a catalog file path.
- Build with enough TCSes (`SGX_THREADS`, default **16**). The edge uses a bounded accept pool (`OPENAPI_ACCEPT_WORKERS`, default **8** on SGX) via `Builder::spawn` — never unbounded `thread::spawn` (that panics when TCSes are exhausted).
- Default heap **32 MiB** fits ~92 MiB EPC on lab boxes without a PRMRR menu.

## 3. Configure runtime env

| Variable | Required | Notes |
|----------|----------|-------|
| `OPENAPI_MRENCLAVE` | yes | Must match signed enclave |
| `OPENAPI_UPSTREAM_BASE_URL` | yes | **`http://IP:port`** only (no HTTPS; no DNS resolution in enclave) |
| `OPENAPI_CATALOG_PATH` | yes | L0 signed key catalog |
| `OPENAPI_CATALOG_VERIFY_KEY_HEX` | yes | Ed25519 catalog verify key |
| `OPENAPI_USAGE_SIGN_SEED_HEX` | yes | Ed25519 usage signing seed |
| `OPENAPI_LISTEN_ADDR` | no | default `0.0.0.0:8443` |
| `OPENAPI_TLS_CERT_PATH` | prod | Server cert PEM (public) |
| `OPENAPI_TLS_SEALED_KEY_PATH` | prod | MRENCLAVE-bound sealed key JSON |
| `OPENAPI_TLS_KEY_PATH` | dev | Plaintext key (**dev only**) |
| `OPENAPI_PROFILE` | prod | Set to **`prod`** on production units |
| `OPENAPI_SEAL_ROOT_HEX` | dev | Dev HKDF input only — **forbidden in prod** (EGETKEY-derived in enclave) |

Sealing: [SECURITY.md](../../SECURITY.md).

### Seal TLS key to MRENCLAVE

After you know `OPENAPI_MRENCLAVE`:

```bash
export OPENAPI_MRENCLAVE=...
./scripts/seal-tls-key-sgx.sh tls-key.pem tls-key.sealed.json
export OPENAPI_TLS_CERT_PATH=cert.pem
export OPENAPI_TLS_SEALED_KEY_PATH=tls-key.sealed.json
```

### ACME / Let's Encrypt (not implemented for EDP yet)

CVM uses in-guest **`openapi-acme`** (instant-acme). For SGX, **do not** run host certbot and import PEM into the enclave.

Documented options (TeeChat sealing threat model §10): sync Rust ACME in-enclave, or CSR-split (keygen in EPC, host ACME sees CSR only). Production CVM path does not require Tokio-inside-EPC.

## 4. Run enclave

```bash
./deploy/sgx/run-enclave.sh
```

One-shot dev (build + dev catalog + run):

```bash
./scripts/dev-run-sgx.sh
```

Smoke tests:

```bash
curl -sS http://127.0.0.1:18443/healthz
curl -sS -H "Authorization: Bearer $OPENAPI_DEV_API_KEY" http://127.0.0.1:18443/v1/models
curl -sS -X POST http://127.0.0.1:18443/v1/attestation/challenge \
  -H 'Content-Type: application/json' -d '{"nonce_b64":"AAAAAAAAAAAAAAAAAAAAAA"}'
```

Inside the enclave, `/v1/attestation/challenge` returns a DCAP ECDSA quote (`quote_format: sgx_dcap_ecdsa`) when:

1. PCCS is up (`./deploy/sgx/setup-pccs.sh` with `INTEL_PCS_API_KEY`)
2. Host helper is running: `./deploy/sgx/run-dcap-helper.sh` (default `127.0.0.1:18500`)
3. Enclave is launched via `run-enclave.sh` / `dev-run-sgx.sh` (passes `OPENAPI_DCAP_HELPER_URL`)

## 5. EPC / sizing guardrails

- Default heap `0x2000000` (32 MiB), stack `0x200000` (2 MiB) — tune via `SGX_HEAP_SIZE` / `SGX_STACK_SIZE` in `build-enclave.sh`.
- Keep concurrent connections modest (design: 32–128 streams) to avoid EPC paging.
- Upstream must be reachable by **IP** from the enclave network usercalls.

## 6. Workspace layout (SGX)

```
bins/openapi-enclave          # EDP binary (fortanix target)
bins/seal-tls-key-sgx         # Seal TLS key to MRENCLAVE
crates/openapi-platform-sgx   # env, attest, tcp upstream, tls, run
crates/openapi-edge           # shared HTTP server loop
deploy/sgx/                   # build/run/preflight scripts
```

## 7. Troubleshooting

| Symptom | Check |
|---------|--------|
| `sgx-detect` fails | BIOS SGX, driver, EPC enabled |
| `ftxsgx-runner` ENOENT | `cargo install fortanix-sgx-tools` |
| Seal/unseal fails | `OPENAPI_MRENCLAVE` matches inspect output |
| Upstream connect fail | Use `http://127.0.0.1:PORT`, not hostname |
| TLS fails in enclave | Use sealed key; ensure cert PEM readable at launch |
