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
| `OPENAPI_BUILD_VERSION` | lab/prod | Challenge `edge.build_version` (e.g. `0.10.3`). Default `sgx` is not a release id. |
| `OPENAPI_CODE_HASH` | lab/prod | 64-hex SHA-256 of the signed `.sgxs`. Unset → `sha256("unknown")` (retired placeholder). Must be passed as an enclave arg (EDP does not inherit host env). |
| `OPENAPI_UPSTREAM_BASE_URL` | yes | **`http://IP:port`** only (no HTTPS; no DNS resolution in enclave) |
| `OPENAPI_CATALOG_PATH` | yes | L0 signed key catalog |
| `OPENAPI_CATALOG_VERIFY_KEY_HEX` | yes | Ed25519 catalog verify key |
| `OPENAPI_USAGE_SIGN_SEED_HEX` | yes | Ed25519 usage signing seed |
| `OPENAPI_LISTEN_ADDR` | no | default `0.0.0.0:8443` |
| `OPENAPI_TLS_CERT_PATH` | lab FS | Host-path cert PEM (unit tests / non-EDP only) |
| `OPENAPI_TLS_SEALED_KEY_PATH` | lab FS | Host-path sealed JSON (unit tests / non-EDP only) |
| `OPENAPI_CEREMONY_HELPER_URL` | prod SGX | Fetch `tls.crt` + `sealed-key.json` over TCP (default helper `http://127.0.0.1:18501`) |
| `OPENAPI_TLS_KEY_PATH` | dev | Plaintext key (**dev only**; forbidden in prod) |
| `OPENAPI_PROFILE` | prod | Set to **`prod`** on production units |
| `OPENAPI_SEAL_ROOT_HEX` | dev | Dev HKDF input only — **forbidden in prod** (EGETKEY-derived in enclave) |
| `OPENAPI_DCAP_HELPER_URL` | attest | Host AESM quote helper (default `http://127.0.0.1:18500`) |
| `OPENAPI_GATEWAY_OPE_API_URL` | prod | F′ OPE API plane base URL — **`https://IP:port`** only (no DNS, no clear-text F′ dial). Unset ⇒ clear HTTP fallback in non-prod; **required in prod** (hard cutover). |
| `OPENAPI_UPSTREAM_CLEAR_HTTP` | no | Set `1` to bypass F′ entirely and use `OPENAPI_UPSTREAM_BASE_URL` (`http://IP:port`) instead. Break-glass only — **forbidden when `OPENAPI_PROFILE=prod`**. |

### F′ OPE dispatch (hard cutover) — `OPENAPI_GATEWAY_OPE_API_*`

Same wire contract and hard-cutover semantics as `openapi-platform-cvm`, dialed with a raw `TcpStream` + `rustls-rustcrypto` instead of `ureq` (`ureq`'s `aws-lc-rs`/`ring` backends hit `#UD` inside the Fortanix enclave). See `crates/openapi-platform-sgx/src/{gateway_ope_api,ope_upstream,ope_wrap,edge_upstream}.rs`.

| Variable | Required | Notes |
|----------|----------|-------|
| `OPENAPI_GATEWAY_OPE_API_URL` | prod | `https://IP:port` — literal IP (no DNS resolver in enclave); rejects `http://` |
| `OPENAPI_GATEWAY_OPE_API_TOKEN` | no | Bearer dispatch token (optional during mTLS-only harden) |
| `OPENAPI_GATEWAY_OPE_API_TLS_CLIENT_CERT_PEM` | mTLS | **Inline PEM only** (`-----BEGIN CERTIFICATE-----…`) — a filesystem path is rejected up front (`std::fs` unsupported on Fortanix EDP) |
| `OPENAPI_GATEWAY_OPE_API_TLS_CLIENT_KEY_PEM` | mTLS | **Inline PEM only**; must be set together with the client cert |
| `OPENAPI_GATEWAY_OPE_API_TLS_CA_PEM` | no | **Inline PEM only**; verifies the gateway server cert. Omit to use the bundled `webpki-roots` trust store |
| `OPENAPI_GATEWAY_OPE_API_TLS_INSECURE_SKIP_VERIFY` | no | Dev-only skip-verify — **forbidden when `OPENAPI_PROFILE=prod`** |
| `OPENAPI_GATEWAY_OPE_API_READ_TIMEOUT_SECS` | no | Default `300` (matches gateway `TEECHAT_OPE_UPSTREAM_TIMEOUT_MS`) |

Startup probes `GET /v1/ope/api/health` and logs the result; in prod, an unreachable/misconfigured F′ plane fails closed (`EdgeUpstream::from_env` returns `Err`) unless `OPENAPI_UPSTREAM_CLEAR_HTTP=1` is set (also forbidden in prod). In dev, a failed probe or unset URL falls back to `OPENAPI_UPSTREAM_BASE_URL` clear HTTP with a warning.

### CFG-001 — measured runtime policy (`policy_hash`)

`ftxsgx-runner` passes host-visible `OPENAPI_*=…` argv into an empty enclave env. **MRENCLAVE** binds code, not catalog/upstream/L0 knobs. The edge now hashes those knobs into challenge `policy_hash` via `EdgeRuntimePolicy` (same digest as CVM; not in `report_data` v1). Publish the expected hex on SGX trust / allowlist rows after lab env changes (auth mode, catalog verify key, upstream URL, L0 URLs, gateway OPE URL).

Sealing: [SECURITY.md](../../SECURITY.md).

### Seal TLS key to MRENCLAVE (lab import — not prod)

Host-side `seal-tls-key-sgx` is for **lab/CI** only (OPS-002). Production SGX uses **Option A** below so the private key is generated and sealed inside the enclave.

```bash
export OPENAPI_MRENCLAVE=...
./scripts/seal-tls-key-sgx.sh tls-key.pem tls-key.sealed.json
# Prefer ceremony helper artifacts on real EDP hardware (no std::fs).
```

### ACME / Let's Encrypt — Option A (in-enclave + host helper)

Fortanix EDP: **no `std::fs`**, DNS hangs, TCP to IP works. The TLS private key must be sealed with **EGETKEY** (`SgxSealer`) inside the **same** `openapi-enclave` binary that serves traffic (same `MRENCLAVE`). The host must **never** see a private key PEM.

**Crypto on EDP:** `ring` ECDSA / key-exchange hits `#UD` (`exception_vector: 6`) inside Fortanix enclaves on sgx-lab (92 MiB EPC). Option A ACME JOSE/CSR uses pure Rust **`p256`/`ecdsa`**, and both the ACME HTTPS client and edge TLS server use **`rustls-rustcrypto`** via `builder_with_provider` (not `rustls`+ring).

| Component | Role |
|-----------|------|
| `openapi-ceremony-helper` | Host loopback `:18501` — DNS, allowlisted ACME HTTPS relay (`/https-relay`), HTTP-01 webroot, artifact store |
| `openapi-enclave` + `OPENAPI_MODE=acme-issue\|acme-renew` | In-enclave `openapi-acme-sync` HTTP-01 + seal → PUT `sealed-key.json` + `tls.crt` |
| Host nginx | Serve `${OPENAPI_ACME_WEBROOT}/.well-known/acme-challenge/` publicly |

**Why `/https-relay`:** Direct `rustls-rustcrypto` HTTPS from the enclave to Let's Encrypt can reach the wire but return truncated/corrupt ACME JSON bodies on Fortanix EDP. Production Option A therefore keeps account key + leaf keygen/JOSE/CSR/seal inside EPC, and has the host helper perform the HTTPS client I/O to allowlisted `*.letsencrypt.org` / `*.zerossl.com` hosts (same trust boundary as DNS + webroot). The TLS leaf private key PEM never leaves the enclave.

**Lab (staging LE):**

```bash
./deploy/sgx/build-enclave.sh
export OPENAPI_MRENCLAVE=...   # from deploy/sgx/last-build-inspect.txt
export OPENAPI_PROFILE=dev
export OPENAPI_ACME_WEBROOT=/var/www/acme
export OPENAPI_ARTIFACT_DIR=/var/lib/teechat-openapi/sgx

# Terminal A — helper (keep running)
./deploy/sgx/run-ceremony-helper.sh

# Terminal B — issue (staging)
./deploy/sgx/issue-and-seal-tls.sh issue \
  --domain openapi-lab.example.com \
  --email ops@example.com \
  --staging

# Serve edge (helper still required for TLS bootstrap)
export OPENAPI_CEREMONY_HELPER_URL=http://127.0.0.1:18501
export OPENAPI_PROFILE=dev
# … catalog / upstream / MRENCLAVE …
./deploy/sgx/run-enclave.sh
```

**Prod (production LE):** `OPENAPI_PROFILE=prod`, omit `--staging`, unset `OPENAPI_TLS_KEY_PATH` / `OPENAPI_SEAL_ROOT_HEX`, then publish the serving SPKI on the TLS ceremony allowlist.

Renew: `./deploy/sgx/issue-and-seal-tls.sh renew --domain …` (same binary / MRENCLAVE).

**Stable leaf key:** `issue` generates and seals once; `renew` unseals `sealed-key.json`, CSRs with the same key, writes a new `tls.crt`, and re-seals. Serving SPKI must not change on renew (ceremony aborts if it would). Re-key = run `issue` again (then update lab trust pins).

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
bins/openapi-enclave            # EDP binary (edge + ACME ceremony modes)
bins/openapi-ceremony-helper    # Host DNS / HTTP-01 / artifact helper
bins/openapi-dcap-helper        # Host AESM ECDSA quote helper
bins/seal-tls-key-sgx           # Lab-only seal import (not prod)
crates/openapi-acme-sync        # Blocking ACME client (rustls/TcpStream)
crates/openapi-platform-sgx     # env, attest, ACME ceremony, tls, run
crates/openapi-edge             # shared HTTP server loop
deploy/sgx/                     # build/run/ceremony scripts
```

## 7. Troubleshooting

| Symptom | Check |
|---------|--------|
| `sgx-detect` fails | BIOS SGX, driver, EPC enabled |
| `ftxsgx-runner` ENOENT | `cargo install fortanix-sgx-tools` |
| Seal/unseal fails | `OPENAPI_MRENCLAVE` matches inspect output |
| Upstream connect fail | Use `http://127.0.0.1:PORT`, not hostname |
| F′ config error `must be inline PEM` | `OPENAPI_GATEWAY_OPE_API_TLS_*_PEM` was set to a filesystem path — use inline `-----BEGIN ...-----` PEM (no `std::fs` on EDP) |
| F′ config error `must be a literal IP address` | `OPENAPI_GATEWAY_OPE_API_URL` used a DNS name — enclave has no resolver; use `https://IP:port` |
| Boot fails `OPENAPI_GATEWAY_OPE_API_URL required in prod` | Hard OPE cutover: set the URL, or (non-prod only) `OPENAPI_UPSTREAM_CLEAR_HTTP=1` |
| TLS fails in enclave | Run ceremony helper; set `OPENAPI_CEREMONY_HELPER_URL`; artifacts `tls.crt` + `sealed-key.json` present |
| ACME DNS hang | Enclave must use helper `/dns` (never enclave libc DNS) |
| ACME JSON truncated / `expected value at line …` | EDP path must use helper `/https-relay` (not direct enclave HTTPS to LE) |
| ACME challenge 404 | Host nginx must map `/.well-known/acme-challenge/` → `OPENAPI_ACME_WEBROOT` |
