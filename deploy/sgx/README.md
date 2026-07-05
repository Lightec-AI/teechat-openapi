# Fortanix EDP (optional)

Production SGX builds target `x86_64-fortanix-unknown-sgx`. CI for this target is not enabled by default.

```bash
rustup target add x86_64-fortanix-unknown-sgx
cargo build --release -p openapi-platform-sgx
```

Wire enclave attestation quote generation in `crates/openapi-platform-sgx` when deploying to E-2388G / E-2374G hosts with 512 MiB EPC.

See TeaChat internal doc `docs/design/teechat-openapi.md` for hardware guidance.
