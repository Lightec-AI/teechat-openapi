#!/usr/bin/env bash
# Verify Intel SGX + Fortanix EDP prerequisites on the host.
set -euo pipefail

echo "=== CPU / device ==="
if [[ -e /dev/sgx_enclave ]] || [[ -e /dev/isgx ]]; then
  echo "SGX device node: ok"
else
  echo "WARN: no /dev/sgx_enclave or /dev/isgx — enable SGX in BIOS and load driver (aesm)" >&2
fi

if command -v sgx-detect >/dev/null 2>&1; then
  sgx-detect || true
else
  echo "Install Fortanix tools: cargo install fortanix-sgx-tools sgxs-tools" >&2
fi

echo "=== Rust target ==="
rustup target list --installed | grep -q x86_64-fortanix-unknown-sgx \
  || echo "Run: rustup target add x86_64-fortanix-unknown-sgx"

echo "=== AESM ==="
if pgrep -x aesm_service >/dev/null 2>&1 || pgrep -x aesmd >/dev/null 2>&1; then
  echo "aesm: running"
else
  echo "WARN: aesm_service not running — needed for DCAP/launch" >&2
fi

echo "Preflight done."
