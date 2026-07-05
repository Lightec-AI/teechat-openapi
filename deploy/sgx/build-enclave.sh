#!/usr/bin/env bash
# Build and sign openapi-enclave for Fortanix EDP on SGX hardware.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

HEAP_SIZE="${SGX_HEAP_SIZE:-0x2000000}"
STACK_SIZE="${SGX_STACK_SIZE:-0x200000}"
KEY="${SGX_ENCLAVE_KEY:-${ROOT}/deploy/sgx/enclave-key.pem}"

TARGET="x86_64-fortanix-unknown-sgx"
PROFILE="${SGX_PROFILE:-release}"
OUT_DIR="${ROOT}/target/${TARGET}/${PROFILE}"
ELF="${OUT_DIR}/openapi-enclave"
SGXS="${OUT_DIR}/openapi-enclave.sgxs"
SIGNED="${OUT_DIR}/openapi-enclave.sgxs.signed"

echo "=== preflight ==="
"${ROOT}/deploy/sgx/sgx-preflight.sh"

echo "=== rust target ==="
rustup target add "${TARGET}"

echo "=== build enclave ELF ==="
cargo build --"${PROFILE}" --target "${TARGET}" -p openapi-enclave

if [[ ! -f "${KEY}" ]]; then
  echo "Generating dev enclave signing key at ${KEY}"
  mkdir -p "$(dirname "${KEY}")"
  openssl genrsa -3 3072 > "${KEY}"
fi

echo "=== ELF -> SGXS ==="
ftxsgx-elf2sgxs "${ELF}" \
  --heap-size "${HEAP_SIZE}" \
  --stack-size "${STACK_SIZE}" \
  --output "${SGXS}"

echo "=== sign SGXS ==="
sgxs-sign --key "${KEY}" --output "${SIGNED}" "${SGXS}"

echo "=== MRENCLAVE / metadata ==="
sgxs-tools inspect "${SIGNED}" | tee "${ROOT}/deploy/sgx/last-build-inspect.txt"

echo ""
echo "Signed enclave: ${SIGNED}"
echo "Export for runtime:"
echo "  export OPENAPI_SGX_ENCLAVE=${SIGNED}"
echo "  # Set OPENAPI_MRENCLAVE from inspect output above"
