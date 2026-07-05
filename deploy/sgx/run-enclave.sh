#!/usr/bin/env bash
# Run a signed openapi enclave on SGX hardware (Fortanix ftxsgx-runner).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

TARGET="x86_64-fortanix-unknown-sgx"
PROFILE="${SGX_PROFILE:-release}"
SIGNED="${OPENAPI_SGX_ENCLAVE:-${ROOT}/target/${TARGET}/${PROFILE}/openapi-enclave.sgxs.signed}"

if [[ ! -f "${SIGNED}" ]]; then
  echo "Signed enclave not found: ${SIGNED}" >&2
  echo "Run: ./deploy/sgx/build-enclave.sh" >&2
  exit 1
fi

: "${OPENAPI_MRENCLAVE:?Set OPENAPI_MRENCLAVE from sgxs-tools inspect output}"
: "${OPENAPI_UPSTREAM_BASE_URL:?Set OPENAPI_UPSTREAM_BASE_URL (http://IP:port — no DNS)}"
: "${OPENAPI_CATALOG_PATH:?Set OPENAPI_CATALOG_PATH}"
: "${OPENAPI_CATALOG_VERIFY_KEY_HEX:?Set OPENAPI_CATALOG_VERIFY_KEY_HEX}"
: "${OPENAPI_USAGE_SIGN_SEED_HEX:?Set OPENAPI_USAGE_SIGN_SEED_HEX}"

export OPENAPI_LISTEN_ADDR="${OPENAPI_LISTEN_ADDR:-0.0.0.0:8443}"
export RUST_LOG="${RUST_LOG:-info}"

echo "Running enclave ${SIGNED}"
echo "Listen: ${OPENAPI_LISTEN_ADDR}  MRENCLAVE: ${OPENAPI_MRENCLAVE}"

exec ftxsgx-runner "${SIGNED}"
