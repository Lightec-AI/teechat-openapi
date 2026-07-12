#!/usr/bin/env bash
# Start host-side AESM/DCAP helper used by Fortanix EDP enclaves for ECDSA quotes.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

LISTEN="${OPENAPI_DCAP_HELPER_LISTEN:-127.0.0.1:18500}"
PROFILE="${DCAP_HELPER_PROFILE:-release}"
BIN="${ROOT}/target/${PROFILE}/openapi-dcap-helper"

if [[ ! -x "${BIN}" ]]; then
  echo "Building openapi-dcap-helper (${PROFILE})…"
  cargo build --"${PROFILE}" -p openapi-dcap-helper
fi

export OPENAPI_DCAP_HELPER_LISTEN="${LISTEN}"
export RUST_LOG="${RUST_LOG:-info}"

echo "Starting DCAP helper on ${LISTEN}"
echo "Preflight: aesmd must be up; PCCS must answer https://localhost:8081 (see setup-pccs.sh)"
exec "${BIN}"
