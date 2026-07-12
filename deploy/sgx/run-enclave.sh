#!/usr/bin/env bash
# Run a signed openapi enclave on SGX hardware (Fortanix ftxsgx-runner).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

TARGET="x86_64-fortanix-unknown-sgx"
PROFILE="${SGX_PROFILE:-release}"
SIGNED="${OPENAPI_SGX_ENCLAVE:-${ROOT}/target/${TARGET}/${PROFILE}/openapi-enclave.sgxs}"

if [[ ! -f "${SIGNED}" ]]; then
  echo "SGXS enclave not found: ${SIGNED}" >&2
  echo "Run: ./deploy/sgx/build-enclave.sh" >&2
  exit 1
fi

SIG_CORESIDENT="${SIGNED%.sgxs}.sig"
if [[ ! -f "${SIG_CORESIDENT}" ]]; then
  echo "Coresident signature missing: ${SIG_CORESIDENT}" >&2
  echo "Run: ./deploy/sgx/build-enclave.sh" >&2
  exit 1
fi

: "${OPENAPI_MRENCLAVE:?Set OPENAPI_MRENCLAVE from sgxs-info summary output}"
: "${OPENAPI_UPSTREAM_BASE_URL:?Set OPENAPI_UPSTREAM_BASE_URL (http://IP:port — no DNS)}"
: "${OPENAPI_CATALOG_JSON:?Set OPENAPI_CATALOG_JSON (inline catalog; EDP has no host fs)}"
: "${OPENAPI_CATALOG_VERIFY_KEY_HEX:?Set OPENAPI_CATALOG_VERIFY_KEY_HEX}"
: "${OPENAPI_USAGE_SIGN_SEED_HEX:?Set OPENAPI_USAGE_SIGN_SEED_HEX}"

export OPENAPI_LISTEN_ADDR="${OPENAPI_LISTEN_ADDR:-0.0.0.0:8443}"
export RUST_LOG="${RUST_LOG:-info}"

echo "Running enclave ${SIGNED} (sig ${SIG_CORESIDENT})"
echo "Listen: ${OPENAPI_LISTEN_ADDR}  MRENCLAVE: ${OPENAPI_MRENCLAVE}"

# Fortanix EDP: empty host env inside enclave — pass KEY=VALUE as enclave args.
# Catalog must be inline (`OPENAPI_CATALOG_JSON=...`); `std::fs` is unavailable.
ARGS=(
  "OPENAPI_MRENCLAVE=${OPENAPI_MRENCLAVE}"
  "OPENAPI_UPSTREAM_BASE_URL=${OPENAPI_UPSTREAM_BASE_URL}"
  "OPENAPI_CATALOG_JSON=${OPENAPI_CATALOG_JSON}"
  "OPENAPI_CATALOG_VERIFY_KEY_HEX=${OPENAPI_CATALOG_VERIFY_KEY_HEX}"
  "OPENAPI_USAGE_SIGN_SEED_HEX=${OPENAPI_USAGE_SIGN_SEED_HEX}"
  "OPENAPI_LISTEN_ADDR=${OPENAPI_LISTEN_ADDR}"
  "OPENAPI_BUILD_VERSION=${OPENAPI_BUILD_VERSION:-sgx}"
)
[[ -n "${OPENAPI_TLS_CERT_PATH:-}" ]] && ARGS+=("OPENAPI_TLS_CERT_PATH=${OPENAPI_TLS_CERT_PATH}")
[[ -n "${OPENAPI_DCAP_HELPER_URL:-}" ]] && ARGS+=("OPENAPI_DCAP_HELPER_URL=${OPENAPI_DCAP_HELPER_URL}")
[[ -n "${RUST_LOG:-}" ]] && ARGS+=("RUST_LOG=${RUST_LOG}")
# Challenge rate limits (0 = unlimited for bench). Fortanix does not inherit host env.
[[ -n "${OPENAPI_CHALLENGE_RPM:-}" ]] && ARGS+=("OPENAPI_CHALLENGE_RPM=${OPENAPI_CHALLENGE_RPM}")
[[ -n "${OPENAPI_CHALLENGE_MAX_INFLIGHT:-}" ]] && ARGS+=("OPENAPI_CHALLENGE_MAX_INFLIGHT=${OPENAPI_CHALLENGE_MAX_INFLIGHT}")
[[ -n "${OPENAPI_CHALLENGE_BENCH_TOKEN:-}" ]] && ARGS+=("OPENAPI_CHALLENGE_BENCH_TOKEN=${OPENAPI_CHALLENGE_BENCH_TOKEN}")

# Default DCAP helper for ECDSA quotes (host openapi-dcap-helper).
if [[ -z "${OPENAPI_DCAP_HELPER_URL:-}" ]]; then
  ARGS+=("OPENAPI_DCAP_HELPER_URL=http://127.0.0.1:18500")
fi

exec ftxsgx-runner --signature coresident "${SIGNED}" "${ARGS[@]}"
