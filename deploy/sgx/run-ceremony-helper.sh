#!/usr/bin/env bash
# Start host-side ACME HTTP-01 + artifact helper for Fortanix EDP enclaves.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

LISTEN="${OPENAPI_CEREMONY_HELPER_LISTEN:-127.0.0.1:18501}"
WEBROOT="${OPENAPI_ACME_WEBROOT:-/var/www/acme}"
ARTIFACT_DIR="${OPENAPI_ARTIFACT_DIR:-/var/lib/teechat-openapi/sgx}"
PROFILE="${CEREMONY_HELPER_PROFILE:-release}"
BIN="${ROOT}/target/${PROFILE}/openapi-ceremony-helper"

if [[ ! -x "${BIN}" ]]; then
  echo "Building openapi-ceremony-helper (${PROFILE})…"
  cargo build --"${PROFILE}" -p openapi-ceremony-helper
fi

mkdir -p "${WEBROOT}/.well-known/acme-challenge" "${ARTIFACT_DIR}"

export OPENAPI_CEREMONY_HELPER_LISTEN="${LISTEN}"
export OPENAPI_ACME_WEBROOT="${WEBROOT}"
export OPENAPI_ARTIFACT_DIR="${ARTIFACT_DIR}"
export RUST_LOG="${RUST_LOG:-info}"

echo "Starting ceremony helper on ${LISTEN}"
echo "  webroot:      ${WEBROOT}"
echo "  artifact_dir: ${ARTIFACT_DIR}"
echo "Ensure host nginx (or equivalent) serves ${WEBROOT}/.well-known/acme-challenge publicly."
exec "${BIN}"
