#!/usr/bin/env bash
# Option A SGX TLS ceremony — run on the SGX host (sgx-lab).
#
# Flow:
#   1. Ensure openapi-ceremony-helper is up (DNS + ACME webroot + artifacts)
#   2. Run openapi-enclave with OPENAPI_MODE=acme-issue|acme-renew
#      (ACME HTTP-01 + EGETKEY seal inside the same MRENCLAVE binary)
#   3. Helper stores sealed-key.json + tls.crt (never a private key PEM)
#
# Usage:
#   ./deploy/sgx/issue-and-seal-tls.sh issue|renew \
#     [--domain NAME] [--email ADDR] [--staging] [--helper-url URL]
#
# Lab (staging LE):  OPENAPI_PROFILE=dev OPENAPI_ACME_STAGING=1
# Prod (prod LE):    OPENAPI_PROFILE=prod  (no staging, no OPENAPI_SEAL_ROOT_HEX)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

TARGET="x86_64-fortanix-unknown-sgx"
PROFILE="${SGX_PROFILE:-release}"
SIGNED="${OPENAPI_SGX_ENCLAVE:-${ROOT}/target/${TARGET}/${PROFILE}/openapi-enclave.sgxs}"
HELPER_URL="${OPENAPI_CEREMONY_HELPER_URL:-http://127.0.0.1:18501}"
HELPER_LISTEN="${OPENAPI_CEREMONY_HELPER_LISTEN:-127.0.0.1:18501}"

usage() {
  sed -n '2,16p' "$0"
  exit 2
}

MODE="${1:-}"
case "$MODE" in
  issue|renew) shift ;;
  -h|--help) usage ;;
  *) echo "Usage: $0 {issue|renew} [options]" >&2; usage ;;
esac

DOMAIN="${OPENAPI_ACME_DOMAIN:-${OPENAPI_ACME_CERT_NAME:-}}"
EMAIL="${OPENAPI_ACME_EMAIL:-}"
STAGING="${OPENAPI_ACME_STAGING:-}"
EDGE_PROFILE="${OPENAPI_PROFILE:-dev}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="${2:?}"; shift 2 ;;
    --email) EMAIL="${2:?}"; shift 2 ;;
    --staging) STAGING=1; shift ;;
    --helper-url) HELPER_URL="${2:?}"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown arg: $1" >&2; usage ;;
  esac
done

[[ -n "$DOMAIN" ]] || { echo "!! --domain / OPENAPI_ACME_DOMAIN required" >&2; exit 1; }
[[ -f "${SIGNED}" ]] || {
  echo "!! SGXS missing: ${SIGNED}" >&2
  echo "   Run: ./deploy/sgx/build-enclave.sh" >&2
  exit 1
}
: "${OPENAPI_MRENCLAVE:?Set OPENAPI_MRENCLAVE from sgxs-info / last-build-inspect.txt}"

if [[ -n "$STAGING" && ( "$STAGING" == "1" || "$STAGING" == "true" ) ]]; then
  if [[ "$EDGE_PROFILE" == "prod" || "$EDGE_PROFILE" == "production" ]]; then
    echo "!! staging LE forbidden under OPENAPI_PROFILE=prod" >&2
    exit 1
  fi
else
  if [[ "$EDGE_PROFILE" != "prod" && "$EDGE_PROFILE" != "production" ]]; then
    echo "!! production LE requires OPENAPI_PROFILE=prod (lab: pass --staging with OPENAPI_PROFILE=dev)" >&2
    exit 1
  fi
fi

if [[ "$EDGE_PROFILE" == "prod" || "$EDGE_PROFILE" == "production" ]]; then
  if [[ -n "${OPENAPI_TLS_KEY_PATH:-}" ]]; then
    echo "!! Unset OPENAPI_TLS_KEY_PATH before prod ceremony" >&2
    exit 1
  fi
  if [[ -n "${OPENAPI_SEAL_ROOT_HEX:-}" ]]; then
    echo "!! Unset OPENAPI_SEAL_ROOT_HEX before prod ceremony" >&2
    exit 1
  fi
fi

# Start / check ceremony helper
if ! curl -fsS "${HELPER_URL}/healthz" >/dev/null 2>&1; then
  echo ">> ceremony helper not healthy at ${HELPER_URL}; starting…"
  # shellcheck disable=SC2091
  OPENAPI_CEREMONY_HELPER_LISTEN="${HELPER_LISTEN}" \
    OPENAPI_ACME_WEBROOT="${OPENAPI_ACME_WEBROOT:-/var/www/acme}" \
    OPENAPI_ARTIFACT_DIR="${OPENAPI_ARTIFACT_DIR:-/var/lib/teechat-openapi/sgx}" \
    nohup ./deploy/sgx/run-ceremony-helper.sh >"${TMPDIR:-/tmp}/openapi-ceremony-helper.log" 2>&1 &
  for _ in $(seq 1 30); do
    if curl -fsS "${HELPER_URL}/healthz" >/dev/null 2>&1; then
      break
    fi
    sleep 0.2
  done
  curl -fsS "${HELPER_URL}/healthz" >/dev/null || {
    echo "!! ceremony helper failed to start; see ${TMPDIR:-/tmp}/openapi-ceremony-helper.log" >&2
    exit 1
  }
fi

ACME_MODE="acme-${MODE}"
# Slot-prefixed artifacts (ceremony|blue|green). Default ceremony for mint path.
ARTIFACT_SLOT="${OPENAPI_ARTIFACT_SLOT:-ceremony}"
TLS_KEY_POLICY="${OPENAPI_TLS_KEY_POLICY:-key_ceremony}"
mkdir -p "${OPENAPI_ARTIFACT_DIR:-/var/lib/teechat-openapi/sgx}/${ARTIFACT_SLOT}"

ARGS=(
  "OPENAPI_MODE=${ACME_MODE}"
  "OPENAPI_MRENCLAVE=${OPENAPI_MRENCLAVE}"
  "OPENAPI_PROFILE=${EDGE_PROFILE}"
  "OPENAPI_ACME_DOMAIN=${DOMAIN}"
  "OPENAPI_CEREMONY_HELPER_URL=${HELPER_URL}"
  "OPENAPI_ARTIFACT_SLOT=${ARTIFACT_SLOT}"
  "OPENAPI_TLS_KEY_POLICY=${TLS_KEY_POLICY}"
  "RUST_LOG=${RUST_LOG:-info}"
)
[[ -n "$EMAIL" ]] && ARGS+=("OPENAPI_ACME_EMAIL=${EMAIL}")
if [[ -n "$STAGING" && ( "$STAGING" == "1" || "$STAGING" == "true" ) ]]; then
  ARGS+=("OPENAPI_ACME_STAGING=1")
fi

echo ">> Running enclave ACME ceremony (${ACME_MODE}) for ${DOMAIN}"
echo "   enclave: ${SIGNED}"
echo "   helper:  ${HELPER_URL}"
echo "   profile: ${EDGE_PROFILE}"
echo "   slot:    ${ARTIFACT_SLOT} policy=${TLS_KEY_POLICY}"

ftxsgx-runner --signature coresident "${SIGNED}" "${ARGS[@]}"

ARTIFACT_DIR="${OPENAPI_ARTIFACT_DIR:-/var/lib/teechat-openapi/sgx}"
SLOT_DIR="${ARTIFACT_DIR}/${ARTIFACT_SLOT}"
echo ""
echo "OK: ACME ${MODE} complete for ${DOMAIN}"
echo "Artifacts (host):"
echo "  ${SLOT_DIR}/sealed-key.json   # EGETKEY-sealed; never a PEM"
echo "  ${SLOT_DIR}/tls.crt           # public fullchain"
echo ""
echo "Next steps:"
echo "  1. Keep ./deploy/sgx/run-ceremony-helper.sh running (serves artifacts to enclave)."
echo "  2. Ensure nginx serves \${OPENAPI_ACME_WEBROOT}/.well-known/acme-challenge for renewals."
echo "  3. Start ceremony export (seal-sync listen), then sync blue:"
echo "       # TeaChat repo:"
echo "       bash scripts/ops/run-sgx-slot-enclave.sh --slot ceremony"
echo "       bash scripts/ops/sgx-openapi-seal-sync.sh --to blue --from ceremony"
echo "       bash scripts/ops/sgx-openapi-park-ceremony.sh --shred-sealed"
echo "  4. Lab trust: update config/openapi-sgx-lab/trust.json (SPKI + MRENCLAVE)."
