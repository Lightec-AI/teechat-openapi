#!/usr/bin/env bash
# Verify openapi edge accepts TLS 1.3 only (rejects TLS 1.2).
#
# Usage:
#   bash scripts/verify-tls13-only.sh
#   OPENAPI_TLS_VERIFY_HOST=openapi.teechat.ai OPENAPI_TLS_VERIFY_PORT=443 \
#     bash scripts/verify-tls13-only.sh
#
# Requires: openssl on PATH.
set -euo pipefail

HOST="${OPENAPI_TLS_VERIFY_HOST:-127.0.0.1}"
PORT="${OPENAPI_TLS_VERIFY_PORT:-8443}"

log() { printf '[verify-tls13] %s\n' "$*"; }
fail() { log "FAIL: $*"; exit 1; }

command -v openssl >/dev/null || fail "openssl not found"

log "host=${HOST} port=${PORT}"

tls13_out="$(echo | openssl s_client -connect "${HOST}:${PORT}" -tls1_3 -servername "${HOST}" 2>/dev/null || true)"
echo "$tls13_out" | grep -q 'Protocol  *: TLSv1.3' || fail "TLS 1.3 handshake did not negotiate TLSv1.3"
log "OK TLS 1.3 handshake"

tls12_out="$(echo | openssl s_client -connect "${HOST}:${PORT}" -tls1_2 -servername "${HOST}" 2>&1 || true)"
if echo "$tls12_out" | grep -q 'Protocol  *: TLSv1.2'; then
  fail "TLS 1.2 still accepted"
fi
log "OK TLS 1.2 rejected"

log "complete — edge is TLS 1.3 only"
