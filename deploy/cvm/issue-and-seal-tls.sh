#!/usr/bin/env bash
# Production TLS ceremony for prod-openapi — run ONLY inside the SNP guest.
#
# Flow:
#   1. openapi-acme (instant-acme) obtains/renews certificate via HTTP-01
#   2. openapi-tls-ceremony seal-from-acme → sealed blob + public fullchain, shred privkey
#   3. systemctl restart teechat-openapi
#
# Requires: OPENAPI_PROFILE=prod, /etc/teechat/openapi.env with attested OPENAPI_LAUNCH_DIGEST
# See: docs/ops/openapi-snp-staging.md §4.1 · deploy/cvm/README.md
set -euo pipefail

ENV_FILE="${OPENAPI_ENV_FILE:-/etc/teechat/openapi.env}"
CERT_NAME="${OPENAPI_ACME_CERT_NAME:-openapi.teechat.ai}"
WEBROOT="${OPENAPI_ACME_WEBROOT:-/var/www/acme}"
ACME_ROOT="${OPENAPI_ACME_ROOT:-/var/lib/teechat-openapi/acme}"
ACME_BIN="${OPENAPI_ACME_BIN:-/usr/local/bin/openapi-acme}"
CEREMONY_BIN="${OPENAPI_TLS_CEREMONY_BIN:-/usr/local/bin/openapi-tls-ceremony}"
# Skip renew when installed public cert is still valid for this many seconds (default 30d).
RENEW_SKEW_SECS="${OPENAPI_ACME_RENEW_SKEW_SECS:-2592000}"

usage() {
  sed -n '2,12p' "$0"
  exit 2
}

MODE="${1:-}"
case "$MODE" in
  issue|renew) ;;
  -h|--help) usage ;;
  *) echo "Usage: sudo $0 {issue|renew}" >&2; usage ;;
esac

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root inside prod-openapi guest." >&2; exit 1; }
[[ -f "$ENV_FILE" ]] || { echo "!! Missing $ENV_FILE" >&2; exit 1; }

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

export OPENAPI_PROFILE="${OPENAPI_PROFILE:-prod}"
export OPENAPI_ACME_CERT_NAME="$CERT_NAME"
export OPENAPI_ACME_WEBROOT="$WEBROOT"
export OPENAPI_ACME_ROOT="$ACME_ROOT"
# seal-from-acme still uses the historical env name for the ACME state tree.
export OPENAPI_LETSENCRYPT_ROOT="$ACME_ROOT"

if [[ "$OPENAPI_PROFILE" != "prod" && "$OPENAPI_PROFILE" != "production" ]]; then
  echo "!! OPENAPI_PROFILE must be prod (got: $OPENAPI_PROFILE)" >&2
  exit 1
fi

if [[ -n "${OPENAPI_TLS_KEY_PATH:-}" ]]; then
  echo "!! Unset OPENAPI_TLS_KEY_PATH before ceremony" >&2
  exit 1
fi

command -v "$ACME_BIN" >/dev/null || { echo "!! install openapi-acme to $ACME_BIN" >&2; exit 1; }
command -v "$CEREMONY_BIN" >/dev/null || { echo "!! install openapi-tls-ceremony to $CEREMONY_BIN" >&2; exit 1; }

mkdir -p "$WEBROOT" "$ACME_ROOT"

if [[ "$MODE" == "renew" ]]; then
  INSTALLED_CERT="${OPENAPI_TLS_CERT_PATH:-/etc/teechat/openapi-tls.crt}"
  if [[ -f "$INSTALLED_CERT" ]] && command -v openssl >/dev/null; then
    if openssl x509 -in "$INSTALLED_CERT" -checkend "$RENEW_SKEW_SECS" -noout 2>/dev/null; then
      echo "OK: $INSTALLED_CERT still valid >${RENEW_SKEW_SECS}s; skip renew"
      exit 0
    fi
  fi
fi

ACME_ARGS=( "$MODE" --domain "$CERT_NAME" --webroot "$WEBROOT" --acme-root "$ACME_ROOT" )
[[ -n "${OPENAPI_ACME_EMAIL:-}" ]] && ACME_ARGS+=( --email "$OPENAPI_ACME_EMAIL" )
[[ -n "${OPENAPI_ACME_STAGING:-}" ]] && ACME_ARGS+=( --staging )

"$ACME_BIN" "${ACME_ARGS[@]}"

"$CEREMONY_BIN" seal-from-acme --cert-name "$CERT_NAME" --letsencrypt-root "$ACME_ROOT"

systemctl restart teechat-openapi.service
systemctl --no-pager status teechat-openapi.service

echo "OK: TLS ceremony complete for $CERT_NAME"
