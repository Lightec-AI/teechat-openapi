#!/usr/bin/env bash
# Production TLS ceremony for prod-openapi — run ONLY inside the SNP guest.
#
# Flow:
#   1. certbot obtains/renews certificate (private key exists briefly under /etc/letsencrypt)
#   2. openapi-tls-ceremony seal-from-acme → sealed blob + public fullchain, shred privkey
#   3. systemctl restart teechat-openapi
#
# Requires: OPENAPI_PROFILE=prod, /etc/teechat/openapi.env with attested OPENAPI_LAUNCH_DIGEST
# See: docs/ops/openapi-snp-staging.md §4.1 · deploy/cvm/README.md
set -euo pipefail

ENV_FILE="${OPENAPI_ENV_FILE:-/etc/teechat/openapi.env}"
CERT_NAME="${OPENAPI_ACME_CERT_NAME:-openapi.teechat.ai}"
WEBROOT="${OPENAPI_ACME_WEBROOT:-/var/www/certbot}"
LE_ROOT="${OPENAPI_LETSENCRYPT_ROOT:-/etc/letsencrypt}"
CEREMONY_BIN="${OPENAPI_TLS_CEREMONY_BIN:-/usr/local/bin/openapi-tls-ceremony}"

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
export OPENAPI_LETSENCRYPT_ROOT="$LE_ROOT"

if [[ "$OPENAPI_PROFILE" != "prod" && "$OPENAPI_PROFILE" != "production" ]]; then
  echo "!! OPENAPI_PROFILE must be prod (got: $OPENAPI_PROFILE)" >&2
  exit 1
fi

if [[ -n "${OPENAPI_TLS_KEY_PATH:-}" ]]; then
  echo "!! Unset OPENAPI_TLS_KEY_PATH before ceremony" >&2
  exit 1
fi

command -v certbot >/dev/null || { echo "!! apt-get install -y certbot" >&2; exit 1; }
command -v "$CEREMONY_BIN" >/dev/null || { echo "!! install openapi-tls-ceremony to $CEREMONY_BIN" >&2; exit 1; }

mkdir -p "$WEBROOT"

if [[ "$MODE" == "issue" ]]; then
  certbot certonly --non-interactive --agree-tos --keep-until-expiring \
    --webroot -w "$WEBROOT" -d "$CERT_NAME" \
    ${OPENAPI_ACME_EMAIL:+--email "$OPENAPI_ACME_EMAIL"} \
    ${OPENAPI_ACME_STAGING:+--staging}
else
  certbot renew --non-interactive --webroot -w "$WEBROOT"
fi

"$CEREMONY_BIN" seal-from-acme --cert-name "$CERT_NAME" --letsencrypt-root "$LE_ROOT"

systemctl restart teechat-openapi.service
systemctl --no-pager status teechat-openapi.service

echo "OK: TLS ceremony complete for $CERT_NAME"
