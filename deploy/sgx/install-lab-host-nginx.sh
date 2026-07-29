#!/usr/bin/env bash
# sgx-lab host nginx: ACME webroot (:8088) + HTTP→HTTPS gateway upstream (:18080).
#
# ACME: gateway-host proxies lab.openapi.teechat.ai:80 → 10.202.0.2:8088
# Upstream: enclave OPENAPI_UPSTREAM_BASE_URL=http://127.0.0.1:18080
#
# Usage (on sgx-lab as root):
#   sudo bash deploy/sgx/install-lab-host-nginx.sh [--webroot DIR]
set -euo pipefail

WEBROOT="${OPENAPI_ACME_WEBROOT:-/var/www/acme}"
ACME_PORT="${OPENAPI_SGX_LAB_ACME_PORT:-8088}"
UPSTREAM_PORT="${OPENAPI_SGX_LAB_UPSTREAM_PROXY_PORT:-18080}"
GATEWAY_HOST="${OPENAPI_GATEWAY_UPSTREAM_HOST:-gateway.teechat.ai}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --webroot) WEBROOT="${2:?}"; shift 2 ;;
    --acme-port) ACME_PORT="${2:?}"; shift 2 ;;
    --upstream-port) UPSTREAM_PORT="${2:?}"; shift 2 ;;
    -h|--help) sed -n '1,14p' "$0"; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
command -v nginx >/dev/null || {
  echo "!! nginx not installed (apt-get install -y nginx)" >&2
  exit 1
}

mkdir -p "${WEBROOT}/.well-known/acme-challenge"
# Ceremony helper runs as the lab user; keep webroot writable.
if id weiji >/dev/null 2>&1; then
  chown -R weiji:weiji "${WEBROOT}"
fi
chmod -R a+rX "${WEBROOT}"

SITE="/etc/nginx/sites-available/teechat-openapi-sgx-lab.conf"
cat >"$SITE" <<EOF
# Managed by deploy/sgx/install-lab-host-nginx.sh — ACME HTTP-01 + gateway upstream proxy.

server {
  listen ${ACME_PORT};
  listen [::]:${ACME_PORT};
  server_name _;
  root ${WEBROOT};

  location /.well-known/acme-challenge/ {
    default_type text/plain;
    try_files \$uri =404;
  }

  location / {
    return 404;
  }
}

server {
  listen 127.0.0.1:${UPSTREAM_PORT};
  server_name _;

  location / {
    proxy_pass https://${GATEWAY_HOST};
    proxy_http_version 1.1;
    proxy_ssl_server_name on;
    proxy_ssl_name ${GATEWAY_HOST};
    proxy_ssl_protocols TLSv1.2 TLSv1.3;
    proxy_set_header Host ${GATEWAY_HOST};
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_read_timeout 600s;
    proxy_send_timeout 600s;
    client_max_body_size 32m;
  }
}
EOF

ln -sf "$SITE" /etc/nginx/sites-enabled/teechat-openapi-sgx-lab.conf
# Avoid default :80 colliding with unrelated local use; keep default disabled if present.
rm -f /etc/nginx/sites-enabled/default

nginx -t
systemctl enable --now nginx
systemctl reload nginx

echo "OK: ACME webroot ${WEBROOT} on 0.0.0.0:${ACME_PORT}"
echo "OK: gateway upstream proxy http://127.0.0.1:${UPSTREAM_PORT} → https://${GATEWAY_HOST}"
echo "Probe: echo ok | tee ${WEBROOT}/.well-known/acme-challenge/probe"
echo "       curl -fsS http://127.0.0.1:${ACME_PORT}/.well-known/acme-challenge/probe"
