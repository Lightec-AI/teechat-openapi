#!/usr/bin/env bash
# Install + configure Intel PCCS on the SGX host (required for DCAP ECDSA quotes).
#
# Prerequisites:
#   - Intel PCS API subscription key from
#     https://api.portal.trustedservices.intel.com/provisioning-certification
#   - sudo
#
# Usage:
#   INTEL_PCS_API_KEY=... ./deploy/sgx/setup-pccs.sh
#   INTEL_PCS_API_KEY=... PCCS_USER_TOKEN=... PCCS_ADMIN_TOKEN=... ./deploy/sgx/setup-pccs.sh
#
# Note: `apt install sgx-dcap-pccs` only drops the service tree. Intel's interactive
# `install.sh` normally runs `npm install` + SSL keygen; this script does that
# non-interactively and writes config (Intel's default.json has // comments).
set -euo pipefail

: "${INTEL_PCS_API_KEY:?Set INTEL_PCS_API_KEY to your Intel PCS subscription key}"

USER_TOKEN="${PCCS_USER_TOKEN:-$(openssl rand -hex 16)}"
ADMIN_TOKEN="${PCCS_ADMIN_TOKEN:-$(openssl rand -hex 16)}"
HTTPS_PORT="${PCCS_HTTPS_PORT:-8081}"
PCCS_HOME="/opt/intel/sgx-dcap-pccs"
CONFIG="${PCCS_HOME}/config/default.json"

echo "=== install Node.js (if needed) + sgx-dcap-pccs ==="
if ! command -v node >/dev/null 2>&1; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
  sudo apt-get install -y nodejs
fi

sudo apt-get update
# Noninteractive install: package postinst is interactive; we configure afterwards.
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  cracklib-runtime sgx-dcap-pccs sgx-pck-id-retrieval-tool || \
  sudo apt-get install -y cracklib-runtime sgx-dcap-pccs sgx-pck-id-retrieval-tool

if [[ ! -f "${CONFIG}" ]]; then
  echo "PCCS config missing at ${CONFIG} after install" >&2
  exit 1
fi

echo "=== npm install PCCS dependencies ==="
# apt does not run Intel install.sh; without node_modules, pccs crash-loops with
# ERR_MODULE_NOT_FOUND (Cannot find package 'config').
# Always install as root then chown — a prior root npm can leave node_modules
# unwritable by user `pccs`, which causes EACCES on re-runs.
sudo bash -lc "cd '${PCCS_HOME}' && npm config set engine-strict true && npm install --omit=dev"
if id pccs >/dev/null 2>&1; then
  sudo chown -R pccs:pccs "${PCCS_HOME}"
fi

echo "=== ensure self-signed TLS material ==="
if [[ ! -f "${PCCS_HOME}/ssl_key/private.pem" || ! -f "${PCCS_HOME}/ssl_key/file.crt" ]]; then
  sudo mkdir -p "${PCCS_HOME}/ssl_key"
  sudo openssl genrsa -out "${PCCS_HOME}/ssl_key/private.pem" 2048
  sudo openssl req -new -key "${PCCS_HOME}/ssl_key/private.pem" \
    -out "${PCCS_HOME}/ssl_key/csr.pem" \
    -subj "/CN=PCCS Server (self-signed certificate)"
  sudo openssl x509 -req -days 3650 \
    -in "${PCCS_HOME}/ssl_key/csr.pem" \
    -signkey "${PCCS_HOME}/ssl_key/private.pem" \
    -out "${PCCS_HOME}/ssl_key/file.crt"
fi

echo "=== write PCCS config ==="
# Hash tokens the way PCCS expects (sha512 hex, no spaces/dashes).
user_hash="$(printf '%s' "${USER_TOKEN}" | sha512sum | tr -d '[:space:]-')"
admin_hash="$(printf '%s' "${ADMIN_TOKEN}" | sha512sum | tr -d '[:space:]-')"

# Do not parse Intel's default.json: it has // comments, and naive // stripping
# also destroys https:// URLs. Write a clean JSON config instead.
sudo python3 - "${CONFIG}" "${INTEL_PCS_API_KEY}" "${user_hash}" "${admin_hash}" "${HTTPS_PORT}" <<'PY'
import json, sys
path, api_key, user_hash, admin_hash, port = sys.argv[1:6]
cfg = {
    "HTTPS_PORT": int(port),
    "hosts": "127.0.0.1",
    "uri": "https://api.trustedservices.intel.com/sgx/certification/v4/",
    "ApiKey": api_key,
    "proxy": "",
    "RefreshSchedule": "0 0 1 * * *",
    "UserTokenHash": user_hash,
    "AdminTokenHash": admin_hash,
    "CachingFillMode": "LAZY",
    "OPENSSL_FIPS_MODE": False,
    "LogLevel": "info",
    "DB_CONFIG": "sqlite",
    "sqlite": {
        "options": {
            "dialect": "sqlite",
            "define": {"freezeTableName": True},
            "logging": False,
            "storage": "pckcache.db",
        }
    },
}
with open(path, "w") as f:
    json.dump(cfg, f, indent=4)
    f.write("\n")
print("wrote", path)
PY

# Service runs as user pccs.
if id pccs >/dev/null 2>&1; then
  sudo chown -R pccs:pccs "${PCCS_HOME}/config" "${PCCS_HOME}/ssl_key" \
    "${PCCS_HOME}/node_modules" 2>/dev/null || true
  sudo chown -R pccs:pccs "${PCCS_HOME}" 2>/dev/null || true
fi

QCNL="/etc/sgx_default_qcnl.conf"
echo "=== ensure QCNL points at local PCCS ==="
if [[ -f "${QCNL}" ]]; then
  sudo python3 - "${QCNL}" "${HTTPS_PORT}" <<'PY'
import json, re, sys

def strip_js_comments(text: str) -> str:
    """Strip // comments outside of strings (preserves https://)."""
    out = []
    for line in text.splitlines():
        in_str = False
        esc = False
        cut = len(line)
        i = 0
        while i < len(line):
            c = line[i]
            if esc:
                esc = False
            elif in_str:
                if c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            else:
                if c == '"':
                    in_str = True
                elif c == "/" and i + 1 < len(line) and line[i + 1] == "/":
                    cut = i
                    break
            i += 1
        out.append(line[:cut].rstrip())
    text = "\n".join(out)
    return re.sub(r",\s*([}\]])", r"\1", text)

path, port = sys.argv[1:3]
cfg = json.loads(strip_js_comments(open(path).read()))
cfg["pccs_url"] = f"https://localhost:{port}/sgx/certification/v4/"
cfg["use_secure_cert"] = False
open(path, "w").write(json.dumps(cfg, indent=2) + "\n")
print("updated", path)
PY
fi

echo "=== restart PCCS + AESM ==="
sudo systemctl enable --now pccs || sudo systemctl enable --now sgx-dcap-pccs || true
sudo systemctl restart pccs 2>/dev/null || sudo systemctl restart sgx-dcap-pccs 2>/dev/null || true
sudo systemctl restart aesmd

sleep 2
echo "=== smoke PCCS ==="
code="$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:${HTTPS_PORT}/sgx/certification/v4/rootcacrl" || true)"
echo "GET rootcacrl -> HTTP ${code} (expect 200)"
if [[ "${code}" != "200" ]]; then
  echo "PCCS not healthy yet. Check: journalctl -u pccs -n 50" >&2
  echo "User token (save): ${USER_TOKEN}" >&2
  echo "Admin token (save): ${ADMIN_TOKEN}" >&2
  exit 2
fi

echo
echo "PCCS OK on https://127.0.0.1:${HTTPS_PORT}"
echo "Save these tokens:"
echo "  PCCS_USER_TOKEN=${USER_TOKEN}"
echo "  PCCS_ADMIN_TOKEN=${ADMIN_TOKEN}"
echo
echo "Next: register this platform (one-time), then start the DCAP helper:"
echo "  sudo PCKIDRetrievalTool -f /tmp/pckid.csv || sudo /opt/intel/sgx-pck-id-retrieval-tool/PCKIDRetrievalTool"
echo "  # If using PCCS admin registration, see Intel DCAP PCCS README (CachingFillMode=LAZY often auto-fills on first quote)."
echo "  ./deploy/sgx/run-dcap-helper.sh"
echo "  ./scripts/dev-run-sgx.sh"
