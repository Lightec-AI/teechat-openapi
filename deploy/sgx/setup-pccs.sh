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
set -euo pipefail

: "${INTEL_PCS_API_KEY:?Set INTEL_PCS_API_KEY to your Intel PCS subscription key}"

USER_TOKEN="${PCCS_USER_TOKEN:-$(openssl rand -hex 16)}"
ADMIN_TOKEN="${PCCS_ADMIN_TOKEN:-$(openssl rand -hex 16)}"
HTTPS_PORT="${PCCS_HTTPS_PORT:-8081}"

echo "=== install Node.js (if needed) + sgx-dcap-pccs ==="
if ! command -v node >/dev/null 2>&1; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
  sudo apt-get install -y nodejs
fi

sudo apt-get update
# Noninteractive install: package postinst is interactive; we configure afterwards.
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y sgx-dcap-pccs sgx-pck-id-retrieval-tool || \
  sudo apt-get install -y sgx-dcap-pccs sgx-pck-id-retrieval-tool

CONFIG="/opt/intel/sgx-dcap-pccs/config/default.json"
if [[ ! -f "${CONFIG}" ]]; then
  echo "PCCS config missing at ${CONFIG} after install" >&2
  exit 1
fi

echo "=== write PCCS config ==="
# Hash tokens the way PCCS expects (sha512).
user_hash="$(printf '%s' "${USER_TOKEN}" | sha512sum | awk '{print $1}')"
admin_hash="$(printf '%s' "${ADMIN_TOKEN}" | sha512sum | awk '{print $1}')"

sudo python3 - "${CONFIG}" "${INTEL_PCS_API_KEY}" "${user_hash}" "${admin_hash}" "${HTTPS_PORT}" <<'PY'
import json, sys
path, api_key, user_hash, admin_hash, port = sys.argv[1:6]
with open(path) as f:
    cfg = json.load(f)
cfg["HTTPS_PORT"] = int(port)
cfg["hosts"] = "127.0.0.1"
cfg["uri"] = "https://api.trustedservices.intel.com/sgx/certification/v4/"
cfg["ApiKey"] = api_key
cfg["UserTokenHash"] = user_hash
cfg["AdminTokenHash"] = admin_hash
cfg["CachingFillMode"] = "LAZY"
cfg.setdefault("LogLevel", "info")
with open(path, "w") as f:
    json.dump(cfg, f, indent=4)
    f.write("\n")
print("wrote", path)
PY

QCNL="/etc/sgx_default_qcnl.conf"
echo "=== ensure QCNL points at local PCCS ==="
if [[ -f "${QCNL}" ]]; then
  sudo python3 - "${QCNL}" "${HTTPS_PORT}" <<'PY'
import json, sys, re
path, port = sys.argv[1:3]
text = open(path).read()
# File may be JSON-with-comments; strip // comments roughly then parse.
stripped = re.sub(r"//.*?$", "", text, flags=re.M)
cfg = json.loads(stripped)
cfg["pccs_url"] = f"https://localhost:{port}/sgx/certification/v4/"
cfg["use_secure_cert"] = False
# Write clean JSON (Intel QCNL accepts JSON).
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
