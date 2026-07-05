#!/usr/bin/env bash
# Dev loop on SGX host: build enclave, print MRENCLAVE, run with dev catalog.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_DIR="${ROOT}/dev/sgx"
mkdir -p "${DEV_DIR}"

API_KEY="${OPENAPI_DEV_API_KEY:-sk-teechat-sgx-dev}"
UPSTREAM="${OPENAPI_UPSTREAM_BASE_URL:-http://127.0.0.1:8000}"

# Build + sign
"${ROOT}/deploy/sgx/build-enclave.sh"

INSPECT="${ROOT}/deploy/sgx/last-build-inspect.txt"
MRENCLAVE="$(grep -i 'mrenclave' "${INSPECT}" | head -1 | awk '{print $NF}' | tr -d '[:space:]')"
if [[ -z "${MRENCLAVE}" ]]; then
  echo "Could not parse MRENCLAVE from ${INSPECT}" >&2
  exit 1
fi

CATALOG_SEED="0101010101010101010101010101010101010101010101010101010101010101"
USAGE_SEED="0202020202020202020202020202020202020202020202020202020202020202"

CATALOG_VERIFY="$(python3 - "${DEV_DIR}/catalog.json" "${API_KEY}" "${CATALOG_SEED}" <<'PY'
import hashlib, json, sys
from pathlib import Path
catalog_path, api_key, catalog_seed = sys.argv[1:4]
try:
    from nacl.signing import SigningKey
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pynacl", "-q"])
    from nacl.signing import SigningKey
sk = SigningKey(bytes.fromhex(catalog_seed))
unsigned = {
    "catalog_version": 1,
    "issued_at_ms": 1,
    "keys": [{"key_id": "dev", "key_hash_hex": hashlib.sha256(api_key.encode()).hexdigest(), "revoked": False}],
}
payload = json.dumps(unsigned, separators=(",", ":")).encode()
catalog = {**unsigned, "signature_hex": sk.sign(payload).signature.hex()}
Path(catalog_path).write_text(json.dumps(catalog, indent=2) + "\n")
print(sk.verify_key.encode().hex())
PY
)"

export OPENAPI_MRENCLAVE="${MRENCLAVE}"
export OPENAPI_UPSTREAM_BASE_URL="${UPSTREAM}"
export OPENAPI_CATALOG_PATH="${DEV_DIR}/catalog.json"
export OPENAPI_CATALOG_VERIFY_KEY_HEX="${CATALOG_VERIFY}"
export OPENAPI_USAGE_SIGN_SEED_HEX="${USAGE_SEED}"
export OPENAPI_LISTEN_ADDR="${OPENAPI_LISTEN_ADDR:-127.0.0.1:18443}"
export OPENAPI_BUILD_VERSION="${OPENAPI_BUILD_VERSION:-sgx-dev}"
export RUST_LOG="${RUST_LOG:-info}"

echo "Dev API key: ${API_KEY}"
echo "MRENCLAVE: ${OPENAPI_MRENCLAVE}"
echo "After start: curl -sS -H 'Authorization: Bearer ${API_KEY}' http://${OPENAPI_LISTEN_ADDR}/v1/models"

exec "${ROOT}/deploy/sgx/run-enclave.sh"
