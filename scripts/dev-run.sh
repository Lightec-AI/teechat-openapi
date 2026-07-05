#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_DIR="${ROOT}/dev"
mkdir -p "${DEV_DIR}"

API_KEY="${OPENAPI_DEV_API_KEY:-sk-teechat-dev-local}"
UPSTREAM="${OPENAPI_UPSTREAM_BASE_URL:-http://127.0.0.1:8000}"
CATALOG_PATH="${DEV_DIR}/catalog.json"
CATALOG_SEED="0101010101010101010101010101010101010101010101010101010101010101"
USAGE_SEED="0202020202020202020202020202020202020202020202020202020202020202"

CATALOG_VERIFY="$(python3 - "${CATALOG_PATH}" "${API_KEY}" "${CATALOG_SEED}" <<'PY'
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
    "keys": [{
        "key_id": "dev",
        "key_hash_hex": hashlib.sha256(api_key.encode()).hexdigest(),
        "revoked": False,
    }],
}
payload = json.dumps(unsigned, separators=(",", ":")).encode()
catalog = {**unsigned, "signature_hex": sk.sign(payload).signature.hex()}
Path(catalog_path).write_text(json.dumps(catalog, indent=2) + "\n")
print(sk.verify_key.encode().hex())
PY
)"

export OPENAPI_LISTEN_ADDR="${OPENAPI_LISTEN_ADDR:-127.0.0.1:18443}"
export OPENAPI_UPSTREAM_BASE_URL="${UPSTREAM}"
export OPENAPI_CATALOG_PATH="${CATALOG_PATH}"
export OPENAPI_CATALOG_VERIFY_KEY_HEX="${CATALOG_VERIFY}"
export OPENAPI_USAGE_SIGN_SEED_HEX="${USAGE_SEED}"
export OPENAPI_BUILD_VERSION="${OPENAPI_BUILD_VERSION:-dev}"
export RUST_LOG="${RUST_LOG:-info}"

echo "Starting openapi on ${OPENAPI_LISTEN_ADDR} (no TLS)"
echo "Dev API key: ${API_KEY}"
echo "Example: curl -sS -H 'Authorization: Bearer ${API_KEY}' http://${OPENAPI_LISTEN_ADDR}/v1/models"

cd "${ROOT}"
cargo run -p openapi
