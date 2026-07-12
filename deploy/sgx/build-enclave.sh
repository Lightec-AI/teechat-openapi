#!/usr/bin/env bash
# Build and sign openapi-enclave for Fortanix EDP on SGX hardware.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

HEAP_SIZE="${SGX_HEAP_SIZE:-0x2000000}"
STACK_SIZE="${SGX_STACK_SIZE:-0x200000}"
# One TCS per concurrent connection thread (+ main). Default 1 panics on thread::spawn.
THREADS="${SGX_THREADS:-16}"
KEY="${SGX_ENCLAVE_KEY:-${ROOT}/deploy/sgx/enclave-key.pem}"

TARGET="x86_64-fortanix-unknown-sgx"
PROFILE="${SGX_PROFILE:-release}"
OUT_DIR="${ROOT}/target/${TARGET}/${PROFILE}"
ELF="${OUT_DIR}/openapi-enclave"
SGXS="${OUT_DIR}/openapi-enclave.sgxs"
# Coresident SIGSTRUCT next to the SGXS (ftxsgx-runner --signature coresident).
SIG="${OUT_DIR}/openapi-enclave.sig"

echo "=== preflight ==="
"${ROOT}/deploy/sgx/sgx-preflight.sh"

# Fortanix EDP needs nightly for #![feature(sgx_platform)] (sgx-isa / std).
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}"

echo "=== rust target ==="
rustup target add "${TARGET}" --toolchain "${RUSTUP_TOOLCHAIN}"

# ring SystemRandom needs a Fortanix cfg fix (see ensure-ring-fortanix-patch.sh).
"${ROOT}/deploy/sgx/ensure-ring-fortanix-patch.sh"

# Inject [patch.crates-io] only for this SGX build so CVM builds stay untouched.
RESTORE_CARGO_TOML=0
if ! grep -q 'deploy/sgx/vendor/ring' "${ROOT}/Cargo.toml"; then
  cat >> "${ROOT}/Cargo.toml" <<'EOF'

# --- begin sgx ring patch (build-enclave.sh) ---
[patch.crates-io]
ring = { path = "deploy/sgx/vendor/ring" }
# --- end sgx ring patch ---
EOF
  RESTORE_CARGO_TOML=1
fi

cleanup_cargo_toml() {
  if [[ "${RESTORE_CARGO_TOML}" -eq 1 ]]; then
    python3 - "${ROOT}/Cargo.toml" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
start = "\n# --- begin sgx ring patch (build-enclave.sh) ---\n"
end = "# --- end sgx ring patch ---\n"
i = text.find(start)
j = text.find(end)
if i != -1 and j != -1:
    path.write_text(text[:i] + text[j + len(end):])
PY
  fi
}
trap cleanup_cargo_toml EXIT

echo "=== build enclave ELF ==="
cargo build --"${PROFILE}" --target "${TARGET}" -p openapi-enclave
cleanup_cargo_toml
trap - EXIT

if [[ ! -f "${KEY}" ]]; then
  echo "Generating dev enclave signing key at ${KEY}"
  mkdir -p "$(dirname "${KEY}")"
  openssl genrsa -3 3072 > "${KEY}"
fi

echo "=== ELF -> SGXS ==="
ftxsgx-elf2sgxs "${ELF}" \
  --heap-size "${HEAP_SIZE}" \
  --stack-size "${STACK_SIZE}" \
  --threads "${THREADS}" \
  --output "${SGXS}"

echo "=== sign SGXS ==="
# Debug enclave for lab bring-up (ftxsgx-runner default); prod signing drops -d.
SIGN_LOG="$(mktemp)"
sgxs-sign -d --key "${KEY}" "${SGXS}" "${SIG}" | tee "${SIGN_LOG}"

echo "=== MRENCLAVE / metadata ==="
{
  grep -E 'ENCLAVEHASH|MRENCLAVE' "${SIGN_LOG}" || true
  sgxs-info summary "${SGXS}"
} | tee "${ROOT}/deploy/sgx/last-build-inspect.txt"
rm -f "${SIGN_LOG}"

echo ""
echo "SGXS: ${SGXS}"
echo "SIG:  ${SIG}"
echo "Export for runtime:"
echo "  export OPENAPI_SGX_ENCLAVE=${SGXS}"
echo "  # Set OPENAPI_MRENCLAVE from ENCLAVEHASH above"
