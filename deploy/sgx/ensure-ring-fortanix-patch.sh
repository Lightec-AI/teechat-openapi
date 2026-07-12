#!/usr/bin/env bash
# Materialize a ring source tree patched for Fortanix EDP:
# 1) SystemRandom via RDRAND (target_os=unknown, not none) — ring#2043
# 2) Build ELF asm for SGX (same ABI as linux) — otherwise x86_64 link fails
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VENDOR_DIR="${ROOT}/deploy/sgx/vendor/ring"
MARKER="${VENDOR_DIR}/.teechat-fortanix-patched"
RING_VER="${RING_PATCH_VERSION:-0.17.14}"
PATCH_REV=2

if [[ -f "${MARKER}" ]] && [[ "$(cat "${MARKER}")" == "${PATCH_REV}" ]]; then
  exit 0
fi

echo "=== prepare patched ring ${RING_VER} for Fortanix EDP (rev ${PATCH_REV}) ==="

RING_SRC="$(
  find "${CARGO_HOME:-${HOME}/.cargo}/registry/src" -type d -name "ring-${RING_VER}" 2>/dev/null \
    | head -1
)"

if [[ -z "${RING_SRC}" || ! -d "${RING_SRC}" ]]; then
  TMP="$(mktemp -d)"
  trap 'rm -rf "${TMP}"' EXIT
  BASE="${CARGO_RING_CRATE_BASE:-https://static.crates.io/crates/ring}"
  echo "Downloading ring-${RING_VER} from ${BASE}"
  curl -fsSL "${BASE}/ring-${RING_VER}.crate" -o "${TMP}/ring.crate"
  tar -xzf "${TMP}/ring.crate" -C "${TMP}"
  RING_SRC="${TMP}/ring-${RING_VER}"
fi

rm -rf "${VENDOR_DIR}"
mkdir -p "$(dirname "${VENDOR_DIR}")"
cp -a "${RING_SRC}" "${VENDOR_DIR}"

python3 - "${VENDOR_DIR}" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])

# --- rand.rs: enable SystemRandom for Fortanix ---
rand_path = root / "src" / "rand.rs"
text = rand_path.read_text()
old = 'all(feature = "less-safe-getrandom-custom-or-rdrand", target_os = "none"),'
new = '''all(
        feature = "less-safe-getrandom-custom-or-rdrand",
        any(
            target_os = "none",
            // TeeChat: Fortanix EDP reports target_os=unknown (ring#2043).
            all(target_os = "unknown", target_env = "sgx"),
        ),
    ),'''
if old not in text:
    if 'target_env = "sgx"' not in text:
        raise SystemExit(f"expected cfg line not found in {rand_path}")
else:
    rand_path.write_text(text.replace(old, new, 1))
    print(f"patched {rand_path}")

# --- build.rs: assemble ELF for fortanix (linux ABI) ---
build_path = root / "build.rs"
b = build_path.read_text()
old_find = """        ASM_TARGETS.iter().find(|asm_target| {
            asm_target.arch == target.arch && asm_target.oss.contains(&target.os.as_ref())
        })"""
new_find = """        ASM_TARGETS.iter().find(|asm_target| {
            asm_target.arch == target.arch
                && (asm_target.oss.contains(&target.os.as_ref())
                    // TeeChat: Fortanix EDP is System V ELF like linux; without this,
                    // x86_64 rust code expects asm symbols that were never built.
                    || (target.os == "unknown"
                        && target.env == "sgx"
                        && asm_target.oss.contains(&"linux")))
        })"""
if old_find not in b:
    if "target.env == \"sgx\"" not in b:
        raise SystemExit(f"expected asm_target find block not found in {build_path}")
else:
    build_path.write_text(b.replace(old_find, new_find, 1))
    print(f"patched {build_path}")
PY

echo "${PATCH_REV}" > "${MARKER}"
echo "Patched ring ready at ${VENDOR_DIR}"
