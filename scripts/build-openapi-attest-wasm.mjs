#!/usr/bin/env node
/**
 * Build `openapi-attest-wasm` for browser / Capacitor WebView (wasm-pack, target `web`).
 *
 * Output: `vendor/teechat-openapi/pkg/openapi-attest-wasm/`
 * Requires: Rust toolchain + `wasm32-unknown-unknown` (wasm-pack installs target if needed).
 *
 * Soft-wire only (RB-02): web keeps manifest-bound fallback when this package is absent.
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const openapiDir = resolve(here, "..");
const repoRoot = resolve(openapiDir, "..", "..");
const outDir = resolve(openapiDir, "pkg", "openapi-attest-wasm");

if (!existsSync(resolve(openapiDir, "Cargo.toml"))) {
  console.error(`[build-openapi-attest-wasm] openapi workspace not found at ${openapiDir}`);
  process.exit(1);
}

mkdirSync(outDir, { recursive: true });

const wasmPack =
  process.env.WASM_PACK_BIN ??
  resolve(repoRoot, "node_modules", ".bin", "wasm-pack");
const args = [
  "build",
  "crates/openapi-attest-wasm",
  "--target",
  "web",
  "--release",
  "--out-dir",
  outDir,
  "--out-name",
  "openapi_attest_wasm",
  "--scope",
  "teechat",
];

console.error(
  `[build-openapi-attest-wasm] ${wasmPack} ${args.join(" ")} (cwd=${openapiDir})`,
);
try {
  execFileSync(wasmPack, args, {
    cwd: openapiDir,
    stdio: "inherit",
  });
} catch (e) {
  console.error(
    `[build-openapi-attest-wasm] failed: ${e instanceof Error ? e.message : e}`,
  );
  process.exit(1);
}

// wasm-pack scopes as @teechat/openapi-attest-wasm; normalize package name for file: deps.
const pkgJsonPath = resolve(outDir, "package.json");
if (existsSync(pkgJsonPath)) {
  const pkg = JSON.parse(readFileSync(pkgJsonPath, "utf8"));
  pkg.name = "@teechat/openapi-attest-wasm";
  pkg.type = "module";
  writeFileSync(pkgJsonPath, `${JSON.stringify(pkg, null, 2)}\n`);
}

// wasm-pack writes a catch-all .gitignore; remove so the file: dep can be committed.
const pkgGitignore = resolve(outDir, ".gitignore");
if (existsSync(pkgGitignore)) {
  unlinkSync(pkgGitignore);
}

console.error(`[build-openapi-attest-wasm] artifacts in ${outDir}`);
