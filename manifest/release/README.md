# Release allowlist asset

Place `openapi-edge-attest.json` here (schema `teechat-openapi-edge-manifest/v1`) so the
tag `Release` workflow attaches the production allowlist instead of a CI stub.

Requirements:

- `code_hash` must equal the SHA-256 of the published `openapi` binary in `SHA256SUMS`.
- TEE `measurement` fields must match the live edge that will serve `openapi.teechat.ai`.
- After the GitHub Release is published, mirror the **same JSON bytes** to teechat.ai
  `.well-known` as an Ed25519-signed fallback (see TeaChat ops runbook
  `docs/ops/openapi-edge-attestation-manifest.md`).
