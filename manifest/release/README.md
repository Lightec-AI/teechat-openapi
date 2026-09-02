# Release allowlist asset

Place `openapi-edge-attest.json` here (schema `teechat-openapi-edge-manifest/v1`) so the
tag `Release` workflow attaches the production allowlist instead of a CI stub.

The **linux-amd64 `openapi` binary is built by GitHub Actions** on `v*` tags — not on
the operator Mac. Ops deploy with:

```bash
bash scripts/ops/install-openapi-cvm.sh --from-github-release
```

Requirements:

- During cutover, keep an **overlap** `active[]` (live row + new row). Never relabel an
  old `code_hash` with a new `build_version`.
- Every `active[].code_hash` must appear in release `SHA256SUMS` (the workflow appends
  all active hashes). Verifiers reject a live edge whose hash is missing from
  `SHA256SUMS` when GitHub is the trust source.
- The new row’s `code_hash` must equal the SHA-256 of the published `openapi` asset
  (or the exact bytes you will deploy if they differ from CI — document why).
- TEE `measurement` fields must match the live edge that will serve `openapi.teechat.ai`.
- After the GitHub Release is published, mirror the **same JSON bytes** to teechat.ai
  `.well-known` as an Ed25519-signed fallback (see TeeChat ops runbook
  `docs/ops/openapi-edge-attestation-manifest.md`).

**Overlap / patch tags:** Live edge reports `build_version` `X.Y.Z` from the deployed
binary. The matching allowlist row often ships on **`vX.Y.(Z+1)`** (allowlist-only
patch tag) before VIP cutover finishes. `teechat-openapi-attest` steps patch tags when
`vX.Y.Z` has no row; golden may use signed www until the GitHub epoch publishes.
