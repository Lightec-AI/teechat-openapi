# OpenAPI edge attestation keys

| File | Purpose |
|------|---------|
| `openapi-attestation-v1.pub` | Ed25519 public key (32-byte hex) pinned in `teechat-openapi-attest` and the TeeChat desktop verifier. |

**Private keys are never committed.** Ops keep them in `scripts/ops/secrets/` (gitignored) on the signing workstation.

## Rotation

1. Generate a new keypair (`openapi-attestation-v2`).
2. Publish a manifest signed by **v1** that includes `next_key` with the v2 public key and `not_before`.
3. After `not_before`, publish subsequent manifests signed by v2 (`key_id = openapi-attestation-v2`).
4. Verifiers accept either the pinned root or a `next_key` authorized by that root until the old key is retired.
