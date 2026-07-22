# prod-openapi CVM — TLS in guest

Production TLS for `openapi.teechat.ai` terminates **inside the SEV-SNP guest**. The hypervisor uses **TCP passthrough** only (no decryption).

## Layout

| Path | Content |
|------|---------|
| `/etc/teechat/openapi.env` | Runtime env (`OPENAPI_PROFILE=prod`, digests, upstream) |
| `/etc/teechat/openapi-tls.crt` | Public certificate chain (Let's Encrypt or commercial) |
| `/etc/teechat/openapi-tls-key.sealed.json` | AMD-SP sealed private key (`seal_version` 3 / `SNP_GET_DERIVED_KEY`) |
| `/var/lib/teechat-openapi/acme/` | ACME account + short-lived live/archive PEMs; **privkey shredded after seal** |
| `/var/www/acme/` | HTTP-01 webroot (challenge tokens only) |

HTTP-01 challenge delivery (port 80): see TeeChat [openapi-acme-http01-security.md](../../../docs/ops/openapi-acme-http01-security.md) — `openapi-acme` (instant-acme) writes the token in the guest webroot; host proxies the challenge prefix only.

Immutable golden root (target) + small writable data volume for `/etc/teechat` and ACME.

## First issuance (inside guest)

```bash
sudo install -m 0644 deploy/cvm/teechat-openapi.service /etc/systemd/system/
sudo install -m 0755 target/release/openapi /usr/local/bin/
sudo install -m 0755 target/release/openapi-acme /usr/local/bin/
sudo install -m 0755 target/release/openapi-tls-ceremony /usr/local/bin/
sudo install -m 0755 deploy/cvm/issue-and-seal-tls.sh /usr/local/bin/

# openapi.env must include OPENAPI_LAUNCH_DIGEST matching snpguest attestation
export OPENAPI_ACME_EMAIL=ops@lightec.ai
sudo bash /usr/local/bin/issue-and-seal-tls.sh issue
```

**Never** run `seal-tls-key` or `issue-and-seal-tls.sh` from a laptop with a generated `key.pem`.

**Do not install certbot** — issuance is `openapi-acme` (Rust / instant-acme).

**Sealing:** ceremony calls AMD-SP `SNP_GET_DERIVED_KEY` (GUEST_POLICY ‖ MEASUREMENT) so a non-identical CVM cannot unseal the blob. Requires `/dev/sev-guest` inside the guest.

## Renewal

```bash
sudo systemctl start teechat-openapi-acme-renew.service
# or: sudo bash /usr/local/bin/issue-and-seal-tls.sh renew
```

Timer: `teechat-openapi-acme-renew.timer` (twice daily). Renew skips when `/etc/teechat/openapi-tls.crt` is still valid for >30 days (`OPENAPI_ACME_RENEW_SKEW_SECS`).

## Verify

```bash
sudo openapi-tls-ceremony verify-disk
curl -sk https://127.0.0.1:8443/healthz
bash /usr/local/share/teechat-openapi/verify-tls13-only.sh   # or repo scripts/verify-tls13-only.sh
```

**TLS 1.3 only:** the `openapi` binary negotiates TLS 1.3 exclusively (no TLS 1.2). After install, `verify-tls13-only.sh` must pass on `127.0.0.1:8443`.

See TeeChat [openapi-snp-staging.md](../../../docs/ops/openapi-snp-staging.md) and [openapi-edge-sealing-threat-model.md](../../../docs/design/openapi-edge-sealing-threat-model.md).

## SGX / EDP (documented only — not this deploy path)

CVM uses instant-acme in the guest. SGX remains a secondary SKU; ACME options for EDP are outlined in TeeChat [openapi-edge-sealing-threat-model.md](../../../docs/design/openapi-edge-sealing-threat-model.md) §10 — do not run host certbot for enclave keys.
