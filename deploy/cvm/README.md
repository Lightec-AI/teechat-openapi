# prod-openapi CVM — TLS in guest

Production TLS for `openapi.teechat.ai` terminates **inside the SEV-SNP guest**. The hypervisor uses **TCP passthrough** only (no decryption).

## Layout

| Path | Content |
|------|---------|
| `/etc/teechat/openapi.env` | Runtime env (`OPENAPI_PROFILE=prod`, digests, upstream) |
| `/etc/teechat/openapi-tls.crt` | Public certificate chain (Let's Encrypt or commercial) |
| `/etc/teechat/openapi-tls-key.sealed.json` | Measurement-bound sealed private key |
| `/etc/letsencrypt/` | ACME state during renewal only; **privkey shredded after seal** |

HTTP-01 challenge delivery (port 80): see TeaChat [openapi-acme-http01-security.md](../../../docs/ops/openapi-acme-http01-security.md) — certbot writes token in guest webroot; host proxies challenge prefix only.

Immutable golden root (target) + small writable data volume for `/etc/teechat` and ACME.

## First issuance (inside guest)

```bash
sudo install -m 0644 deploy/cvm/teechat-openapi.service /etc/systemd/system/
sudo install -m 0755 target/release/openapi /usr/local/bin/
sudo install -m 0755 target/release/openapi-tls-ceremony /usr/local/bin/
sudo install -m 0755 deploy/cvm/issue-and-seal-tls.sh /usr/local/bin/

# openapi.env must include OPENAPI_LAUNCH_DIGEST matching snpguest attestation
export OPENAPI_ACME_EMAIL=ops@lightec.ai
sudo bash /usr/local/bin/issue-and-seal-tls.sh issue
```

**Never** run `seal-tls-key` or `issue-and-seal-tls.sh` from a laptop with a generated `key.pem`.

## Renewal

```bash
sudo systemctl start teechat-openapi-acme-renew.service
# or: sudo bash /usr/local/bin/issue-and-seal-tls.sh renew
```

Timer: `teechat-openapi-acme-renew.timer` (twice daily).

## Verify

```bash
sudo openapi-tls-ceremony verify-disk
curl -sk https://127.0.0.1:8443/healthz
bash /usr/local/share/teechat-openapi/verify-tls13-only.sh   # or repo scripts/verify-tls13-only.sh
```

**TLS 1.3 only:** the `openapi` binary negotiates TLS 1.3 exclusively (no TLS 1.2). After install, `verify-tls13-only.sh` must pass on `127.0.0.1:8443`.

See TeaChat [openapi-snp-staging.md](../../../docs/ops/openapi-snp-staging.md) and [openapi-edge-sealing-threat-model.md](../../../docs/design/openapi-edge-sealing-threat-model.md).
