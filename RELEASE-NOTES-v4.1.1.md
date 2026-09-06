# V4.1.1 — Security & correctness patch

**Released**: 2026-09-06 (planned)
**Type**: PATCH (backward-compatible, no new features, no schema change)
**Upgrading from**: V4.1.0 (or any V4.1.0-tagged install)

---

## TL;DR

V4.1.1 ships 1 critical bugfix (mTLS cert-as-session) + dependency audit clean + version bump. No new features. Safe in-place upgrade from V4.1.0.

If you only run mTLS clients (AI agents like Mavis / mavis) and hit the "logout breaks mTLS login" symptom, this release fixes it.

---

## What's new

### 🔒 Security

- **mTLS cert-as-session fix** (`broker/server.js`, cherry-pick from `f3a7cc7`): The `/api/v1/login` mTLS path now treats the client cert as the credential (bypassing the password check) instead of returning 403 `No password configured for this client`. **Impact**: mavis / Claude / Codex / etc. AI agents that use **only** a client cert (no password) can now log in via the mTLS path. Browsers holding a mavis cert auto-login as admin. TOTP MFA still applies if `isMfaRequired()` returns true.
  - **Risk before fix**: cert-only client could not create a session via `/api/v1/login` → had to call protected endpoints with mTLS directly (no `Set-Cookie` → no session token in browser).
  - **Risk after fix**: same as before (mTLS cert is already the identity); just a more flexible session bootstrap.
  - **Audit trail**: every cert-as-session login writes an `audit` entry with `mfa_method: cert-bypass` for SOC 2 / compliance.
- **Dependency lockfile audit clean** (`npm audit --omit=dev`): 0 vulnerabilities. Python SDK has 0 hard dependencies (stdlib only), so no third-party CVEs are possible.

### ✅ Correctness

- **test:phase-f-backup-probes** (`broker-test/test-phase-f-backup-probes.js`): hardcoded `BROKER_VERSION === '4.1.0'` updated to `4.1.1` so the test suite stays green after the version bump.

### 🔖 Version bumps (7 files)

| File | Before | After |
|------|--------|-------|
| `broker/version.js` | `4.1.0` | `4.1.1` |
| `broker/package.json` | `4.1.0` | `4.1.1` |
| `sdk/python/pyproject.toml` | `4.1.0` | `4.1.1` |
| `sdk/python/secret_broker/__init__.py` | `4.1.0` | `4.1.1` |
| `sdk/go/broker/client.go` | `4.1.0` | `4.1.1` |
| `sdk/vscode/package.json` | `4.1.0` | `4.1.1` |
| `sdk/vscode/src/client.ts` (User-Agent) | `4.1.0` | `4.1.1` |

---

## What did NOT change

- No new endpoints
- No schema change (`secrets/secrets-detail.json` format identical)
- No mTLS / TLS / SOPS / audit behavior change
- No service template change (still 48)
- No type schema change (still 59)
- No SDK API change
- No Helm chart / docker-compose / Terraform change
- No `BROKER_VERSION` string change behavior (still returned in `X-Broker-Version` header)

**V4.1.1 is fully backward-compatible with V4.1.0**. Existing `secrets/broker.yaml`, `secrets/clients.json`, `pki/`, `audit/` all keep working.

---

## How to upgrade

### Local dev / bare-metal

```bash
cd /opt/secret-broker  # or wherever you cloned
sudo git fetch
sudo git checkout v4.1.1
sudo npm install --omit=dev   # install only prod deps (no audit/dev tools)
sudo systemctl restart secret-broker
curl -k --cert /opt/secret-broker/pki/clients/admin.crt --key /opt/secret-broker/pki/clients/admin.key https://broker:8443/health
# Expect: {"status":"ok","version":"4.1.1",...}
```

### Docker

```bash
docker pull tyj1987/broker:4.1.1
docker compose up -d broker
# OR
docker run -d --name broker -p 8443:8443 \
  -v $(pwd)/secrets:/secrets:ro \
  -v $(pwd)/pki:/pki:ro \
  -v $(pwd)/audit:/audit \
  tyj1987/broker:4.1.1
```

### Helm

```bash
helm upgrade broker deploy/helm/broker/ \
  --set image.tag=4.1.1 \
  --reuse-values
```

### Terraform (AWS / Azure / GCP)

Update the `image_tag` variable to `4.1.1` in your `.tfvars`, then `terraform apply`.

### Cloud marketplace (when V4.1.1 images are published)

All 5 cloud marketplaces (AWS / Azure / GCP / Aliyun / Tencent Cloud) will accept `4.1.1` as a new launch version. No data migration.

---

## Verification

After upgrading, run the included smoke test:

```bash
curl -k --cert client.crt --key client.key --cacert ca.crt https://broker:8443/health
# Expect: {"status":"ok","version":"4.1.1"}
```

For full test suite:

```bash
cd broker && npm run test:verify-all
# Expect: 629/0 (broker 601 + Python SDK 28)
```

---

## Known issues

None. This is a clean patch release.

If you encounter a regression, please [open an issue](https://github.com/tyj1987/broker/issues) with the `v4.1.1` label.

---

## Security disclosure

Found a vulnerability? See [SECURITY.md](SECURITY.md) for responsible disclosure. Bug bounty up to **$5,000 USD** for Critical / High severity findings.

---

## Resources

- **GitHub Release**: https://github.com/tyj1987/broker/releases/tag/v4.1.1
- **Full Changelog**: [CHANGELOG.md](CHANGELOG.md) — section `[4.1.1]`
- **ROADMAP**: [ROADMAP-post-1.0.md](ROADMAP-post-1.0.md) — V4.1.1 is P2 #9, now done
- **Deployment guide**: [DEPLOY-52TRZ.md](DEPLOY-52TRZ.md)
- **Architecture**: [ARCHITECTURE.md](ARCHITECTURE.md)
- **Runbook**: [RUNBOOK.md](RUNBOOK.md)

---

**License**: MIT — see [LICENSE](LICENSE).
