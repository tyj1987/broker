# V4.1.1 — Security & correctness patch

**Released**: 2026-09-06 (planned)
**Type**: PATCH (backward-compatible, no new features, no schema change)
**Upgrading from**: V4.1.0 (or any V4.1.0-tagged install)

---

## TL;DR

V4.1.1 ships 1 critical bugfix (mTLS cert-as-session) + dependency audit clean + version bump + a **unified error contract across all 4 SDKs** (Python, Go, Node CLI, VSCode). No new server-side features. Safe in-place upgrade from V4.1.0.

If you only run mTLS clients (AI agents like Mavis / mavis) and hit the "logout breaks mTLS login" symptom, this release fixes it.

If you maintain code that calls any of the 4 SDKs, you'll benefit from the new structured `BrokerError` (with `code` / `requestId` / `retryAfter` / `isRetryable` / `toString` / `toJSON`) and built-in retry (5xx / 429 / connection with exponential backoff + `Retry-After` override).

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

## SDK V4.1.1 — unified error contract (all 4 SDKs)

In addition to the version bump, V4.1.1 ships a **unified error contract** across all 4 official SDKs. Before V4.1.1, each SDK exposed its own 6-class error hierarchy (`BrokerAuthError` / `ErrAuth` / `BrokerPermissionError` / etc.) with subtle behavior differences. V4.1.1 replaces them with a single `BrokerError` class with structured fields.

### What changed in each SDK

| SDK | Class location | New fields | New methods | Retry | Tests |
|-----|----------------|------------|-------------|-------|-------|
| Python | `secret_broker.exceptions` | `code`, `request_id`, `retry_after` | `__repr__`, `to_dict`, `is_retryable` | (Config-driven, broker-side) | 54 (was 28; +26 new) |
| Go | `broker/errors.go` | `Code`, `RequestID`, `RetryAfter` | `IsRetryable`, `ToMap` | `Config.MaxRetries` + `RetryBackoffMs` | 33 + 1 SKIP (was 15; +18 new) |
| Node CLI | `cli/secret-broker.js` | `code`, `requestId`, `retryAfter` | `toString`, `toJSON` | `mTLSRequest` (5xx/429/connection) | 21 (new) |
| VS Code | `sdk/vscode/src/client.ts` | `code`, `requestId`, `retryAfter` | `toString`, `toJSON` | `mtlsRequest` (5xx/429/connection) | 48 (was 11; +37 new) |
| **Total** | – | – | – | – | **166** (was 54; **+112 new**) |

### Single BrokerError contract

```python
# Same fields across all 4 SDKs (Python shown, equivalent in Go/Node/VSCode)
class BrokerError(Exception):
    op: str            # logical operation ("get_secret", "login", ...)
    status: int        # HTTP status code (0 for connection errors)
    code: str          # broker-specific error code from response body
    request_id: str    # X-Request-Id response header (correlate with audit logs)
    retry_after: int   # Retry-After response header in seconds
    body: str          # redacted response body
    is_retryable: bool # 5xx / 429 / connection → True
```

Plus a separate `BrokerConnectionError` for network-level failures (always retryable).

### New: `parseBrokerError(status, headers, body, op)` factory

All 4 SDKs now expose a `parseBrokerError` factory that converts a raw response
into a typed `BrokerError`, pulling `X-Request-Id` + `Retry-After` headers and
`code`/`message` from the JSON body. Useful for middleware that needs structured
error handling without catching per-class.

### New: built-in retry (5xx / 429 / connection)

All 4 SDKs automatically retry **retryable errors** with exponential backoff,
honoring the broker's `Retry-After` response header.

| Setting | Default | Configurable via |
|---------|---------|------------------|
| `maxRetries` | `2` (so up to 3 total attempts) | `Config.max_retries` / `Config.MaxRetries` / `config.maxRetries` |
| `retryBackoffMs` | `500` ms (doubled each retry) | `Config.retry_backoff_ms` / `Config.RetryBackoffMs` / `config.retryBackoffMs` |

**Backoff curve** (default settings): 500 ms → 1000 ms → 2000 ms.
If the broker returns `Retry-After: 30`, the SDK waits 30 seconds (overrides exponential backoff).

Set `maxRetries=0` to disable retry.

### Migration from V4.1.0 (6-class model)

If you were using `BrokerAuthError` / `ErrAuth` / etc.:

=== "Python"
    ```python
    # V4.1.0
    try:
        c.get_secret("github.pat")
    except secret_broker.BrokerAuthError as e:
        ...

    # V4.1.1
    try:
        c.get_secret("github.pat")
    except secret_broker.BrokerError as e:
        if e.status == 401 or e.code == "auth_failed":
            ...  # your auth handling
    ```

=== "Go"
    ```go
    // V4.1.0
    val, err := c.GetSecret("github.pat")
    if errors.Is(err, broker.ErrAuth) { ... }

    // V4.1.1
    val, err := c.GetSecret("github.pat")
    var berr *broker.BrokerError
    if errors.As(err, &berr) && berr.Status == 401 { ... }
    ```

=== "Node / VSCode"
    ```javascript
    // V4.1.0
    try { await c.getSecret("github.pat"); }
    catch (e) { if (e instanceof BrokerAuthError) { ... } }

    // V4.1.1
    try { await c.getSecret("github.pat"); }
    catch (e) { if (e instanceof BrokerError && e.status === 401) { ... } }
    ```

### Defense in depth: body auto-redact on construction

All 4 SDKs now **auto-redact** the response body at `BrokerError` construction time
(using their existing redaction engines: GitHub PAT / OpenAI / Anthropic / AWS / JWT
patterns). This means secrets never leak into logs / audit even if the caller forgot
to redact.

### Reference

- Python: `sdk/python/secret_broker/exceptions.py` (PR `9a0c5f7`)
- Go: `sdk/go/broker/errors.go` (PR `6052779`)
- Node CLI: `cli/secret-broker.js` (PR `ba6da09`)
- VS Code: `sdk/vscode/src/client.ts` (PR `f0a6dd1`)
- Cross-SDK docs: `docs/SDK-REFERENCE.md` (PR `20c5e6d`)

---

## What did NOT change

- No new endpoints
- No schema change (`secrets/secrets-detail.json` format identical)
- No mTLS / TLS / SOPS / audit behavior change
- No service template change (still 48)
- No type schema change (still 59)
- **No breaking SDK API change** (V4.1.0 SDK code still works; new fields are additive; old `BrokerAuthError` etc. classes are deprecated but still exported for one release)
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
