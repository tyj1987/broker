# Frequently Asked Questions

> Common questions about deploying, operating, and integrating with
> [Secret Broker V4.1](https://github.com/tyj1987/broker).
> If your question is not here, open a [GitHub Discussion](https://github.com/tyj1987/broker/discussions).

## Install & Deploy

### Q: What's the minimum deployment footprint?

**Single container.** The broker is a Node 20 process listening on a single
port (8443 by default). For dev: `cd broker && npm start` works after
`bootstrap.ps1` (Windows) or `scripts/broker/init-ca.sh` (Linux).

For production, use the [Helm chart](../deploy/helm/broker/) (2-replica HA on
K8s) or the [Docker Compose profile](../docker-compose.yml) (`--profile
monitoring` for Prometheus + Grafana).

### Q: Does it run on Windows?

Yes. Tested on Windows 10/11 with Node 20.11+ and Windows Server 2022.
The broker is platform-agnostic — all paths in the source use
`path.join()`, no Unix-only syscalls.

For the bootstrap scripts, `bootstrap.ps1` is the Windows entry point
(PowerShell 5.1+). On Linux, use the equivalent shell scripts in
`scripts/broker/`.

### Q: How do I run it behind nginx / Cloudflare / a reverse proxy?

Three options:

1. **mTLS termination at the proxy** — proxy validates client cert and
   forwards request to broker. You must also forward the client cert via
   `X-Client-Cert` header (broker will validate it again). See
   [DESIGN-V4-SECURITY-MODEL § Reverse proxies](DESIGN-V4-SECURITY-MODEL.md).
2. **TCP passthrough** — proxy passes raw TLS through, broker does mTLS
   directly. Recommended for production.
3. **Mutual with proxy headers** — proxy injects `X-Forwarded-ClientCert`
   header; broker trusts a specific set of upstream proxies (configured
   per-client via `clients[cn].trusted_proxies`).

### Q: How much disk / memory does it need?

- **CPU**: 0.2 cores baseline, 1.0 cores at 100 RPS proxy
- **Memory**: 256 MB baseline, 512 MB at 100 RPS proxy
- **Disk**: 1 GB PVC (for SOPS-encrypted secrets). The audit log adds
  ~10 MB/day at moderate use.
- **Network**: 1 Gbps NIC recommended; broker is single-threaded for
  secrets but uses libuv for network I/O.

## Security

### Q: How do I rotate the broker's own TLS certificate without downtime?

1. Generate the new cert with `scripts/broker/issue-server-cert.sh -new`.
2. Add the new cert as a secondary SAN on the existing one.
3. Reload broker: `curl -X POST https://broker:8443/api/v1/admin/reload?token=...`
4. Switch the active cert via DNS or load balancer.
5. Remove the old cert from the trust chain.

Or use the Helm chart's `tls.crt` secret, which can be rotated via
`helm upgrade` with zero downtime (broker re-reads on SIGHUP).

### Q: How does the broker detect a stolen client cert?

Three signals:
1. **Geo-anomaly** — login from a country where this CN has never been
   seen → MFA challenge.
2. **Velocity** — > 1000 RPS from a single client → automatic rate limit
   + alert.
3. **Risk score** — high-risk actions require re-auth (WebAuthn or TOTP).

For full revocation, run `secret-broker pki revoke --fingerprint <sha256>`,
which adds the cert's serial to the CRL. The broker reloads CRL every 5
minutes (or via `admin/reload`).

### Q: What if a client leaks their private key?

1. **Immediate**: revoke the cert (`pki revoke --fingerprint <fp>`).
   The next request with that cert is rejected.
2. **Within 5 minutes**: the CRL is reloaded automatically. All clients
   see the revocation.
3. **After**: reissue a new cert for the legitimate user, re-deploy
   it to their device, revoke the old one.

### Q: Can the broker be a single point of failure?

It depends on the deployment:
- **Single instance**: yes. SPOF. Use a load balancer with health checks.
- **Helm chart with 2+ replicas**: no. Replicas are stateless — any
  can serve any request. Use a shared PVC for SOPS-encrypted secrets.
- **Multi-cloud failover**: see the Tencent mirror deployment in
  `infra/tencent/broker.tf`. Active-passive with rsync + DNS switch
  gives ~5 minute RTO.

### Q: How do I migrate from v3.8 to v4.1?

Run `secret-broker migrate v3-to-v4 --in-place secrets/broker.yaml`. This:

- Adds the new v4.1 sections (`mfa_policy`, `alerting`,
  `workload_identity`) with safe defaults.
- Preserves all v3.8 service definitions and client ACLs.
- Re-encrypts with SOPS using the existing age key.

No data loss. v3.8 clients continue to work unchanged.

## Operations

### Q: How do I read the audit log?

```bash
# Today's audit (server)
cat /var/lib/broker/audit/2026-09-01.jsonl | jq -c '.'

# Filter by client
cat audit/2026-09-01.jsonl | jq -c 'select(.cn == "ai-agent-1")'

# Filter by failed logins (failed auth attempts)
cat audit/2026-09-01.jsonl | jq -c 'select(.action == "login" and .status == "failed")'
```

The audit log is **append-only** with a daily SHA-256 hash chain. To verify
integrity: `tail -1 audit/2026-09-01.jsonl | jq .chain_hash` and compare
against the previous day's `chain_hash` + the day's events.

### Q: How do I add a new secret type?

1. Add the type to `broker/type-schemas.js` (under `TYPE_SCHEMAS`):
   ```js
   my_new_type: {
     label: 'My New Type',
     description: '...',
     rotate_recommendation_days: 90,
     fields: [
       { name: 'token', label: 'Token', kind: 'password', required: true, sensitive: true },
     ],
   }
   ```
2. Add a redact pattern if the token format is recognizable
   (`broker/lib/redact.js`).
3. Add a service template if the type is for a specific cloud provider
   (`broker/service-templates.js`).
4. Add tests in `broker-test/test-redact.js` and a new test file
   under `broker-test/`.

### Q: How do I add a new SDK language?

Follow the pattern of `sdk/python/` or `sdk/go/`:

1. Implement the 8 calling surfaces (get / resolve / list / proxy / exec
   / ssh / workload / login).
2. Add typed errors with `errors.Is` support.
3. Add a `redact()` function with at least these patterns:
   `ghp_`, `sk-`, `sk-ant-`, `AKIA`, `ASIA`, JWT, `Authorization:`,
   `X-API-Key:`, `token=`, `password=`.
4. Use **stdlib only** if possible (Python and Go SDKs both do this).
   For Node, only `ws` is allowed.
5. Add a `README.md` with the 8-surface table.
6. Add tests using stdlib HTTP mocks.
7. Add the SDK to the [VERIFICATION matrix](VERIFY.md) and
   `npm run test:verify-all`.

### Q: Why is the test:verify count different from what I expect?

The `npm run test:verify` script runs:

- `test:modular` — 10 v3.8 test files, 282 tests
- `test:v4-modules` — 1 V4 integration file, 201 tests
- `test:workload` — 56 tests
- `test:ssh` — 53 tests
- `test:ws` — 27 tests

Total: **619 broker tests**. Add `npm run test:python-sdk` for 28 more
(= **647** with `test:verify-all`).

The Go SDK (15 cases) and VS Code extension (11 cases) tests are not
automated in the broker test suite because they require Go and tsc
toolchains. They are validated separately per
[VERIFICATION matrix](VERIFY.md) §5-6.

## Troubleshooting

### Q: My SDK gets `407 Proxy Authentication Required` from the broker.

This is actually the **proxy auth prompt** (HTTP 407), not a 407 from
the upstream service. It means the broker itself rejected the request.
Check the response body — it should be a JSON error with a `code` field:

- `code: "mfa_required"` — your risk score is high; complete MFA.
- `code: "ip_not_allowed"` — your IP isn't in the whitelist; ask the
  admin to add it.
- `code: "service_not_allowed"` — your ACL doesn't include this service.
- `code: "rate_limited"` — you're over the limit; back off.

### Q: I get `INVALID_CLIENT_CERT` but my cert is valid.

Common causes:
1. **Wrong CA**: client cert is signed by a different CA than the broker
   trusts. Check `clients[cn].ca_chain`.
2. **Expired**: cert is past `notAfter`. Reissue with
   `scripts/broker/issue-client-cert.sh -CN x -Days 365`.
3. **Wrong hostname**: server cert SAN doesn't include the hostname
   you're connecting with. The CN must be in the SAN list, not just
   `subject.CN`.
4. **mTLS not configured**: broker is configured for password login
   only. Add `mTLS: { enabled: true }` to broker.yaml.

### Q: `secret-broker get` works but `proxy` returns 502.

The proxy failed to reach the upstream. Check:

1. **Network**: from the broker host, can you `curl` the upstream URL?
2. **Upstream auth**: did the broker inject the correct auth header?
   Look at `audit/...jsonl` for `upstream_status: 502` and the
   `upstream_error` field.
3. **Timeout**: is the upstream slow? Default 30s. Configure per-service
   with `services[svc].proxy_timeout_ms`.

### Q: Auto-rotate ran but my secret still has the old value.

1. Check `audit/...jsonl` for the `secret.rotated` event.
2. If the event exists but the value didn't change, the rotation
   function returned the same value (e.g. AWS IAM `CreateAccessKey`
   returns the new key, but the secret store didn't get the response).
3. If the event doesn't exist, the rotation check (`runRotationCheck`)
   didn't find your secret as "expired" — verify the
   `rotate_recommendation_days` is set correctly.

### Q: My test:verify runs 619 tests but my fork runs 612. Why?

This usually means a test was deleted or renamed. Run with verbose output:

```bash
cd broker
npm run test:v4-modules 2>&1 | grep -E "FAIL|Section"
```

to find the regression. Then check the [CHANGELOG](../CHANGELOG.md) for
recent removals.

## Contributing

### Q: Can I add a new redact pattern?

Yes. Add to `broker/lib/redact.js`:

```js
{ name: 'my_new_pattern', regex: /pattern/i, replace: '[REDACTED_MINE]' },
```

Then add a test in `broker-test/test-redact.js`:

```js
ok('my new pattern redacts', !redact('...pattern...').includes('...'));
```

PRs that add a new secret format MUST include the corresponding redact
pattern (see [CONTRIBUTING.md](../CONTRIBUTING.md) Architecture principles).

### Q: How do I get a CVE assigned for a vulnerability I found?

Email **security@broker.example.com** with:
- Vulnerability description + impact
- Reproduction steps
- Suggested fix (if any)

We will:
- Acknowledge within 48 hours
- Assign a CVE within 7 days (if confirmed)
- Coordinate disclosure with you (default 30 days)
- Credit you in the advisory

## V4.1.1 FAQ (2026-09-06)

### Q: What's in V4.1.1?

V4.1.1 is a backward-compatible security & correctness patch over V4.1.0
with two main improvements:

1. **mTLS cert-as-session fix** (broker side): mavis / Claude /
   Codex / Cursor and other cert-only AI agents can now log in via
   the mTLS path. V4.1.0 returned 403 "No password configured for
   this client"; V4.1.1 treats the cert as the credential. Every
   cert-as-session login writes an audit entry with
   `mfa_method: cert-bypass` for SOC 2 / compliance.

2. **4-SDK unified error contract** (Python, Go, Node CLI, VSCode):
   all 4 SDKs now expose a single `BrokerError` class with
   structured fields (`status`, `code`, `requestId`,
   `retryAfter`, `is_retryable`, `toString`, `toJSON`). Plus a
   `parseBrokerError(status, headers, body, op)` factory and
   built-in retry (5xx / 429 / connection with exponential
   backoff + `Retry-After` header override).

See [RELEASE-NOTES-v4.1.1.md](../RELEASE-NOTES-v4.1.1.md) and
[SECURITY.md §V4.1.1 Security Notes](../SECURITY.md#v411-security-notes-2026-09-06).

### Q: Do I have to upgrade from V4.1.0 to V4.1.1?

**Recommended but not required.** V4.1.1 is a backward-compatible
patch; existing V4.1.0 SDK code continues to work unchanged.
Upgrade at your convenience — zero downtime, no schema change.

However, if you use:
- **cert-only AI agents** (mavis / Claude / Codex / Cursor):
  V4.1.1 enables the mTLS cert-as-session path. V4.1.0 returned
  403; V4.1.1 returns 200 + session cookie.
- **V4.1.0 SDK code with `BrokerAuthError` etc.**: V4.1.1 keeps
  the old 6-class hierarchy exported for one release, but emits
  `DeprecationWarning`. New code should switch to
  `BrokerError` + `e.code === 'auth_failed'` checks.
  See [SDK-UPGRADE-GUIDE.md](SDK-UPGRADE-GUIDE.md).

### Q: My V4.1.0 SDK code throws a `DeprecationWarning` after upgrading to V4.1.1. What do I do?

The 6 typed error classes (`BrokerAuthError`, `ErrAuth`, etc.)
are still exported in V4.1.1 for one release, but emit
`DeprecationWarning` on import. Migrate to the new
`BrokerError` + `e.code` pattern:

```python
# V4.1.0 (deprecated, still works in V4.1.1)
try:
    c.get_secret("github.pat")
except BrokerAuthError as e:
    ...

# V4.1.1 (recommended)
try:
    c.get_secret("github.pat")
except BrokerError as e:
    if e.status == 401 or e.code == "auth_failed":
        ...  # your auth handling
```

See [SDK-UPGRADE-GUIDE.md](SDK-UPGRADE-GUIDE.md) for full migration
examples for all 4 SDKs (Python / Go / Node CLI / VSCode).

### Q: What is the V4.1.1 retry behavior?

All 4 SDKs now automatically retry **retryable errors** (5xx /
429 / connection failures) with exponential backoff:

| Setting | Default | Configurable via |
|---------|---------|------------------|
| `maxRetries` | `2` (so up to 3 total attempts) | `Config.max_retries` / `Config.MaxRetries` / `config.maxRetries` |
| `retryBackoffMs` | `500` ms (doubled each retry) | `Config.retry_backoff_ms` / `Config.RetryBackoffMs` / `config.retryBackoffMs` |

**Backoff curve** (default settings): 500 ms → 1000 ms → 2000 ms.
If the broker returns `Retry-After: 30`, the SDK waits 30
seconds (overrides exponential backoff).

Set `maxRetries=0` to disable retry (useful if you have your
own retry logic).

### Q: Does V4.1.1 introduce new broker error codes?

No. V4.1.1 introduces no new error codes from the broker. The
change is **in the SDKs** (single `BrokerError` class replacing
6 typed classes). The underlying codes broker returns are
unchanged. See [ERROR-CODES.md](ERROR-CODES.md) for the full
registry of 25 broker error codes.

### Q: How do I handle the cert-bypass audit entries for SOC 2 / ISO 27001?

V4.1.1 writes a new audit field for cert-as-session logins:

```json
{
  "ts": "2026-09-06T12:34:56.789Z",
  "event": "login",
  "client": "mavis",
  "ip": "127.0.0.1",
  "user_agent": "secret-broker-cli/4.1.1",
  "auth_method": "mtls",
  "mfa_method": "cert-bypass",
  "session_id": "...",
  "session_duration_s": 604800
}
```

The `mfa_method: cert-bypass` field is the new V4.1.1 marker.
SOC 2 / ISO 27001 audits can filter the audit log by this field
to identify all cert-only logins (i.e. logins that bypassed
TOTP / WebAuthn). This is documented in
[SECURITY.md §V4.1.1 Security Notes](../SECURITY.md#v411-security-notes-2026-09-06).

### Q: When should I migrate to V4.1.1?

| Your situation | Recommendation |
|----------------|----------------|
| Using V4.1.0 SDK, integration works fine | Stay on V4.1.0 indefinitely; SDK auto-upgrade is safe but not required. |
| Use cert-only AI agents (mavis / Claude / Codex / Cursor) | Upgrade immediately — V4.1.0 returns 403 for cert-only clients. |
| Need richer error context (for monitoring / audit) | Upgrade; switch to `BrokerError` pattern. |
| Hitting transient 5xx / 429 frequently | Upgrade; built-in retry (default 2 retries, exp backoff). |
| Mission-critical, cannot risk any SDK change | Stay on V4.1.0; V4.1.1 is forward-compatible. |

### Q: How do I verify V4.1.1 release readiness?

After merging all V4.1.1 PRs (per AWAITING-USER V13), run:

```bash
node scripts/verify-v4.1.1-release.mjs --strict
```

This runs both:
- `preflight-v4.1.1.mjs` (broker + versions + docs).
- `verify-sdk-v4.1.1-parity.mjs` (4-SDK parity contract).

Exit 0 = ready to tag `v4.1.1` and ship. Non-zero = see output
for which work remains.

See [RUNBOOK-v4.1.1.md §Step 1](RUNBOOK-v4.1.1.md) for full details.

### Q: How do I upgrade my 52trz.com (or production) install from V4.1.0 to V4.1.1?

In-place upgrade, zero downtime, ~5 minutes:

```bash
ssh user@broker.52trz.com
cd /opt/secret-broker
sudo cp -a secrets pki audit secrets.bak.$(date +%Y%m%d)  # safety backup
sudo git fetch
sudo git checkout v4.1.1
sudo npm install --omit=dev
sudo systemctl restart secret-broker
sleep 3
curl -k --cert /opt/secret-broker/pki/clients/admin.crt \
        --key /opt/secret-broker/pki/clients/admin.key \
        https://broker.52trz.com:8443/health
# Expect: {"status":"ok","version":"4.1.1",...}
```

Then verify the cert-as-session fix:

```bash
curl -k --cert /opt/secret-broker/pki/clients/mavis.crt \
        --key /opt/secret-broker/pki/clients/mavis.key \
        -c /tmp/mavis-cookies.txt \
        -X POST https://broker.52trz.com:8443/api/v1/login \
        -H 'Content-Type: application/json' \
        -d '{}'
# Expect: 200 OK + Set-Cookie: broker_session=... (V4.1.0: 403)
```

See [DEPLOY-52TRZ.md](../../DEPLOY-52TRZ.md) and
[RUNBOOK-v4.1.1.md §Step 7](RUNBOOK-v4.1.1.md).

### Q: Where do I report a V4.1.1-specific issue?

V4.1.1 falls under the standard 4.x bug bounty (up to $5000).
Follow [SECURITY.md §Reporting a Vulnerability](../SECURITY.md#reporting-a-vulnerability)
or email **security@broker.example.com**.

For non-security issues (e.g. documentation bug, V4.1.1 SDK
question), open a GitHub issue using the V4.1.1-era
[PR template](https://github.com/tyj1987/broker/blob/main/.github/PULL_REQUEST_TEMPLATE.md)
or [discussion](https://github.com/tyj1987/broker/discussions).

## Related

- [RELEASE-NOTES-v4.1.1.md](../RELEASE-NOTES-v4.1.1.md) — official release body.
- [SDK-UPGRADE-GUIDE.md](SDK-UPGRADE-GUIDE.md) — V4.1.0 → V4.1.1 migration.
- [ERROR-CODES.md](ERROR-CODES.md) — 25 broker error codes.
- [SECURITY.md](../SECURITY.md#v411-security-notes-2026-09-06) — V4.1.1 security notes.
- [RUNBOOK-v4.1.1.md](RUNBOOK-v4.1.1.md) — 8 步 release manual.
- [V4.1.1-COMMITS.md](V4.1.1-COMMITS.md) — 21 commits × 10 sections.

See [SECURITY.md](../SECURITY.md) for the full Bug Bounty program.
