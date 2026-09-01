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

See [SECURITY.md](../SECURITY.md) for the full Bug Bounty program.
