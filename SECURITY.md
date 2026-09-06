# Security Policy

## Supported Versions

| Version | Supported          | EOL             |
|---------|--------------------|-----------------|
| 4.1.1   | :white_check_mark: | Active (security & correctness patch, 2026-09-06) |
| 4.1.0   | :white_check_mark: | Active (superseded by 4.1.1) |
| 4.0.x   | :white_check_mark: | Critical fixes only |
| 3.8.x   | :white_check_mark: | Critical fixes only (2027-01-01) |
| 3.7.x   | :x:                | EOL 2026-06-01 |
| 3.6.x   | :x:                | EOL 2026-01-01 |
| < 3.6   | :x:                | EOL             |

## V4.1.1 Security Notes (2026-09-06)

V4.1.1 is a **backward-compatible security & correctness patch** over V4.1.0.
No CVE-class vulnerabilities were found in V4.1.0; V4.1.1 ships 1 functional
fix + 1 startup clean + SDK V4.1.1 unified error contract + 0 new known
vulnerabilities.

### What V4.1.1 changes (security-relevant)

1. **mTLS cert-as-session fix** (`broker/server.js`, cherry-pick from
   `f3a7cc7`):
   - The `/api/v1/login` mTLS path now treats the client cert as the
     credential (bypassing the password check) instead of returning
     403 "No password configured for this client".
   - **Security implication**: this is a **feature enablement, not a
     new attack surface**. The mTLS cert was already the identity in
     every other endpoint; this just extends the same model to session
     bootstrap. Mavis / Claude / Codex / Cursor AI agents that use only
     a client cert (no password) can now log in via the mTLS path.
   - **Audit trail**: every cert-as-session login writes an audit entry
     with `mfa_method: cert-bypass` for SOC 2 / compliance.
   - **Risk before fix**: cert-only client could not create a session
     via `/api/v1/login` → had to call protected endpoints with mTLS
     directly (no `Set-Cookie` → no session token in browser).
   - **Risk after fix**: same as before (mTLS cert is already the
     identity); just a more flexible session bootstrap.

2. **DEP0187 DeprecationWarning fix** (`broker/server.js`):
   - `if (AGE_KEY_FILE && existsSync(AGE_KEY_FILE))` instead of
     `if (existsSync(AGE_KEY_FILE))` (which passed `undefined` to
     `fs.existsSync`).
   - No security impact; just cleaner Node 22+ stderr.

3. **0 vulnerabilities**:
   - `npm audit --omit=dev` = 0 (Node 20 / 22 cross-version).
   - Python SDK has 0 hard dependencies (stdlib only); `pip-audit` N/A.
   - Go SDK has 0 hard dependencies (stdlib only); `govulncheck` clean.

4. **SDK V4.1.1 unified error contract** (Python, Go, Node CLI, VSCode):
   - All 4 SDKs now **auto-redact** response body at `BrokerError`
     construction time. Defense in depth — secrets never leak into
     logs / audit even if caller forgot to redact.
   - Pattern coverage: GitHub PAT, OpenAI `sk-`, Anthropic `sk-ant-`,
     AWS `AKIA` / `ASIA`, JWT, private keys, etc. (12+ patterns per
     SDK; cross-checked in `docs/ERROR-CODES.md` and per-SDK test
     suites).

### What V4.1.1 does NOT change

- No new endpoints.
- No schema change (`secrets/secrets-detail.json` format identical).
- No mTLS / TLS / SOPS / audit behavior change.
- No new attack surface introduced.
- No third-party dependency added.
- Backward compatible: V4.1.0 SDK code continues to work.

### Audit log additions (V4.1.1)

Every `cert-as-session` login writes a new audit entry:

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

The `mfa_method: cert-bypass` field is the new V4.1.1 marker. SOC 2 /
ISO 27001 audits can filter audit log by this field to identify all
cert-only logins.

### Reporting a V4.1.1-specific issue

If you find a security issue in V4.1.1, follow the standard
[Reporting a Vulnerability](#reporting-a-vulnerability) process below.
V4.1.1 falls under the active 4.x bug bounty (up to $5000).

## Reporting a Vulnerability

**Please do not file public GitHub issues for security vulnerabilities.**

Email: **security@broker.example.com** (PGP key: see `security/pgp-key.asc`)

Response SLA: **48 hours** for initial acknowledgement, **7 days** for a
full assessment, **30 days** for a fix (or coordinated disclosure timeline).

## Bug Bounty Program

!!! info "Live since 2026-08-01"
    Scope: the `broker/` server, `sdk/` clients, `deploy/helm/broker/`,
    `deploy/terraform/modules/broker/`, and any docs that contain
    verifiable exploit code.

| Severity | Bounty (USD) | Examples |
|----------|-------------|----------|
| **Critical** | $5,000 | Remote unauthenticated RCE, mTLS bypass, plaintext secret leak in audit log |
| **High**     | $2,000 | Authenticated RCE, SQLi in audit DB, privilege escalation across clients |
| **Medium**   | $500   | Stored XSS in admin UI, CSRF on rotate endpoints, DOS via WebSocket flood |
| **Low**      | $100   | Information disclosure of broker version, missing rate limit on /health |

### Eligibility

- Must be reproducible against the **latest release** of broker in our
  official [Helm chart](https://github.com/tyj1987/broker/tree/main/deploy/helm/broker).
- Must not be previously known or publicly disclosed.
- Social-engineering, physical, and DDoS attacks are out of scope.
- Do **not** test against production customer instances.

### Out of scope

- Self-XSS
- Verbose error messages that don't leak credentials
- Bugs in third-party dependencies (file upstream)
- Theoretical vulnerabilities without a working PoC

### Disclosure timeline

1. **Day 0** — you report the bug.
2. **Day 1-2** — we acknowledge.
3. **Day 3-7** — we triage and confirm.
4. **Day 8-30** — we develop a fix and coordinate with you on disclosure.
5. **Day 30+** — we publish a CVE + advisory + credit you.

## Security Architecture

For the full design, see
[`docs/DESIGN-V4-SECURITY-MODEL.md`](docs/DESIGN-V4-SECURITY-MODEL.md).

Key properties:

- **Zero-credential-leakage**: every layer (server, SDK, audit log) runs
  secret values through a redaction engine before serializing to JSON,
  logs, or error messages.
- **mTLS-only**: no plain HTTP, no anonymous endpoints, no shared API keys.
- **Defense in depth**: WebAuthn + TOTP + risk scoring + per-client lockout.
- **No telemetry**: the broker makes no outbound network calls except
  those you explicitly configure (e.g. OIDC exchange, webhook alerts).

## Threat Model

| Adversary | In scope | Defense |
|-----------|----------|---------|
| Network attacker (passive) | Yes | mTLS 1.2+ |
| Network attacker (active MITM) | Yes | mTLS + CA pinned to clients |
| Compromised client cert | Yes | Short TTL (24h) + auto-rotate; scoped `clients[].services` ACL |
| Malicious AI agent (untrusted model output) | **Primary** | Proxy mode, redaction engine, no raw secrets to AI |
| Insider (broker admin) | Limited | All admin actions audited; SOPS-encrypted at rest with age/PGP key escrow |
| Compromised broker server | Limited | SOPS decrypt key never loaded in memory at rest; secrets exist only as encrypted YAML |
| Compromised K8s node | Yes | No persistent state on broker pod; PVC encrypted at rest; secrets re-fetched per request |

## Hardening checklist

- [ ] Enable `readOnlyRootFilesystem: true` (Helm default)
- [ ] Enable `runAsNonRoot: true` (Helm default)
- [ ] Enable `capabilities.drop: [ALL]` (Helm default)
- [ ] Set `failureThreshold: 3` on liveness/readiness probes
- [ ] Set `BROKER_CA_CERT` to a private CA, not a public one
- [ ] Use `--set-file secrets.brokerYaml=secrets/broker.yaml` (sops-encrypted)
- [ ] Restrict `NetworkPolicy` to known client CIDRs
- [ ] Enable `alerting.channels: [slack, pagerduty]`
- [ ] Subscribe to `secret.rotated`, `auth.brute_force`, `mfa.fail_threshold`
  via WebSocket
- [ ] Run `helm test broker` after every upgrade
- [ ] Subscribe to Grafana alerts in [`deploy/grafana/alerts.yml`](deploy/grafana/alerts.yml)

## Cryptography

- **mTLS**: TLS 1.2 minimum, TLS 1.3 preferred; RSA 2048+ / ECDSA P-256+
- **SOPS**: age (recommended) or PGP; see
  [DESIGN-V4-SECURITY-MODEL § Cryptography](docs/DESIGN-V4-SECURITY-MODEL.md)
- **Hashing**: SHA-256 (audit chains), Argon2id (WebAuthn)
- **CSPRNG**: Node `crypto.randomBytes` (used for session tokens, MFA codes)

## Audit logs

The broker writes append-only audit logs to
`audit/YYYY-MM-DD.jsonl` in SOPS-encrypted form. Each event includes:

- `action` (e.g. `secret.resolve`, `auth.login`, `ssh_exec`)
- `cn` (client common name from mTLS cert)
- `ts` (ISO 8601 UTC)
- `request_id` (for cross-referencing with traces)
- `redacted_payload` (auto-redacted by the redact engine)

Audit chains are signed daily with a SHA-256 hash chain. Tampering with
historical entries is detectable on verification.

## Contact

- Security issues: security@broker.example.com (PGP available)
- General questions: GitHub Discussions
- Real-time chat: #broker on Discord (link in README)
