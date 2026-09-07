# Security Policy

## Supported Versions

| Version | Supported          | EOL             |
|---------|--------------------|-----------------|
| 4.x     | :white_check_mark: | Active (GA Q3 2026) |
| 3.8.x   | :white_check_mark: | Critical fixes only (2027-01-01) |
| 3.7.x   | :x:                | EOL 2026-06-01 |
| 3.6.x   | :x:                | EOL 2026-01-01 |
| < 3.6   | :x:                | EOL             |

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
| **Medium**   | $500   | Stored XSS in admin UI, CSRF on rotate endpoints, DOS via WebSocket flood, unauthenticated `/health` leaking SOPS/service inventory |
| **Low**      | $100   | Information disclosure of broker version on authenticated responses, missing rate limit on /health |

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
