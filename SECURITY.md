# Security Policy

## Supported Versions


> **Languages**: [English](SECURITY.md) · [中文](SECURITY.zh-CN.md)
| Version | Supported |
|---------|-----------|
| `master` | Security fixes during pre-release development |
| Tagged releases | Not yet supported for production use |

## Reporting a Vulnerability

**Please do not file public GitHub issues for security vulnerabilities.**

Use [GitHub private vulnerability reporting](https://github.com/tyj1987/broker/security/advisories/new).
Include affected versions, impact, prerequisites, and a minimal reproduction.
Do not include real credentials or test against production systems.

No public bounty or response-time commitment is offered unless it is announced
through the repository's verified security page.

## Security Architecture

For the full design, see
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

Key properties:

- **Typed operations**: strict-profile automation is limited to versioned
  provider operations rather than caller-provided URLs or headers.
- **Authenticated transport**: the public reverse proxy validates external
  client certificates and uses a separate workload certificate upstream.
- **Defense in depth**: WebAuthn, short sessions, scoped workload identities,
  request policy, rate limits, and revocation are independent controls.
- **Explicit egress**: provider calls, identity exchange and alert delivery
  must be allowlisted and are covered by outbound policy and audit events.

## Threat Model

| Adversary | In scope | Defense |
|-----------|----------|---------|
| Network attacker (passive) | Yes | TLS 1.3 |
| Network attacker (active MITM) | Yes | mTLS + CA pinned to clients |
| Compromised client cert | Yes | Revocation, scoped policy, short sessions, and workload identity |
| Malicious AI agent (untrusted model output) | **Primary** | Proxy mode, redaction engine, no raw secrets to AI |
| Insider (broker admin) | Limited | All admin actions audited; SOPS-encrypted at rest with age/PGP key escrow |
| Compromised broker server | Limited | Encrypted storage, host hardening, minimal workload identity, rotation, and external audit copies |
| Compromised K8s node | Residual risk | Node isolation, envelope encryption, short-lived identities, rotation, and external audit copies reduce but do not eliminate impact |

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

- **mTLS**: TLS 1.3; certificates chain to the configured private CA and are revocable
- **SOPS**: age (recommended) or PGP; see
  [DESIGN-V4-SECURITY-MODEL § Cryptography](docs/THREAT-MODEL.md)
- **Hashing**: SHA-256 (audit chains); password verifiers use the configured password KDF
- **CSPRNG**: Node `crypto.randomBytes` (used for session tokens, MFA codes)

## Audit logs

The broker writes structured append-only audit events to its configured audit
sink. Local development defaults to `audit/YYYY-MM-DD.jsonl`. Each event includes:

- `action` (e.g. `secret.resolve`, `auth.login`, `ssh_exec`)
- `cn` (client common name from mTLS cert)
- `ts` (ISO 8601 UTC)
- `request_id` (for cross-referencing with traces)
- `redacted_payload` (auto-redacted by the redact engine)

Audit chains are signed daily with a SHA-256 hash chain. Tampering with
historical entries is detectable on verification.
