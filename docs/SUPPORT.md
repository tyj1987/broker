# Secret Broker — Support Tiers

> **Version**: applies to Secret Broker v4.5.0+
> **Last updated**: 2026-09-11

## Tier Comparison

| Tier | Price | Response — P1 (broker down) | Response — P2 (degraded) | Response — P3 (question) | Channels |
|---|---|---|---|---|---|
| **Community** | Free | none | none | none | GitHub Issues, Discussions |
| **Standard** | included with Small commercial license | 1 business day | 3 business days | 5 business days | Email |
| **Pro** | included with Medium commercial license | 4 business hours | 1 business day | 2 business days | Email + Slack/Teams |
| **Enterprise** | included with Large / Enterprise license | 1 hour (24/7) | 4 business hours | 1 business day | Email + Slack/Teams + phone |

P1 = production broker down or major feature broken
P2 = degraded operation (some features unavailable)
P3 = usage question or non-urgent change request

## Channels

### Community (free)

- **GitHub Issues** — bug reports, feature requests
- **GitHub Discussions** — questions, share patterns
- **Discord `#broker`** — community chat (placeholder link, no invite yet)

Response is best-effort from maintainers and community.

### Standard / Pro / Enterprise (paid)

Email `support@broker.example.com` (placeholder). For Pro / Enterprise,
a shared Slack or Teams channel is provisioned during onboarding.

## Security Issues

**Do not report security issues through normal support channels.**

See [`SECURITY.md`](../SECURITY.md) for responsible-disclosure instructions
and the $5,000 bug-bounty program.

## Severity Definitions

### P1 — Critical (response per SLA above)

- Broker is down (won't start, won't accept connections)
- Authentication is bypassable (mTLS / session / API key broken)
- Secrets are exposed in audit logs, error messages, or responses
- Private keys / SOPS keys are at risk of compromise

### P2 — High

- One specific feature broken in production (e.g., healthcheck for one
  provider failing; rotation for one type stuck)
- Performance degraded beyond acceptable (e.g., p95 latency > 5s)
- A documented feature is missing or behaves differently from spec

### P3 — Normal

- Usage questions
- Non-urgent change requests
- Cosmetic issues
- Documentation gaps

## Service Level Agreement (Enterprise)

For Enterprise tier, the following applies:

- **Uptime commitment**: 99.9% monthly, excluding planned maintenance.
  Maintenance windows announced ≥ 7 days in advance.
- **Disaster recovery RTO**: ≤ 60 minutes (target ≤ 30 minutes)
- **Disaster recovery RPO**: ≤ 15 minutes (target ≤ 5 minutes)
- **Backup retention**: 30 days encrypted age-key backup + 90 days
  audit log retention

If we miss the uptime SLA in a calendar month, you receive a service credit
equal to one month of your annual fee, applied to the next invoice.

## Self-Service Resources

Before opening a support ticket, please consult:

- [`docs/FAQ.md`](FAQ.md) — common questions
- [`docs/RUNBOOK.md`](../RUNBOOK.md) — incident response procedures
- [`docs/SECURITY-AUDIT-2026-09-05.md`](SECURITY-AUDIT-2026-09-05.md) —
  known limitations
- [`broker/dashboard/llms.txt`](../broker/dashboard/llms.txt) — AI agent
  prompt for automated troubleshooting
- `/health` and `/metrics` endpoints on your own broker — first place to
  look when diagnosing

## Out of Scope

Support does not cover:

- Custom feature development (commercial quote required)
- Migration from your existing secret store (assistance available at Pro /
  Enterprise rates)
- Compliance certifications (we provide documentation; you certify)
- Provider-side incidents (GitHub / Aliyun / etc. outages are not our SLA)

## Contact

| Purpose | Channel |
|---|---|
| Bug / security | GitHub Security Advisory (preferred) or `security@broker.example.com` |
| Support request (paid tiers) | `support@broker.example.com` |
| Sales / licensing | `licensing@broker.example.com` |
| General | GitHub Discussions |
