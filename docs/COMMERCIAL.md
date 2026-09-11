# Secret Broker — Commercial Policy

> **Version**: applies to Secret Broker v4.5.0+
> **Last updated**: 2026-09-11

Secret Broker v4.5.0 is dual-licensed:

- **Open-source**: MIT (see [`LICENSE`](../LICENSE) for full text).
- **Commercial**: required for revenue-generating, multi-tenant, embedded,
  or managed-service use (see below).

## Open-Source Use (MIT)

Free, no strings attached, for:
- Personal projects, learning, and research
- Internal evaluation and testing
- Open-source projects that ship the broker as a tool their users run themselves
- Educational institutions
- Non-profit and government internal use

## Commercial Use (License Required)

A separate commercial license is required when the broker is used in any of
the following contexts:

| Use case | Commercial license required? |
|---|---|
| Self-hosted SaaS (you charge customers to use your broker) | **Yes** |
| Embedding the broker in a commercial product or appliance | **Yes** |
| Operating a managed broker service for paying customers | **Yes** |
| Multi-tenant broker hosting where the operator charges per tenant | **Yes** |
| Internal use by a for-profit organization | **Yes** (see Volume tiers below) |
| Internal use by a non-profit / government / educational org | No (MIT) |

### Volume Tiers (Internal Use)

| Tier | Seats / secrets | Annual fee |
|---|---|---|
| Small | ≤ 10 client certs, ≤ 50 secrets | USD 5,000 |
| Medium | ≤ 50 client certs, ≤ 500 secrets | USD 15,000 |
| Large | unlimited | USD 45,000 |
| Enterprise | unlimited + SLA | Contact us |

These tiers apply to **internal** use only; SaaS / OEM use is priced separately.

### What the Commercial License Includes

- Legal indemnification
- Right to use in revenue-generating contexts
- SLA-backed support response times (see [`SUPPORT.md`](SUPPORT.md))
- Access to pre-built cloud-marketplace images (Aliyun / Tencent / AWS / Azure / GCP)
- Right to redistribute as part of a commercial product

## What's NOT Covered by Commercial License

- The broker source code itself (still MIT for open-source use)
- Bug-bounty awards (open to all, see [`SECURITY.md`](../SECURITY.md))
- Community Discord / GitHub Discussions support (free for all)

## How to Obtain a Commercial License

Email `licensing@broker.example.com` (placeholder — replace before public launch)
with:
- Company name and jurisdiction
- Use case (SaaS / OEM / internal / managed)
- Estimated scale (client certs, secrets, MAU)

We respond within 2 business days with a term sheet and pricing.

## Roadmap to Wider Availability

- **2026 Q4**: Cloud marketplace images (Aliyun / Tencent / AWS / Azure / GCP)
  with one-click deploy and built-in license metering.
- **2027 Q1**: SOC 2 Type 1 report and ISO 27001 Annex A mapping
  (required for many enterprise customers).
- **2027 Q2**: Multi-tenant broker with per-tenant quotas, billing API, and
  Stripe integration.

These are tracked in [`ROADMAP-post-1.0.md`](../ROADMAP-post-1.0.md).

## Compliance Notes

The broker is designed to support customer compliance programs:

| Customer program | Broker support |
|---|---|
| SOC 2 (CC6, CC7) | mTLS, audit log, MFA, RBAC, rate limit — see [`docs/DESIGN-V4-SECURITY-MODEL.md`](DESIGN-V4-SECURITY-MODEL.md) |
| ISO 27001 (A.9, A.10, A.12, A.13) | Access control, cryptography, audit, secure development — see [THREAT-MODEL.md](THREAT-MODEL.md) |
| HIPAA (security rule) | Encryption in transit + at rest (SOPS), access logging, MFA |
| PCI DSS 4.0 (Req 3, 8, 10) | Vault architecture, MFA, audit log retention, tamper-evidence |

A formal SOC 2 Type 1 report is not yet available (planned Q4 2026). Until
then, customers can self-attest using the design docs and threat model.

## Open Questions

- **OEM / embedded redistribution pricing** — varies by reach; contact us.
- **Federal / government use** — FIPS-validated cryptography is on the
  v5+ roadmap but not yet implemented.
- **Air-gapped deployments** — supported, but license validation requires
  offline token activation.
