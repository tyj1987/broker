# SOC 2 Trust Services Criteria — Control Mapping (2026-09-06)

> **Status**: P1 #4 partial — Trust Services Criteria 控制映射文档, 不是 Type 1 report。
> **ROADMAP**: target 2026-12-15 (control docs + evidence collection + pen test + auditor + fix + submit)
> **Source**: [ROADMAP-post-1.0.md §4](../ROADMAP-post-1.0.md#4-soc-2-type-1-readiness-w33-w40)
> **Audit basis**: broker V4.1.0 baseline (commit `9d275dc`, master HEAD) — pre-V4.1.1-patch

---

## 1. Scope

This document maps **AICPA Trust Services Criteria (TSC 2017, updated 2022)**
to Secret Broker V4.1.0 features + code. The TSC has 5 categories, 33
criteria total, plus the 9 common criteria (CC1-CC9).

**Service**: Secret Broker V4.1.0 (self-hosted mTLS credential proxy for AI clients)
**System boundary**: broker server + CLI + 4 SDKs (Node / Python / Go / VSCode)
**Out of scope**: cloud marketplace images, Tauri desktop (P2 #6 partial), mobile clients (P3 #11)
**Reference baseline**: [docs/THREAT-MODEL.md](THREAT-MODEL.md) + [docs/SECURITY-AUDIT-2026-09-05.md](SECURITY-AUDIT-2026-09-05.md) + [docs/SECURITY-CONTROLS-ISO27001.md](SECURITY-CONTROLS-ISO27001.md) (sister doc)

## 2. Trust Services Categories

The 5 Trust Services Categories (in addition to Common Criteria CC1-CC9):

- **A.1 Additional criteria for availability** (4 criteria: A1.1-A1.3)
- **C.1 Additional criteria for confidentiality** (2 criteria: C1.1-C1.2)
- **PI.1 Additional criteria for processing integrity** (10 criteria: PI1.1-PI1.5)
- **P.1-P.8 Additional criteria for privacy** (18 criteria) — **out of scope for broker** (broker is non-PII by design)
- **Confidentiality** (broker processes secrets, not PII — focus on C, not P)

**Selected scope for broker SOC 2 Type 1**:
- **CC1-CC9 Common Criteria** (mandatory)
- **A1.1-A1.3 Availability** (broker is critical infrastructure for AI agents)
- **C1.1-C1.2 Confidentiality** (broker holds credentials, must be confidential)

**Excluded**:
- **PI1.1-PI1.5 Processing Integrity** — broker is a proxy, not a transactional system; processing integrity is downstream (GitHub / OpenAI / etc. handle their own)
- **P1.1-P8.1 Privacy** — broker is **non-PII by design** (no personal data; secrets are service credentials)

## 3. Common Criteria (CC1-CC9, mandatory for all SOC 2)

### CC1 — Control Environment

| Criterion | Title | Status | Implementation |
|-----------|-------|--------|----------------|
| CC1.1 | Commitment to integrity & ethical values | ⏳ | [SECURITY.md](../SECURITY.md) + Code of Conduct pending P1 #4 |
| CC1.2 | Board of directors exercises oversight | ⏳ | Single maintainer (tyj1987); formal board/committee pending |
| CC1.3 | Establishes structure, authority & responsibility | 🔄 | [ROADMAP-post-1.0.md](../ROADMAP-post-1.0.md) — P0-P3 优先级 + responsible party; formal org chart pending P1 #4 |
| CC1.4 | Demonstrates commitment to competence | ⏳ | Maintainer = tyj1987 (6+ years self-host); formal competence matrix pending |
| CC1.5 | Enforces accountability | ✅ | [docs/SECURITY-AUDIT-2026-09-05.md](../docs/SECURITY-AUDIT-2026-09-05.md) — dual control (WebAuthn 2-person approval with distinct physical key IDs) |
| CC1.6, CC1.7, CC1.8, CC1.9, CC1.10 | (various) | ⏳ | Pending P1 #4 |

### CC2 — Communication & Information

| Criterion | Title | Status | Implementation |
|-----------|-------|--------|----------------|
| CC2.1 | Information to support functioning of internal control | ✅ | [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) + [docs/DESIGN-V4-SECURITY-MODEL.md](../docs/DESIGN-V4-SECURITY-MODEL.md) + [docs/THREAT-MODEL.md](../docs/THREAT-MODEL.md) |
| CC2.2 | Internal communication | 🔄 | Maintainer direct + GitHub Discussions; formal internal comm channel pending |
| CC2.3 | External communication | ✅ | [SECURITY.md](../SECURITY.md) (security@broker.example.com, 48h SLA, $5k bug bounty) + [docs/FAQ.md](../docs/FAQ.md) + [docs/QUICKSTART.md](../docs/QUICKSTART.md) |
| CC2.4, CC2.5, CC2.6 | (various) | ⏳ | Pending P1 #4 |

### CC3 — Risk Assessment

| Criterion | Title | Status | Implementation |
|-----------|-------|--------|----------------|
| CC3.1 | Specifies objectives | ✅ | [ROADMAP-post-1.0.md](../ROADMAP-post-1.0.md) §"Decision drivers" — Bug Bounty / customer request / OpenSSF / CVE triggers |
| CC3.2 | Identifies risks | ✅ | [docs/THREAT-MODEL.md](../docs/THREAT-MODEL.md) — 6 trust boundaries, 6 attack paths |
| CC3.3 | Assesses risks (likelihood + impact) | 🔄 | [docs/SECURITY-AUDIT-2026-09-05.md](../docs/SECURITY-AUDIT-2026-09-05.md) — "Verdict: NOT APPROVED FOR PRODUCTION" + remediation list; formal risk register pending P1 #4 |
| CC3.4 | Identifies & assesses changes | ✅ | [ROADMAP-post-1.0.md](../ROADMAP-post-1.0.md) — version 4.1.0, 4.1.1, 4.2.0, 5.0.0 timeline; semver discipline |
| CC3.5, CC3.6, CC3.7 | (various) | ⏳ | Pending P1 #4 |

### CC4 — Monitoring Activities

| Criterion | Title | Status | Implementation |
|-----------|-------|--------|----------------|
| CC4.1 | Selects & develops ongoing or separate evaluations | ✅ | [docs/SECURITY-AUDIT-2026-09-05.md](../docs/SECURITY-AUDIT-2026-09-05.md) — local audit at baseline; [docs/PHASE-D-TRACING-AUDIT.md](../docs/PHASE-D-TRACING-AUDIT.md) — ongoing audit logs |
| CC4.2 | Evaluates & communicates internal control deficiencies | 🔄 | [docs/SECURITY-AUDIT-2026-09-05.md](../docs/SECURITY-AUDIT-2026-09-05.md) — explicit "NOT APPROVED FOR PRODUCTION" verdict; formal deficiency tracking pending P1 #4 |
| CC4.3, CC4.4 | (various) | ⏳ | Pending P1 #4 |

### CC5 — Control Activities

| Criterion | Title | Status | Implementation |
|-----------|-------|--------|----------------|
| CC5.1 | Selects & develops control activities | ✅ | [docs/THREAT-MODEL.md](../docs/THREAT-MODEL.md) + this document + [SECURITY-CONTROLS-ISO27001.md](SECURITY-CONTROLS-ISO27001.md) |
| CC5.2 | Selects & develops general controls over technology | ✅ | [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) + [docs/DESIGN-V4-SECURITY-MODEL.md](../docs/DESIGN-V4-SECURITY-MODEL.md) + typed-operation policy decision point |
| CC5.3 | Deploys through policies & procedures | ✅ | [RUNBOOK.md](../RUNBOOK.md) + [DEPLOY-52TRZ.md](../DEPLOY-52TRZ.md) + [POST-DEPLOY-CHECKLIST.md](../POST-DEPLOY-CHECKLIST.md) (11-step) |
| CC5.4, CC5.5 | (various) | ⏳ | Pending P1 #4 |

### CC6 — Logical & Physical Access Controls

| Criterion | Title | Status | Implementation |
|-----------|-------|--------|----------------|
| CC6.1 | Logical access security software, infrastructure & architectures | ✅ | mTLS only (TLS 1.2+); loopback-only backend bind; nginx TLS edge; 6 auth factors; RBAC; default-deny API keys; resource-grant intersection |
| CC6.2 | Prior authorization for new/modified access | ✅ | WebAuthn 2-person approval for create/update/delete; dual control with distinct physical key IDs; client update requires mTLS + 2-person approval |
| CC6.3 | Removes access when appropriate | ✅ | Client deletion/role downgrade/cert fingerprint change → all sessions invalidated; revoking parent API key → all children invalidated |
| CC6.4 | Restricts physical access | ❌ | Out of scope (cloud-provider) |
| CC6.5 | Discontinues logical & physical protections | 🔄 | `migrate-v3-to-v4.sh` creates rollback; secrets in `.gitignore`; formal asset disposal pending |
| CC6.6 | Implements logical access security measures | ✅ | 6 auth factors; mTLS + WebAuthn AAL3 hardware-only; TOTP RFC 6238 with counter; recovery codes one-time; rate limiting; IP allowlist |
| CC6.7 | Restricts transmission of information | ✅ | mTLS only; signed binaries (V4.1.0 GitHub Release + SHA-256); TLS 1.2+; no plain HTTP |
| CC6.8 | Prevents or detects/acts on unauthorized/malicious software | ✅ | npm audit (clean); gitleaks history scan; pinned GitHub Actions (40-char SHA); release-candidate workflow gates on security-coverage + supply-chain + SBOM + Cosign |
| CC6.9, CC6.10, CC6.11, CC6.12 | (various) | ⏳ | Pending P1 #4 |

### CC7 — System Operations

| Criterion | Title | Status | Implementation |
|-----------|-------|--------|----------------|
| CC7.1 | Detects & acts on vulnerabilities | ✅ | `npm audit --omit=dev` (clean); pinned GitHub Actions; release-candidate workflow; SECURITY-AUDIT 2026-09-05 (desensitized) |
| CC7.2 | Monitors components & operation | ✅ | WebSocket push (audit/healthcheck/alerts/secret_rotated/mfa_enrolled/config_reloaded); 4-hour healthcheck auto-probes; structured JSON audit logs |
| CC7.3 | Detects/responds to security incidents | ✅ | [RUNBOOK.md](../RUNBOOK.md) §6 — incident response playbooks (broker down / mTLS fail / secret leak / key rotation) |
| CC7.4 | Responds to identified security incidents | ✅ | Rotate cert / revoke client / disable client / kill session / SOPS decrypt; alert escalation (severity_gte) |
| CC7.5 | Recovers from identified security incidents | ✅ | [docs/PHASE-F-BACKUP-PROBES.md](../docs/PHASE-F-BACKUP-PROBES.md) — backup manifest + age key + rollback.sh |
| CC7.6, CC7.7, CC7.8, CC7.9 | (various) | ⏳ | Pending P1 #4 |

### CC8 — Change Management

| Criterion | Title | Status | Implementation |
|-----------|-------|--------|----------------|
| CC8.1 | Authorizes, designs, develops, tests changes | ✅ | PR review; [docs/VERIFY.md](../docs/VERIFY.md) — 647/0 tests; signed-release gate; security-coverage gate; supply-chain gate |
| CC8.2 | Tracks changes | ✅ | [ROADMAP-post-1.0.md](../ROADMAP-post-1.0.md); [CHANGELOG.md](../CHANGELOG.md); git log + signed commits |
| CC8.3 | Tests changes before deployment | ✅ | [docs/VERIFY.md](../docs/VERIFY.md); [docs/POST-DEPLOY-CHECKLIST.md](../POST-DEPLOY-CHECKLIST.md) (11-step) |
| CC8.4, CC8.5 | (various) | ⏳ | Pending P1 #4 |

### CC9 — Risk Mitigation

| Criterion | Title | Status | Implementation |
|-----------|-------|--------|----------------|
| CC9.1 | Identifies, selects & develops risk mitigation activities | ✅ | [docs/THREAT-MODEL.md](../docs/THREAT-MODEL.md) — 6 attack paths + 6 controls; [ROADMAP-post-1.0.md](../ROADMAP-post-1.0.md) §"Out of scope" — explicit limitations |
| CC9.2 | Vendor & business partner risk | ⏳ | npm / Node.js / SOPS / age are 3rd-party; formal vendor risk register pending P1 #4 |

## 4. A. Additional criteria for Availability

| Criterion | Title | Status | Implementation |
|-----------|-------|--------|----------------|
| A1.1 | Maintains, monitors & evaluates current processing capacity | ✅ | [docs/PHASE-F-BACKUP-PROBES.md](../docs/PHASE-F-BACKUP-PROBES.md) — 4-hour healthcheck probes; WebSocket push; alert thresholds |
| A1.2 | Environmental protections, software, data backup, recovery | ✅ | [docs/PHASE-F-BACKUP-PROBES.md](../docs/PHASE-F-BACKUP-PROBES.md); `rollback.sh`; SOPS-encrypted secrets; gitignored audit |
| A1.3 | Tests recovery plan procedures | ⏳ | Recovery procedures documented; disaster-recovery rehearsal pending P1 #4 |

## 5. C. Additional criteria for Confidentiality

| Criterion | Title | Status | Implementation |
|-----------|-------|--------|----------------|
| C1.1 | Identifies confidential information | ✅ | `secrets/secrets-detail.json` SOPS-encrypted; `broker/lib/redact.js` (12+ patterns); strict-mode secret listings `[REDACTED]`; audit logs redacted |
| C1.2 | Disposes of, retains & protects confidential information | ✅ | `migrate-v3-to-v4.sh` creates rollback; secrets in `.gitignore`; no plaintext fallback; `gitleaks` history scan in release workflow |

## 6. PI. Additional criteria for Processing Integrity (out of scope, see §2)

broker is a **proxy** — processing integrity is the responsibility of
downstream services (GitHub, OpenAI, AWS, etc.). Not in scope.

## 7. P. Additional criteria for Privacy (out of scope, see §2)

broker is **non-PII by design**:
- Secrets stored are **service credentials** (GitHub PAT, OpenAI key, AWS key)
- **No personal data** (no user names, no emails, no addresses, no SSN)
- Authentication metadata (WebAuthn credential ID, mTLS fingerprint) is **cryptographic hash, not PII**

## 8. Summary

| Category | Total | Implemented | Partial | Planned | Out of scope |
|----------|-------|-------------|---------|---------|--------------|
| CC1 Control Environment | 10 | 1 | 1 | 8 | 0 |
| CC2 Communication & Information | 6 | 2 | 1 | 3 | 0 |
| CC3 Risk Assessment | 7 | 3 | 1 | 3 | 0 |
| CC4 Monitoring | 4 | 1 | 1 | 2 | 0 |
| CC5 Control Activities | 5 | 3 | 0 | 2 | 0 |
| CC6 Logical & Physical Access | 12 | 7 | 1 | 3 | 1 |
| CC7 System Operations | 9 | 5 | 0 | 4 | 0 |
| CC8 Change Management | 5 | 3 | 0 | 2 | 0 |
| CC9 Risk Mitigation | 2 | 1 | 0 | 1 | 0 |
| A1 Availability | 3 | 2 | 0 | 1 | 0 |
| C1 Confidentiality | 2 | 2 | 0 | 0 | 0 |
| **Total in scope** | **65** | **30** | **5** | **29** | **1** |

- **Implemented (30/65, 46%)**: core controls in place (mTLS, audit, change mgmt, encryption, etc.)
- **Partial (5/65, 8%)**: control partially implemented, gap documented
- **Planned (29/65, 45%)**: deferred to ROADMAP P1 #4 (governance / policies / formal auditor engagement)
- **Out of scope (1/65, 2%)**: physical (CC6.4) — cloud-provider

## 9. Gap analysis (Partial + Planned → Implementation plan)

**Quick wins (1-2 weeks, 1 commit each)**:
- CC1.1 / CC1.2 / CC1.3 Code of Conduct + governance doc
- CC1.6 / CC1.7 / CC1.8 / CC1.9 / CC1.10 org chart + competence matrix + accountability
- CC2.2 / CC2.4 / CC2.5 / CC2.6 internal comm + change comm
- CC3.3 / CC3.5 / CC3.6 / CC3.7 risk register + formal change review
- CC4.2 / CC4.3 / CC4.4 deficiency tracking + remediation tracking
- CC5.4 / CC5.5 segregation of duties + control environment
- CC6.5 / CC6.9 / CC6.10 / CC6.11 / CC6.12 asset disposal + remote access + encryption at rest
- CC7.6 / CC7.7 / CC7.8 / CC7.9 security awareness + threat intel + DR rehearsal
- CC8.4 / CC8.5 change advisory board + post-deployment review
- CC9.2 vendor risk register

**Heavy work (4-6 weeks)**:
- **Third-party pen test**: commission accredited firm (NCC Group / Trail of Bits / Cure53), $30-80k
- **Auditor engagement**: Big 4 (Deloitte / EY / PwC / KPMG) or mid-tier (Schellman / A-LIGN), $50-150k
- **SOC 2 Type 1 report**: ~3 month observation window + report delivery

**Total budget estimate**: $80-230k for SOC 2 Type 1 readiness + report.

## 10. Type 1 vs Type 2

- **Type 1**: as-of-date audit (e.g. "as of 2026-12-15, controls are designed + operating effectively"). Cheaper, faster.
- **Type 2**: 6-12 month observation window. More credible, more expensive.

ROADMAP target 2026-12-15 = **Type 1** (one-time point audit, no observation period needed).

## 11. Limitations

- This is a **self-assessment**, not a third-party audit.
- "Implemented" assumes the operator enables all features (mTLS, 2-person approval, WebAuthn, etc.). A deployment with `compatibility` profile only would have lower coverage.
- SOC 2 Type 1 report is the **auditor's opinion** on the operating effectiveness of controls at a point in time. This document is the **input**, not the output.
- The broker is **not** the customer's system — operators deploying broker in their own environment must map their org's controls to this document.

## 12. Refs

- [ROADMAP-post-1.0.md §4](../ROADMAP-post-1.0.md#4-soc-2-type-1-readiness-w33-w40)
- [docs/THREAT-MODEL.md](../docs/THREAT-MODEL.md)
- [docs/SECURITY-AUDIT-2026-09-05.md](../docs/SECURITY-AUDIT-2026-09-05.md)
- [docs/SECURITY-CONTROLS-ISO27001.md](SECURITY-CONTROLS-ISO27001.md) (sister doc for ISO 27001)
- [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md)
- [docs/DESIGN-V4-SECURITY-MODEL.md](../docs/DESIGN-V4-SECURITY-MODEL.md)
- [RUNBOOK.md](../RUNBOOK.md)
- [docs/PHASE-F-BACKUP-PROBES.md](../docs/PHASE-F-BACKUP-PROBES.md)
- [AICPA Trust Services Criteria](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2)

## 13. License

This document is licensed under MIT — see [LICENSE](../LICENSE).
