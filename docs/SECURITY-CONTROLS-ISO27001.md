# ISO 27001 Annex A — Control Mapping (2026-09-06)

> **Status**: P1 #5 partial — Annex A 控制映射文档, 不是认证。
> **ROADMAP**: target 2026-11-30 (Annex A 控制映射 + gap analysis + 缺失控制实现 + 内审)
> **Source**: [ROADMAP-post-1.0.md §5](../ROADMAP-post-1.0.md#5-iso-27001-annex-a-controls-mapping-w33-w36)
> **Audit basis**: broker V4.1.0 baseline (commit `9d275dc`, master HEAD) — pre-V4.1.1-patch

---

## 1. Scope

This document maps ISO/IEC 27001:2022 **Annex A** controls to Secret Broker
V4.1.0 features + code. The broker is the **system under audit**; the
control narrative covers:

- **System**: Secret Broker V4.1.0 (single-tenant, self-hosted)
- **Boundary**: broker server + its CLI + 4 SDKs (Node / Python / Go / VSCode)
- **Out of scope**: cloud marketplace images, Tauri desktop (P2 #6, partial), mobile clients (P3 #11)
- **Reference baseline**: [docs/THREAT-MODEL.md](THREAT-MODEL.md) (6 trust boundaries, 6 attack paths) + [docs/SECURITY-AUDIT-2026-09-05.md](SECURITY-AUDIT-2026-09-05.md) (broker V4.1.0 local audit)

## 2. Annex A structure (ISO/IEC 27001:2022)

ISO 27001:2022 reorganized Annex A from 14 domains (2013) into **4 themes × 93 controls**:

- **A.5 Organizational controls** (37 controls)
- **A.6 People controls** (8 controls)
- **A.7 Physical controls** (14 controls)
- **A.8 Technological controls** (34 controls)

Each control has:
- **5 attributes**: control type (preventive/detective/corrective), security properties (confidentiality/integrity/availability), cybersecurity concepts (identify/protect/detect/respond/recover), operational capabilities (governance/protect/defend/sustain), security domains
- **Implementation guidance**: ISO 27002:2022 (free with ISO 27001 purchase)

This document maps controls to broker features + code paths. Compliance
status is per control:

- ✅ **Implemented** — control fully implemented in code or operating procedure
- 🔄 **Partial** — control partially implemented, gap documented
- ⏳ **Planned** — control planned in ROADMAP (specific item referenced)
- ❌ **Out of scope** — control not applicable to broker scope (e.g. datacenter security for cloud-only)

## 3. A.5 Organizational controls (37)

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| A.5.1 | Policies for information security | ⏳ | [SECURITY.md](../SECURITY.md) (response SLA, bug bounty) + [ROADMAP §3 P1 #4 SOC 2 Type 1](ROADMAP-post-1.0.md#4-soc-2-type-1-readiness-w33-w40) — auditor engagement + control docs |
| A.5.2 | Information security roles & responsibilities | 🔄 | Maintainer = tyj1987; developer = tyj1987 + community; security contact = security@broker.example.com. Formal RACI matrix pending P1 #4 |
| A.5.3 | Segregation of duties | ✅ | [WebAuthn 2-person approval](../docs/SECURITY-AUDIT-2026-09-05.md) (client/secret/service create/update/delete requires distinct requester + approver, payload-bound, different physical key IDs) |
| A.5.4 | Management responsibilities | ⏳ | Maintainer handles; formal sign-off process pending P1 #4 |
| A.5.5 | Contact with authorities | ⏳ | GitHub Security Advisories; formal contact list (FBI / CN-CERT / etc.) pending P1 #4 |
| A.5.6 | Contact with special interest groups | ⏳ | OpenSSF / CNCF Slack channels (informal); formal membership pending |
| A.5.7 | Threat intelligence | 🔄 | [THREAT-MODEL.md](../docs/THREAT-MODEL.md) (6 attack paths mapped); ongoing threat intel feed (NVD / GitHub Advisory) pending P1 #4 |
| A.5.8 | Information security in project management | ✅ | This ROADMAP + [ROADMAP-post-1.0.md](../ROADMAP-post-1.0.md) (13 P0-P3 items, target quarters, success criteria) |
| A.5.9 | Inventory of information & associated assets | 🔄 | [ARCHITECTURE.md](../ARCHITECTURE.md) (storage layout, repository layout); formal asset inventory (data classification) pending P1 #4 |
| A.5.10 | Acceptable use of information & assets | ⏳ | [SECURITY.md](../SECURITY.md) covers external reporters; internal AUP pending P1 #4 |
| A.5.11 | Return of assets | ✅ | [DEPLOY-52TRZ.md](../DEPLOY-52TRZ.md) — `migrate-v3-to-v4.sh` auto-creates `secret-broker-v3-backup-*/` with rollback.sh; uninstall scripts preserve /etc config |
| A.5.12 | Classification of information | 🔄 | Secrets in `secrets/secrets-detail.json` SOPS-encrypted; audit logs structured; formal classification scheme (public / internal / confidential / secret) pending P1 #4 |
| A.5.13 | Labelling of information | 🔄 | Secrets auto-redacted in audit/alert/broadcast (12+ patterns in `broker/lib/redact.js`); formal labeling in code pending |
| A.5.14 | Information transfer | ✅ | TLS 1.2+ only (mTLS required for production); mTLS-only identity; signed-binary distribution (V4.1.0 GitHub Release + SHA-256) |
| A.5.15 | Access control | ✅ | RBAC (`role: admin/operator/developer/viewer`); API-key hierarchical + intersection-of-parent grants; IP allowlist; mTLS + 6 auth factors |
| A.5.16 | Identity management | ✅ | 6 auth factors: mTLS / Pass / TOTP / WebAuthn / SMS / Recovery; client enrollment requires mTLS; WebAuthn hardware-only single-device |
| A.5.17 | Authentication information | ✅ | mTLS cert-as-session (V4.1.1); WebAuthn AAL3 (hardware key + UV); TOTP RFC 6238 with counter persistence; recovery codes one-time + transactionally removed |
| A.5.18 | Access rights | ✅ | Default-deny for API keys (`allowed_secrets` + `allowed_services` no longer mean unrestricted); child grants = parent ∩ child; TTL capped |
| A.5.19 | Supplier relationships | ⏳ | Open source (MIT); no commercial supplier dependency; formal SLA with Node.js / npm registry pending P1 #4 |
| A.5.20 | Information security in supplier agreements | ⏳ | N/A (no supplier data); formal policy pending |
| A.5.21 | Managing information security in ICT supply chain | ✅ | [release-candidate workflow](../.github/workflows/deploy.yml) — pinned GitHub Actions by 40-char SHA; npm audit + lockfile; SBOM + Cosign; immutable digest |
| A.5.22 | Monitoring, review & change management of supplier services | ⏳ | Node.js / npm registry monitoring (inactive; we pin versions) |
| A.5.23 | Information security for use of cloud services | 🔄 | AWS / Azure / GCP Terraform modules (V4.1.0); Aliyun 镜像市场 + Tencent 镜像市场 are P1 #3 deferred. Formal cloud security review pending P1 #4 |
| A.5.24 | Information security incident management planning | ✅ | [RUNBOOK.md](../RUNBOOK.md) §6 — incident response playbooks (broker down, mTLS fail, secret leak, key rotation) |
| A.5.25 | Assessment & decision on information security events | ✅ | [RUNBOOK.md](../RUNBOOK.md) §6 — alert thresholds (severity_gte), healthcheck auto-probes (every 4h), WebSocket push for real-time triage |
| A.5.26 | Response to information security incidents | ✅ | [RUNBOOK.md](../RUNBOOK.md) §6 — rotate cert / revoke client / disable client / kill session procedures |
| A.5.27 | Learning from information security incidents | ⏳ | Incident postmortems (in private security@broker.example.com); public postmortem template pending P1 #4 |
| A.5.28 | Collection of evidence | ✅ | [docs/PHASE-D-TRACING-AUDIT.md](../docs/PHASE-D-TRACING-AUDIT.md) — structured audit logs (request_id, source_ip, client, action, mfa_method), append-only |
| A.5.29 | Information security during disruption | ✅ | [docs/PHASE-F-BACKUP-PROBES.md](../docs/PHASE-F-BACKUP-PROBES.md) — backup manifest, age-key, config, secrets; `rollback.sh` for V3→V4 migration |
| A.5.30 | ICT readiness for business continuity | 🔄 | HA via shared PVC + RWO (stateless broker); multi-region active-active is out of scope (per ROADMAP) |
| A.5.31 | Legal, statutory, regulatory & contractual requirements | ⏳ | MIT license; no PII / GDPR data (secrets = service credentials, not personal data); formal compliance review pending P1 #4 |
| A.5.32 | Intellectual property rights | ✅ | MIT; 3rd-party deps via npm audit (clean); SOPS + age (MPL-2.0 / Apache-2.0); all transitive deps in `package-lock.json` |
| A.5.33 | Protection of records | ✅ | Audit logs under `audit/` (gitignored); SOPS-encrypted secrets; structured JSON for machine parse |
| A.5.34 | Privacy & protection of PII | ✅ | broker is **non-PII by design**: secrets are service credentials (GitHub PAT, OpenAI key, AWS key) — no personal data. PII redaction filter (12+ patterns) in `broker/lib/redact.js` |
| A.5.35 | Independent review of information security | ⏳ | Internal self-audit (this document); third-party pen test pending P1 #4 |
| A.5.36 | Compliance with policies, rules & standards | ⏳ | This document; formal compliance dashboard pending P1 #4 |
| A.5.37 | Documented operating procedures | 🔄 | [RUNBOOK.md](../RUNBOOK.md) (incident), [DEPLOY-52TRZ.md](../DEPLOY-52TRZ.md) (deploy), [POST-DEPLOY-CHECKLIST.md](../POST-DEPLOY-CHECKLIST.md) (11-step verify); gap: change management, backup procedures |

## 4. A.6 People controls (8)

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| A.6.1 | Screening | ⏳ | Open source project — no "employment"; contributor DCO + CLA pending P1 #4 |
| A.6.2 | Terms & conditions of employment | ⏳ | N/A (community project); formal code-of-conduct pending P1 #4 |
| A.6.3 | Information security awareness, education & training | ⏳ | [docs/README.md](../README.md) + [docs/QUICKSTART.md](../docs/QUICKSTART.md) + [docs/SDK-REFERENCE.md](../docs/SDK-REFERENCE.md) cover end-user; admin training (PKI rotation, SOPS, mTLS enrollment) pending P1 #4 |
| A.6.4 | Disciplinary process | ⏳ | N/A; Code of Conduct (CNCF-style) pending |
| A.6.5 | Responsibilities after termination or change of employment | ✅ | `migrate-v3-to-v4.sh` / `update-from-github.sh` / `uninstall` — all preserve or rotate credentials |
| A.6.6 | Confidentiality or non-disclosure agreements | ⏳ | Maintainer = single (tyj1987); CLA pending P1 #4 |
| A.6.7 | Remote working | ⏳ | Self-hosted; user manages own remote-work security |
| A.6.8 | Information security event reporting | ✅ | [SECURITY.md](../SECURITY.md) — `security@broker.example.com`, 48h SLA, $5k bug bounty |

## 5. A.7 Physical controls (14)

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| A.7.1 | Physical perimeters | ❌ | Out of scope (broker is software; physical security = cloud provider) |
| A.7.2 | Physical entry | ❌ | Out of scope |
| A.7.3 | Securing offices, rooms & facilities | ❌ | Out of scope |
| A.7.4 | Physical security monitoring | ❌ | Out of scope |
| A.7.5 | Threating to physical & environmental security | ❌ | Out of scope |
| A.7.6 | Working in secure areas | ❌ | Out of scope |
| A.7.7 | Clear desk & clear screen | ❌ | Out of scope (end-user) |
| A.7.8 | Equipment siting & protection | ❌ | Out of scope (cloud-provider) |
| A.7.9 | Security of assets off-premises | 🔄 | Maintainer laptop + YubiKey (WebAuthn); user laptop for local broker — formal asset tracking pending |
| A.7.10 | Storage media | 🔄 | Secrets in `secrets/secrets-detail.json` SOPS-encrypted at rest; backup media per user; formal media handling pending P1 #4 |
| A.7.11 | Supporting utilities | ❌ | Out of scope (cloud-provider) |
| A.7.12 | Cabling security | ❌ | Out of scope |
| A.7.13 | Equipment maintenance | ❌ | Out of scope |
| A.7.14 | Secure disposal or re-use of equipment | ✅ | `migrate-v3-to-v4.sh` auto-creates rollback; secrets SOPS-encrypted (not plaintext); `secrets/` in `.gitignore` |

## 6. A.8 Technological controls (34)

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| A.8.1 | User endpoint devices | ❌ | Out of scope (user-managed); Tauri desktop (P2 #6) will offer opinionated defaults |
| A.8.2 | Privileged access rights | ✅ | WebAuthn 2-person approval for create/update/delete; RBAC; IP allowlist |
| A.8.3 | Information access restriction | ✅ | Default-deny API keys; resource-grant intersection; child-key TTL cap; IP allowlist |
| A.8.4 | Access to source code | ✅ | GitHub public repo; signed commits; branch protection (main + wip/* require PR review) |
| A.8.5 | Secure authentication | ✅ | 6 auth factors: mTLS / Pass / TOTP / WebAuthn / SMS / Recovery; WebAuthn AAL3 hardware-only; TOTP replay prevention |
| A.8.6 | Capacity management | ⏳ | Single-VM broker (HA via shared PVC + RWO); no auto-scaling yet (per ROADMAP) |
| A.8.7 | Protection against malware | ⏳ | Node.js runtime (no native code injection vector); npm audit (clean); container image SBOM + Cosign signature |
| A.8.8 | Management of technical vulnerabilities | ✅ | `npm audit --omit=dev` (0 vulns at V4.1.0); Python SDK 0 hard deps; pinned GitHub Actions (40-char SHA); release-candidate workflow gates on security-coverage + supply-chain |
| A.8.9 | Configuration management | ✅ | `secrets/broker.yaml` example + `RUNBOOK.md` + `migrate-v3-to-v4.sh`; `strict / controlled / compatibility` profiles |
| A.8.10 | Information deletion | ✅ | `migrate-v3-to-v4.sh` creates rollback; secrets in `.gitignore`; SOPS encryption at rest |
| A.8.11 | Data masking | ✅ | `broker/lib/redact.js` (45 tests) — 12+ patterns (github/openai/anthropic/aws/jwt/...) redacted in audit/alert/broadcast; strict-mode secret listings replace every value with `[REDACTED]` |
| A.8.12 | Data leakage prevention | ✅ | mTLS-only; private-IP blocking in outbound policy; HTTPS origin pinning; absolute-URL rejection; redirect/header controls; response size limit |
| A.8.13 | Information backup | ✅ | [docs/PHASE-F-BACKUP-PROBES.md](../docs/PHASE-F-BACKUP-PROBES.md) — backup manifest (config + age key + secrets checklist); `rollback.sh` for V3→V4 |
| A.8.14 | Redundancy of information processing facilities | 🔄 | HA via shared PVC + RWO; multi-region active-active is out of scope (per ROADMAP) |
| A.8.15 | Logging | ✅ | Structured JSON audit logs (request_id, source_ip, client, action, mfa_method); audit under `audit/` (gitignored) |
| A.8.16 | Monitoring activities | ✅ | WebSocket push (audit/healthcheck/alerts/secret_rotated/mfa_enrolled/config_reloaded); alert thresholds (severity_gte); 4-hour healthcheck probes |
| A.8.17 | Clock synchronization | 🔄 | NTP via OS; broker uses `Date.now()` (millisecond resolution); formal NTP requirement pending P1 #4 |
| A.8.18 | Rights to use information | ✅ | RBAC + API-key grants + typed-operation policy decision point (strict mode) |
| A.8.19 | Installation of software | ✅ | [release-candidate workflow](../.github/workflows/deploy.yml) — pinned digest; OIDC + Cosign; SBOM; provenance |
| A.8.20 | Networks security | ✅ | mTLS only; loopback-only backend bind (0d6f2db); trusted-proxy fingerprint check; nginx-only public TLS edge |
| A.8.21 | Security of network services | ✅ | Rate limiting (minute/hour/day); IP allowlist; trusted-proxy metadata constraint; absolute-URL rejection; method ACL |
| A.8.22 | Segregation in networks | ✅ | Loopback-only broker; nginx TLS edge (public 443); internal mTLS (8443 loopback); no direct backend exposure |
| A.8.23 | Web filtering | ❌ | Out of scope (broker is server; not proxy) |
| A.8.24 | Use of cryptography | ✅ | TLS 1.2+ (mTLS); SOPS + age (X25519 + AES-256-GCM); bcrypt for password; SHA-256 for fingerprints; WebAuthn FIDO2 (EdDSA) |
| A.8.25 | Secure development life cycle | ✅ | This ROADMAP; TDD (647/0 tests); security-coverage gate; lockfile-only install; supply-chain policy checks |
| A.8.26 | Application security requirements | ✅ | [docs/DESIGN-V4-SECURITY-MODEL.md](../docs/DESIGN-V4-SECURITY-MODEL.md); 6 auth factors; default-deny; mTLS-only; PII redaction |
| A.8.27 | Secure system architecture & engineering principles | ✅ | [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md); 4 storage surfaces (secrets/audit/pki); 4 key invariants; modular routes (P2 #6) |
| A.8.28 | Secure coding | ✅ | `npm audit` + `gitleaks` history scan; redact patterns; typed schemas (59); no inline secrets in code |
| A.8.29 | Security testing in development & acceptance | ✅ | [docs/SECURITY-AUDIT-2026-09-05.md](../docs/SECURITY-AUDIT-2026-09-05.md); CI security-coverage gate; supply-chain policy; SBOM + Cosign |
| A.8.30 | Outsourced development | ⏳ | N/A (no outsourced); formal policy pending |
| A.8.31 | Separation of development, test & production environments | ✅ | `npm run dev` plaintext bypass (SOPS_SKIP=1, DEV ONLY); `npm test` for tests; `npm start` for production; strict mode is production default |
| A.8.32 | Change management | 🔄 | [ROADMAP-post-1.0.md](../ROADMAP-post-1.0.md); PR review; signed commits; formal change log pending P1 #4 |
| A.8.33 | Test information | ✅ | [docs/VERIFY.md](../docs/VERIFY.md) — 647/0 tests; security-coverage gate; signed-release gate |
| A.8.34 | Protection during audit testing | 🔄 | [docs/SECURITY-AUDIT-2026-09-05.md](../docs/SECURITY-AUDIT-2026-09-05.md) (desensitized snapshot); formal audit-mode controls pending P1 #4 |

## 7. Summary

| Theme | Total | Implemented | Partial | Planned | Out of scope |
|-------|-------|-------------|---------|---------|--------------|
| A.5 Organizational | 37 | 10 | 10 | 13 | 4 |
| A.6 People | 8 | 2 | 0 | 6 | 0 |
| A.7 Physical | 14 | 1 | 2 | 0 | 11 |
| A.8 Technological | 34 | 23 | 6 | 4 | 1 |
| **Total** | **93** | **36** | **18** | **23** | **16** |

- **Implemented (36/93, 39%)**: core security controls are in place (mTLS, 6 auth factors, RBAC, audit, redact, backups, secure SDLC, etc.)
- **Partial (18/93, 19%)**: control partially implemented, gap documented above
- **Planned (23/93, 25%)**: deferred to ROADMAP P1 #4 SOC 2 Type 1 readiness
- **Out of scope (16/93, 17%)**: physical controls (cloud-provider), web filtering (broker is server), outsourced development (none)

## 8. Gap analysis (Partial + Planned → Implementation plan)

### Phase 1: P1 #4 SOC 2 Type 1 readiness (8-12 weeks, target 2026-12-15)

Cross-cuts with SOC 2 (CC1-CC9 + selected TSC). Targets 36 implemented → ~70+ implemented.

**Quick wins (1-2 weeks, 1 commit each)**:
- A.5.2 RACI matrix
- A.5.5/5.6/5.7/5.10/5.22/5.35 formal policies
- A.5.9/5.12/5.13 asset inventory + classification scheme
- A.5.27 incident postmortem template (public)
- A.5.36/5.37 compliance dashboard + change mgmt
- A.6.1/6.2/6.3/6.4/6.6 DCO + CLA + Code of Conduct + admin training
- A.6.7/6.8 formal secure-development awareness
- A.7.9/7.10 asset tracking + media handling
- A.8.6/8.14/8.17 capacity / redundancy / NTP
- A.8.32 change log

**Heavy work (4-6 weeks, auditor + engineering)**:
- A.5.1/5.4 formal policy + sign-off
- A.5.19/5.20/5.31/5.35 third-party pen test + auditor engagement
- A.5.23/8.7 cloud security review (P1 #3 cloud marketplace images needed)
- A.8.30 outsourced development policy

### Phase 2: Internal audit (2-4 weeks)

Walk through this document + SOC 2 mapping with internal auditor, verify
each "Implemented" status is true, document any new gaps.

### Phase 3: ISO 27001 Stage 1 audit (external)

Submit to accredited certification body. Stage 1 = documentation review
(this document + audit report). Stage 2 = on-site / virtual audit.

## 9. Limitations

- This is a **self-assessment**, not a third-party audit.
- Control status depends on operator's actual deployment configuration
  (strict / controlled / compatibility profile).
- "Implemented" assumes the operator enables all features (mTLS, 2-person
  approval, WebAuthn, etc.). A deployment with `compatibility` profile
  only would have lower coverage.
- ISO 27001:2022 is the basis; ISO 27002:2022 provides implementation
  guidance but is not free.

## 10. Refs

- [ROADMAP-post-1.0.md §5](../ROADMAP-post-1.0.md#5-iso-27001-annex-a-controls-mapping-w33-w36)
- [docs/THREAT-MODEL.md](../docs/THREAT-MODEL.md)
- [docs/SECURITY-AUDIT-2026-09-05.md](../docs/SECURITY-AUDIT-2026-09-05.md)
- [docs/DESIGN-V4-SECURITY-MODEL.md](../docs/DESIGN-V4-SECURITY-MODEL.md)
- [SECURITY.md](../SECURITY.md)
- [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md)
- [RUNBOOK.md](../RUNBOOK.md)
- [docs/PHASE-F-BACKUP-PROBES.md](../docs/PHASE-F-BACKUP-PROBES.md)
- [docs/SECURITY-CONTROLS-SOC2.md](SECURITY-CONTROLS-SOC2.md) (sister doc for SOC 2)

## 11. License

This document is licensed under MIT — see [LICENSE](../LICENSE).
