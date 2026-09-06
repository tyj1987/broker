# Documentation Index

> **One-page index of every documentation file in the broker project.**
> Use this when you're looking for a specific doc but don't know the name.
> Last verified: 2026-09-06 (V4.1.1 release prep, 21 commit ready).

---

## TL;DR — Most important docs

| If you want to... | Read this |
|-------------------|-----------|
| Understand the project | [README.md](../README.md) + [QUICKSTART.md](QUICKSTART.md) |
| Use the V4.1.1 SDKs | [SDK-REFERENCE.md](SDK-REFERENCE.md) + [SDK-UPGRADE-GUIDE.md](SDK-UPGRADE-GUIDE.md) |
| Migrate V4.1.0 SDK → V4.1.1 | [SDK-UPGRADE-GUIDE.md](SDK-UPGRADE-GUIDE.md) |
| Handle a broker error code | [ERROR-CODES.md](ERROR-CODES.md) |
| Run V4.1.1 release | [RUNBOOK-v4.1.1.md](RUNBOOK-v4.1.1.md) |
| Verify V4.1.1 release readiness | `node scripts/verify-v4.1.1-release.mjs` |
| Ship V4.1.1 announcement | [ANNOUNCEMENT-TEMPLATES-v4.1.1.md](ANNOUNCEMENT-TEMPLATES-v4.1.1.md) |
| See the 1-page V4.1.1 release state | [V4.1.1-FINAL-STATE.md](V4.1.1-FINAL-STATE.md) |
| See all V4.1.1 commit hashes | [V4.1.1-COMMITS.md](V4.1.1-COMMITS.md) |
| See all open V4.1.1 PRs | [AWAITING-USER.md](../AWAITING-USER.md) |
| See project roadmap | [ROADMAP-post-1.0.md](../ROADMAP-post-1.0.md) |
| See security policy | [SECURITY.md](../SECURITY.md) + [SECURITY-AUDIT-2026-09-05.md](SECURITY-AUDIT-2026-09-05.md) |
| Understand architecture | [DESIGN-V4-MASTER-PLAN.md](DESIGN-V4-MASTER-PLAN.md) |
| Use the Python SDK | [QUICKSTART.md](QUICKSTART.md) + [SDK-REFERENCE.md](SDK-REFERENCE.md) |
| Use the Go SDK | [SDK-REFERENCE.md](SDK-REFERENCE.md) |
| Use the VSCode extension | [QUICKSTART.md](QUICKSTART.md) (VSCode section) |
| Use the Node CLI / mavis | [SDK-REFERENCE.md](SDK-REFERENCE.md) |
| Configure workload identity (K8s/ECS/GKE) | [WORKLOAD-IDENTITY.md](WORKLOAD-IDENTITY.md) |
| Use SSH proxy / tunnel | [SSH-PROXY.md](SSH-PROXY.md) |
| Use WebSocket events | [WEBSOCKET.md](WEBSOCKET.md) |
| Use the API | [DESIGN-V4-API-CALLING-STANDARDS.md](DESIGN-V4-API-CALLING-STANDARDS.md) |
| Check threat model | [THREAT-MODEL.md](THREAT-MODEL.md) |
| See FAQ | [FAQ.md](FAQ.md) |

---

## V4.1.1 release docs (newest)

| File | Size | Purpose |
|------|------|---------|
| [V4.1.1-FINAL-STATE.md](V4.1.1-FINAL-STATE.md) | 8.2 KB | 1-page executive summary |
| [V4.1.1-COMMITS.md](V4.1.1-COMMITS.md) | 8.7 KB | All 21 commit hashes × 10 sections |
| [RELEASE-NOTES-v4.1.1.md](../RELEASE-NOTES-v4.1.1.md) | 7.0 KB | GitHub Release body |
| [RUNBOOK-v4.1.1.md](RUNBOOK-v4.1.1.md) | 10.6 KB | 8 步 release manual |
| [ANNOUNCEMENT-TEMPLATES-v4.1.1.md](ANNOUNCEMENT-TEMPLATES-v4.1.1.md) | 15 KB | 10 platform templates |
| [SDK-UPGRADE-GUIDE.md](SDK-UPGRADE-GUIDE.md) | 15.5 KB | V4.1.0 → V4.1.1 SDK migration |
| [SDK-REFERENCE.md](SDK-REFERENCE.md) | 7.1 KB | 4-SDK error contract (V4.1.1 section) |
| [ERROR-CODES.md](ERROR-CODES.md) | 12 KB | 25 broker error codes reference |
| [../AWAITING-USER.md](../AWAITING-USER.md) | 12.4 KB | 21 PR + recommended merge order (V13) |
| [../CHANGELOG.md](../CHANGELOG.md) | 14.5 KB | V4.1.1 history + SDK parity section |
| [../ROADMAP-post-1.0.md](../ROADMAP-post-1.0.md) | 6.7 KB | 13/13 items status |
| [../STATUS.md](../STATUS.md) | 2.0 KB | V4.1.1 ready state |
| [../SECURITY.md](../SECURITY.md) | 9.8 KB | V4.1.1 security notes + cert-as-session fix |
| [../AGENTS.md](../AGENTS.md) | 15.4 KB | Broker project onboarding for AI agents |

## Design specs (architecture + V4 plans)

| File | Size | Purpose |
|------|------|---------|
| [DESIGN-V4-MASTER-PLAN.md](DESIGN-V4-MASTER-PLAN.md) | 45 KB | Overall V4 architecture |
| [DESIGN-V4-ROADMAP.md](DESIGN-V4-ROADMAP.md) | 17 KB | V4 6-month roadmap |
| [DESIGN-V4-API-CALLING-STANDARDS.md](DESIGN-V4-API-CALLING-STANDARDS.md) | 40 KB | How AI agents call the broker |
| [DESIGN-V4-IDENTITY-MFA.md](DESIGN-V4-IDENTITY-MFA.md) | 28 KB | 6-factor auth (mTLS + WebAuthn + TOTP + ...) |
| [DESIGN-V4-SECURITY-MODEL.md](DESIGN-V4-SECURITY-MODEL.md) | 26 KB | Security model + threat model |
| [DESIGN-V4-PROVIDER-TEMPLATES.md](DESIGN-V4-PROVIDER-TEMPLATES.md) | 32 KB | 48 service templates (signing) |
| [V4.1.2-PATCH-PREP.md](V4.1.2-PATCH-PREP.md) | 12 KB | V4.1.2 prep (Q1 2027) |
| [CLOUD-MARKETPLACE.md](CLOUD-MARKETPLACE.md) | 12 KB | AWS/Azure/GCP/Aliyun/Tencent |
| [HOMEBREW.md](HOMEBREW.md) | 7.5 KB | Homebrew formula |
| [SNAP-APT-WINGET.md](SNAP-APT-WINGET.md) | 5.2 KB | Snap / apt / winget packages |
| [DESIGN-V4.2.0.md](DESIGN-V4.2.0.md) | 18 KB | V4.2.0 design (4 features) |
| [DESIGN-MOBILE-CLIENTS.md](DESIGN-MOBILE-CLIENTS.md) | 15 KB | iOS Swift + Android Kotlin |
| [DESIGN-TAURI-DESKTOP.md](DESIGN-TAURI-DESKTOP.md) | 15 KB | Tauri 2.0 desktop client |
| [DESIGN-MARKETPLACE-SELF-SERVICE.md](DESIGN-MARKETPLACE-SELF-SERVICE.md) | 16 KB | 3rd-party provider publish |
| [SECURITY-CONTROLS-ISO27001.md](SECURITY-CONTROLS-ISO27001.md) | 20 KB | ISO 27001 Annex A (93 controls) |
| [SECURITY-CONTROLS-SOC2.md](SECURITY-CONTROLS-SOC2.md) | 16 KB | SOC 2 Type 1 (65 criteria) |

## Operational docs (using the broker)

| File | Size | Purpose |
|------|------|---------|
| [QUICKSTART.md](QUICKSTART.md) | 4.0 KB | 5-minute walkthrough |
| [FAQ.md](FAQ.md) | 10 KB | Frequently asked questions |
| [WORKLOAD-IDENTITY.md](WORKLOAD-IDENTITY.md) | 5.2 KB | K8s / ECS / GKE identity |
| [WEBSOCKET.md](WEBSOCKET.md) | 5.0 KB | WebSocket event subscription |
| [SSH-PROXY.md](SSH-PROXY.md) | 4.4 KB | SSH proxy / tunnel / exec |
| [SERVER-WIRE-CHECKLIST.md](SERVER-WIRE-CHECKLIST.md) | 9.9 KB | Server wire protocol checklist |
| [THREAT-MODEL.md](THREAT-MODEL.md) | 2.7 KB | Threat model (STRIDE) |
| [PHASE-A-SERVER-WIRE.md](PHASE-A-SERVER-WIRE.md) | 1.7 KB | V4 phase A plan |
| [PHASE-B-MODULARIZE.md](PHASE-B-MODULARIZE.md) | 0.8 KB | V4 phase B plan |
| [PHASE-B5-CUTOVER.md](PHASE-B5-CUTOVER.md) | 2.0 KB | V4 phase B5 plan |
| [PHASE-C-OBSERVABILITY.md](PHASE-C-OBSERVABILITY.md) | 1.6 KB | V4 phase C plan |
| [PHASE-D-TRACING-AUDIT.md](PHASE-D-TRACING-AUDIT.md) | 1.8 KB | V4 phase D plan |
| [PHASE-E-OPS.md](PHASE-E-OPS.md) | 1.8 KB | V4 phase E plan |
| [PHASE-F-BACKUP-PROBES.md](PHASE-F-BACKUP-PROBES.md) | 1.4 KB | V4 phase F plan |
| [PLAN-secret-broker-v3.md](PLAN-secret-broker-v3.md) | 54 KB | v3.0 master plan (historical) |
| [SECURITY-AUDIT-2026-09-05.md](SECURITY-AUDIT-2026-09-05.md) | 17 KB | Security audit 2026-09-05 |
| [index.md](index.md) | 3.4 KB | MkDocs landing page |

## Top-level docs (in repo root)

| File | Size | Purpose |
|------|------|---------|
| [../README.md](../README.md) | n/a | Top-level project intro |
| [../CHANGELOG.md](../CHANGELOG.md) | 14.5 KB | Version history |
| [../STATUS.md](../STATUS.md) | 2.0 KB | Project state (V4.1.1 ready) |
| [../ROADMAP-post-1.0.md](../ROADMAP-post-1.0.md) | 6.7 KB | 13 items P0-P3 |
| [../AWAITING-USER.md](../AWAITING-USER.md) | 12.4 KB | Current user decisions (V13) |
| [../SECURITY.md](../SECURITY.md) | 9.8 KB | Security policy + V4.1.1 notes |
| [../RUNBOOK.md](../RUNBOOK.md) | 25 KB | General broker operations |
| [../DEPLOY-52TRZ.md](../DEPLOY-52TRZ.md) | n/a | 52trz.com production deploy |
| [../ARCHITECTURE.md](../ARCHITECTURE.md) | n/a | One-page architecture overview |
| [../VERIFY.md](../VERIFY.md) | n/a | 1-line verification |
| [../V4.1-COMPLETE.md](../V4.1-COMPLETE.md) | n/a | V4.1.0 GA completion summary |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | 17 KB | V4 contribution guide |
| [../AGENTS.md](../AGENTS.md) | 15.4 KB | Broker project onboarding for AI agents |
| [../LICENSE](../LICENSE) | n/a | MIT license |
| [../RELEASE-NOTES-v4.1.0.md](../RELEASE-NOTES-v4.1.0.md) | n/a | V4.1.0 release notes |
| [../RELEASE-NOTES-v4.1.1.md](../RELEASE-NOTES-v4.1.1.md) | 7.0 KB | V4.1.1 release notes (with SDK parity) |

## Tooling

| File | Purpose |
|------|---------|
| `../scripts/preflight-v4.1.1.mjs` | V4.1.1 pre-tag sanity check (cross-platform Node.js) |
| `../scripts/verify-sdk-v4.1.1-parity.mjs` | 4-SDK parity contract verification |
| `../scripts/verify-v4.1.1-release.mjs` | Combined runner (1 command) |
| `../scripts/release/v4.1.1.sh` | Bash build + upload (Linux/macOS only) |

## PR / process templates

| File | Purpose |
|------|---------|
| [../.github/PULL_REQUEST_TEMPLATE.md](../.github/PULL_REQUEST_TEMPLATE.md) | V4.1.1-era PR template (30+ areas, 14 SDK parity items) |
| [../.github/CODEOWNERS](../.github/CODEOWNERS) | 4-SDK parity routing (auto-assign reviewers) |
| [../.github/ISSUE_TEMPLATE/](../.github/ISSUE_TEMPLATE/) | bug_report / feature_request / question |

---

## Doc categories summary

- **V4.1.1 release** (14 files): FINAL-STATE, COMMITS, RELEASE-NOTES, RUNBOOK, ANNOUNCEMENT, SDK-UPGRADE-GUIDE, SDK-REFERENCE, ERROR-CODES, AWAITING-USER V13, CHANGELOG, ROADMAP, STATUS, SECURITY, AGENTS
- **Design specs** (16 files): master plan, roadmap, API standards, identity/MFA, security, providers, future versions (V4.1.2, V4.2.0, mobile, desktop, marketplace), security controls (ISO 27001 + SOC 2)
- **Operational** (17 files): quickstart, FAQ, workload identity, websocket, SSH, server wire, threat model, 7 phase plans, v3 plan, security audit, MkDocs index
- **Top-level** (16 files): README, CHANGELOG, STATUS, ROADMAP, AWAITING-USER, SECURITY, RUNBOOK, DEPLOY-52TRZ, ARCHITECTURE, VERIFY, V4.1-COMPLETE, CONTRIBUTING, AGENTS, LICENSE, 2 RELEASE-NOTES
- **Tooling** (4 files): 3 verify scripts + 1 release script
- **PR / process** (5 files): template, CODEOWNERS, 3 issue templates

**Total**: 72 documentation files (~290 KB).

---

## How to navigate

1. **Start with [QUICKSTART.md](QUICKSTART.md)** for 5-minute intro.
2. **For V4.1.1 SDK users**: [SDK-UPGRADE-GUIDE.md](SDK-UPGRADE-GUIDE.md) +
   [SDK-REFERENCE.md](SDK-REFERENCE.md) + [ERROR-CODES.md](ERROR-CODES.md).
3. **For V4.1.1 maintainers**: [V4.1.1-FINAL-STATE.md](V4.1.1-FINAL-STATE.md) +
   [AWAITING-USER.md V13](../AWAITING-USER.md) + [RUNBOOK-v4.1.1.md](RUNBOOK-v4.1.1.md).
4. **For architects**: [DESIGN-V4-MASTER-PLAN.md](DESIGN-V4-MASTER-PLAN.md) +
   [THREAT-MODEL.md](THREAT-MODEL.md) + [WORKLOAD-IDENTITY.md](WORKLOAD-IDENTITY.md).
5. **For ops**: [RUNBOOK.md](../RUNBOOK.md) (general) + [RUNBOOK-v4.1.1.md](RUNBOOK-v4.1.1.md) (V4.1.1 release).

---

## Reference

- [README.md](../README.md)
- [index.md](index.md) (MkDocs landing page)
- [V4.1.1-COMMITS.md](V4.1.1-COMMITS.md) (commit hash index)
- [V4.1.1-FINAL-STATE.md](V4.1.1-FINAL-STATE.md) (1-page summary)
- [AWAITING-USER.md V13](../AWAITING-USER.md) (PR merge order)

---

**Document version**: 2026-09-06 (V4.1.1 release prep)
**Files indexed**: 72 (~290 KB)
**Last verified**: session 17 (21 commit, 18 dimensions complete)
