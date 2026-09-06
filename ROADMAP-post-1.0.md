# Roadmap (Post 1.0)

> V4.1.0 is **GA** (tag `v4.1.0`, 2026-09-01). This document outlines
> what's next. For the v4.x timeline that delivered V4.1.0, see
> [docs/DESIGN-V4-ROADMAP.md](docs/DESIGN-V4-ROADMAP.md) and
> [V4.1-COMPLETE.md](V4.1-COMPLETE.md).

## What was delivered in V4.1.0

| Metric | Value |
|--------|-------|
| Total tasks (P1 + P2 + P3) | 23 / 23 ✅ |
| Total test cases | ~1027 (100% pass) |
| Lines of production code added | ~9,500 |
| SDKs (Node + Python + Go + VSCode) | 4 |
| Service templates | 48 (up from 6) |
| Type schemas | 59 (up from 42) |
| Cloud deployment surfaces | 4 (Docker / Helm / Terraform × AWS+Azure+GCP / bare-metal) |
| Calling surfaces | 8 (REST / WS / SSH / OIDC / MCP / proxy / exec / login) |
| Auth factors | 6 (mTLS / Pass / TOTP / WebAuthn / SMS / Recovery) |
| Cloud marketplace images | **0 (deferred to post-1.0)** |
| Native desktop client | **0 (deferred)** |
| Mobile clients | **0 (deferred)** |

## Post-1.0 priorities (2026 Q4 → 2027 Q2)

Listed in priority order. Each item has a target quarter and a clear
"done" definition.

### P0 — Required for "V4.1 is the production-ready version"

#### 1. Real CI runs on GitHub Actions (W25-W26)
- [ ] Merge `.github/workflows/ci-v4.yml` and `test-sdks.yml` to `main`
- [ ] Confirm 3 OS × 2 Node versions × 5 Python versions × 3 Go versions
  pass = 45+ green checkmarks
- [ ] Add `workflow_dispatch` for on-demand runs
- **Target**: 2026-09-15

#### 2. Real GitHub release (W25)
- [x] `git push origin v4.1.0` ✅ 2026-09-01
- [x] Create GitHub Release with `RELEASE-NOTES-v4.1.0.md` as body ✅ 2026-09-01 (id 380224739)
- [x] Attach source tarball + wheel for the Python SDK ✅ 2026-09-01
- [x] Attach Linux/Windows/macOS binaries of the Go SDK ✅ 2026-09-01 (4 binaries + linux-arm64)
- **Target**: 2026-09-15 — **DONE 2026-09-01** (https://github.com/tyj1987/broker/releases/tag/v4.1.0)

### P1 — Required for "V4.1 is enterprise-ready"

#### 3. Cloud marketplace images (W27-W32)
- [x] **AWS Marketplace** ✅ 2026-09-06 — Packer template (`deploy/packer/aws-broker.pkr.hcl`) + CloudFormation template (`cfn-template.yaml`) + cloud-init (`files/cloud-init-user-data.sh`) + systemd unit (`files/broker.service`) + maintainer guide (`README.md`) shipped
- [ ] **Azure Marketplace** (Phase 3b, target 2026-10-22)
- [ ] **Google Cloud Marketplace** (Phase 3c, target 2026-10-29)
- [ ] **Aliyun 镜像市场** (China) (Phase 3d, target 2026-10-31)
- [ ] **Tencent Cloud 镜像市场** (China) (Phase 3e, target 2026-10-31)
- **Target**: 2026-10-31 — **PARTIAL 2026-09-06** (AWS ready; 4 others follow sequentially)
- **Acceptance**: all 5 listings live, install count tracked in BrokerCacheStat

#### 4. SOC 2 Type 1 readiness (W33-W40)
- [x] Document all controls (CC1-CC9 + selected TSC) ✅ 2026-09-06 — `docs/SECURITY-CONTROLS-SOC2.md` (16 KB, 65 criteria mapped, 46% implemented, 8% partial, 45% planned)
- [ ] Implement evidence collection (audit chain, config snapshots) (Phase 2)
- [ ] Third-party pen test (commissioned) (Phase 3, $30-80k)
- [ ] Auditor engagement (Phase 3, $50-150k)
- [ ] Fix any findings (Phase 4)
- [ ] Submit for Type 1 report (Phase 5)
- **Target**: 2026-12-15 — **PARTIAL 2026-09-06** (control docs done; pen test + auditor + report remain)
- **Acceptance**: Type 1 report received, all Critical/High findings remediated

#### 5. ISO 27001 Annex A controls mapping (W33-W36)
- [x] Map broker features to Annex A controls (A.5-A.18) ✅ 2026-09-06 — `docs/SECURITY-CONTROLS-ISO27001.md` (20 KB, 93 controls mapped, 39% implemented, 19% partial, 25% planned, 17% out of scope)
- [x] Gap analysis ✅ 2026-09-06 — embedded in §8 of ISO doc
- [ ] Implement missing controls (Phase 2, 1-2 weeks quick wins)
- [ ] Internal audit (Phase 3, 2-4 weeks)
- **Target**: 2026-11-30 — **PARTIAL 2026-09-06** (mapping + gap analysis done; missing controls + internal audit remain)

### P2 — Quality of life

#### 6. Tauri desktop client (W37-W42)
- [x] Cross-platform (Linux / macOS / Windows) desktop app ✅ 2026-09-06 — Phase 1 scaffold shipped (Tauri 2.x + Solid.js + Rust workspace)
- [ ] System tray icon with broker health (Phase 4, +2 weeks)
- [ ] Native notifications for alerts (WebSocket) (Phase 4, +2 weeks)
- [ ] Built-in mTLS client cert management (Phase 2, +4 weeks)
- [ ] Auto-update via Tauri updater (Phase 5, +4 weeks)
- **Target**: 2026-12-15 — **PARTIAL 2026-09-06** (Phase 1 spec + scaffold shipped; Phases 2-6 需 14 weeks 全职)

#### 7. Homebrew tap (W37)
- [ ] `brew install tyj1987/broker/broker` (CLI)
- [ ] Auto-update on `brew upgrade`
- **Target**: 2026-10-15

#### 8. Snap / apt / winget packages (W38-W40)
- [ ] Snap store: `snap install broker`
- [ ] apt PPA: `apt install broker`
- [ ] winget: `winget install tyj1987.broker`
- **Target**: 2026-11-15

#### 9. V4.1.1 patch (Q4 2026)
- [ ] Backport fixes from master
- [ ] Update `dependencies` lockfile (`npm audit fix`, `pip-audit`)
- [ ] Bump `BROKER_VERSION` to 4.1.1
- **Target**: 2026-10-31

#### 10. V4.1.2 patch (Q1 2027)
- [x] Design prep ✅ 2026-09-06 — `docs/V4.1.2-PATCH-PREP.md` (12 KB, 6-phase prep + patch SLA + bug bounty pipeline + auto-rotate cache design)
- [ ] Community-reported bug fixes (Phase 10.5, 2027-01-15)
- [ ] Performance: cache auto-rotate decision (Phase 10.2, 2026-10-15)
- [ ] Bug Bounty: process any Critical/High findings (Phase 10.3, ongoing)
- **Target**: 2027-01-31 — **PARTIAL 2026-09-06** (prep done; 4.5 weeks full-time for release)

### P3 — Stretch goals

#### 11. Mobile clients (Q1 2027)
- [x] Design spec ✅ 2026-09-06 — `docs/DESIGN-MOBILE-CLIENTS.md` (15 KB, iOS Swift + Android Kotlin detailed design)
- [ ] iOS app: Swift + Network.framework mTLS (Phase 11.1-11.5, 14 weeks, 2026-12-15 → 2027-03-15)
- [ ] Android app: Kotlin + OkHttp mTLS (Phase 11.6-11.10, 12 weeks, 2027-01-15 → 2027-03-31)
- [ ] Both: Touch ID / Face ID for MFA
- **Target**: 2027-03-31 — **PARTIAL 2026-09-06** (design done; iOS + Android parallel 6-month full-time)

#### 12. V4.2.0 (Q2 2027)
- [x] Design spec ✅ 2026-09-06 — `docs/DESIGN-V4.2.0.md` (18 KB, 4 features detailed design)
- [ ] Per-tenant rate limiting (Phase 7.1, 2027-04-15)
- [ ] Attribute-based access control (ABAC) for secret access (Phase 7.2, 2027-05-15)
- [ ] Secret versioning with diff UI (Phase 7.3 + 7.5, 2027-06-01 + 2027-06-25)
- [ ] Approval workflow for high-risk secret access (Phase 7.4, 2027-06-15)
- **Target**: 2027-06-30 — **PARTIAL 2026-09-06** (design done; implementation 12-15 weeks full-time)

#### 13. Marketplace self-service (Q2 2027)
- [x] Design spec ✅ 2026-09-06 — `docs/DESIGN-MARKETPLACE-SELF-SERVICE.md` (16 KB, 3rd-party provider publish + GitHub review + auto-update)
- [ ] Third-party providers can publish templates via `secret-broker marketplace publish` (Phase 13.2, 2027-04-30)
- [ ] Review process via GitHub Discussions (Phase 13.4, 2027-05-31)
- [ ] Auto-update on `secret-broker sync` (Phase 13.5, 2027-06-15)
- **Target**: 2027-06-30 — **PARTIAL 2026-09-06** (design done; implementation 19 weeks full-time)

## Out of scope (will NOT be done in broker)

- **Secret storage for non-AI use cases** (e.g. human password manager) —
  the broker is designed for AI-first workload, where humans rarely
  interact directly. Use 1Password / Bitwarden for that.
- **HSM integration** (YubiHSM2, AWS CloudHSM) — out of scope. SOPS +
  age + RBAC is sufficient for our threat model. If you need HSM, fork
  the repo and add a `secrets-detail.json` SOPS encryptor plugin.
- **Cross-region active-active replication** — the broker is stateless;
  shared PVC + RWO is the recommended pattern. For multi-region, deploy
  a primary per region with async replication of the SOPS-encrypted
  secrets.

## Decision drivers

These will trigger scope changes from the above plan:

- **Bug Bounty**: Critical or High severity finding in V4.1.0
  → immediate patch, may push other items
- **Customer request**: any enterprise customer requesting a specific
  feature with LOI will be evaluated for V4.2.0
- **OpenSSF / SLSA scorecard**: dropping below Gold will trigger a
  remediation sprint
- **CVE**: any CVE assigned will trigger immediate patch

## How to influence this roadmap

1. **Open a GitHub Discussion** in the `roadmap` category.
2. **Vote** on existing proposals (👍 reaction = +1).
3. **Submit a PR** to `ROADMAP-post-1.0.md` (yes, this file is a PR-able
   doc — we treat it as living).
4. **For enterprise**: contact `broker@local` for a custom SLA.

## Versioning

Per [Semantic Versioning](https://semver.org/):
- Patches (4.1.x): backwards-compatible bug fixes
- Minors (4.x.0): new features, backwards-compatible
- Majors (5.0.0): breaking changes (rare; v3.8 → v4.0.0 was a major
  because of MFA requirements and ACL changes)

The next major is V5.0.0, planned for 2027 Q4 (or earlier if needed).
