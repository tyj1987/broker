# Releases Index

> **Index of all broker releases.** Maps each release to its tag, release
> notes, key changes, and current status. Use this when looking for what
> changed in a specific version.
>
> Last updated: 2026-09-06 (V4.1.1 release prep, 22 commit ready).

---

## At a glance

| Version | Tag | Type | Date | Status | Release notes |
|---------|-----|------|------|--------|---------------|
| V4.2.0  | (TBD) | minor | Q2 2027 (planned) | Design only | [DESIGN-V4.2.0.md](docs/DESIGN-V4.2.0.md) |
| V4.1.2  | (TBD) | patch | Q1 2027 (planned) | Prep ready | [V4.1.2-PATCH-PREP.md](docs/V4.1.2-PATCH-PREP.md) |
| **V4.1.1** | (TBD) | patch | **2026-09-06 (planned)** | **Code + docs + tools 100% ready, awaiting user merge + tag + release** | [RELEASE-NOTES-v4.1.1.md](RELEASE-NOTES-v4.1.1.md) |
| V4.1.0  | `v4.1.0` | minor | 2026-09-01 (GA) | ✅ Shipped, superseded by V4.1.1 | [RELEASE-NOTES-v4.1.0.md](RELEASE-NOTES-v4.1.0.md) |
| V4.0    | `v4.0.0` | major | 2026 Q2 (design) | Design only | [DESIGN-V4-MASTER-PLAN.md](docs/DESIGN-V4-MASTER-PLAN.md) |
| V3.8.x  | n/a | stable | 2025-2026 | Critical fixes only (EOL 2027-01-01) | n/a |

**Most recent release**: V4.1.0 (`v4.1.0`, 2026-09-01). Superseded by
V4.1.1 patch in progress (22 PR in origin, 21 dimensions complete).

---

## V4.1.1 — Security & correctness patch (PLANNED, 2026-09-06)

**Tag**: (to be tagged after PRs merged per AWAITING-USER.md V13)
**Type**: backward-compatible patch (no breaking change)
**Lead time vs target**: 55 days early (Q4 2026 target → 2026-09-06)

### What ships

- **Broker**: mTLS cert-as-session fix (cherry-pick from `f3a7cc7`).
- **4 SDKs** (Python, Go, Node CLI, VSCode): unified `BrokerError` contract
  with structured fields (`code`, `requestId`, `retryAfter`, `is_retryable`),
  `parseBrokerError` factory, built-in retry (5xx / 429 / connection with
  exponential backoff + `Retry-After` override), auto-redact body on
  construction.
- **0 vulnerabilities**: `npm audit` clean, `pip-audit` N/A (Python stdlib only),
  `govulncheck` clean (Go stdlib only).
- **Tests**: 658 (V4.1.0) → 795 (V4.1.1) (+137). SDK tests: 54 → 166 (+112,
  +208% growth).

### Documentation (13 new / updated)

- [SDK-REFERENCE.md V4.1.1 section](docs/SDK-REFERENCE.md) (4-SDK error contract)
- [SDK-UPGRADE-GUIDE.md](docs/SDK-UPGRADE-GUIDE.md) (V4.1.0 → V4.1.1 migration)
- [ERROR-CODES.md](docs/ERROR-CODES.md) (25 broker error codes)
- [RUNBOOK-v4.1.1.md](docs/RUNBOOK-v4.1.1.md) (8 步 release manual)
- [ANNOUNCEMENT-TEMPLATES-v4.1.1.md](docs/ANNOUNCEMENT-TEMPLATES-v4.1.1.md) (10 platforms)
- [V4.1.1-FINAL-STATE.md](docs/V4.1.1-FINAL-STATE.md) (1-page summary)
- [V4.1.1-COMMITS.md](docs/V4.1.1-COMMITS.md) (21 commits × 10 sections)
- [DOCS-INDEX.md](docs/DOCS-INDEX.md) (72 doc files index)
- [AWAITING-USER.md V13](AWAITING-USER.md) (22 PR + merge order)
- [ROADMAP-post-1.0.md](ROADMAP-post-1.0.md) (13/13 items status)
- [CHANGELOG.md V4.1.1 entry](CHANGELOG.md) (with SDK parity subsection)
- [STATUS.md V4.1.1 ready](STATUS.md)
- [SECURITY.md V4.1.1 security notes](SECURITY.md) (cert-as-session fix)
- [AGENTS.md](AGENTS.md) (broker project onboarding)

### Tooling (4 new / updated)

- [scripts/preflight-v4.1.1.mjs](scripts/preflight-v4.1.1.mjs) (cross-platform Node.js)
- [scripts/verify-sdk-v4.1.1-parity.mjs](scripts/verify-sdk-v4.1.1-parity.mjs) (4-SDK parity contract)
- [scripts/verify-v4.1.1-release.mjs](scripts/verify-v4.1.1-release.mjs) (combined runner)
- [scripts/release/v4.1.1.sh](scripts/release/v4.1.1.sh) (bash build + upload)

### Release notes

- [RELEASE-NOTES-v4.1.1.md](RELEASE-NOTES-v4.1.1.md) — official GitHub Release body
  (with SDK parity section, migration examples, 4-SDK before/after).

### Ship process

See [docs/RUNBOOK-v4.1.1.md](docs/RUNBOOK-v4.1.1.md) for 8 步:

1. Merge 22 PRs per AWAITING-USER V13 (~140 min)
2. `node scripts/verify-v4.1.1-release.mjs --strict` (verify, ~30s)
3. `git tag -a v4.1.1 -m "V4.1.1 GA"` (1 min)
4. `git push origin v4.1.1` (1 min)
5. `bash scripts/release/v4.1.1.sh` (build 8 assets, ~10 min)
6. `bash scripts/release/v4.1.1.sh --upload --publish` (GitHub Release, ~3 min)
7. Smoke (`curl /health`, ~2 min)
8. (Optional) 52trz.com V4.1.0 → V4.1.1 upgrade (~5 min)
9. Announce via 10 platforms (~5 min)

---

## V4.1.0 — General Availability (SHIPPED, 2026-09-01)

**Tag**: `v4.1.0`
**Type**: minor
**Date**: 2026-09-01 (GA)
**Status**: ✅ Shipped, **superseded by V4.1.1**

### What shipped

V4.1.0 was the GA release delivering the V4 6-month roadmap (W1-W24, 23 tasks).
Total: 22 tasks ✅ + 1027 tests + ~9,500 LOC + 4 SDKs (Python, Go, Node, VSCode)
+ 48 service templates + 59 type schemas + 4 cloud deployment surfaces
(6 auth factors, 8 calling surfaces).

### Release notes

- [RELEASE-NOTES-v4.1.0.md](RELEASE-NOTES-v4.1.0.md) — official GitHub Release body
- [V4.1-COMPLETE.md](V4.1-COMPLETE.md) — per-task summary (8.5 KB)
- [GitHub Release v4.1.0](https://github.com/tyj1987/broker/releases/tag/v4.1.0) —
  includes 8 assets (source tarball + zip, Python wheel + sdist, 4 Go SDK binaries)

### Migration

- V3.8.x → V4.1.0: see [RELEASE-NOTES-v4.1.0.md §Migration from v3.8](RELEASE-NOTES-v4.1.0.md)
- V4.1.0 → V4.1.1: see [docs/SDK-UPGRADE-GUIDE.md](docs/SDK-UPGRADE-GUIDE.md)

---

## V4.0 — Major (DESIGN PHASE, Q2 2026)

**Tag**: (no V4.0 release; V4.0 design phase was 2026 Q2, V4.0.0 not released)
**Type**: design phase
**Status**: Design complete; rolled into V4.1.0 as the GA milestone

### What was designed

V4 6-month roadmap: 23 tasks covering mTLS, MFA (6 factors), 17 new
type schemas, 48 service templates, 8 signing algorithms, auto-rotation,
OpenAPI 3.1, zero-credential-leakage, cross-platform CI.

### Documents

- [DESIGN-V4-MASTER-PLAN.md](docs/DESIGN-V4-MASTER-PLAN.md) (45 KB)
- [DESIGN-V4-ROADMAP.md](docs/DESIGN-V4-ROADMAP.md) (17 KB)
- [DESIGN-V4-API-CALLING-STANDARDS.md](docs/DESIGN-V4-API-CALLING-STANDARDS.md) (40 KB)
- [DESIGN-V4-IDENTITY-MFA.md](docs/DESIGN-V4-IDENTITY-MFA.md) (28 KB)
- [DESIGN-V4-SECURITY-MODEL.md](docs/DESIGN-V4-SECURITY-MODEL.md) (26 KB)
- [DESIGN-V4-PROVIDER-TEMPLATES.md](docs/DESIGN-V4-PROVIDER-TEMPLATES.md) (32 KB)

---

## V4.1.2 — Patch (PLANNED, Q1 2027)

**Tag**: (TBD)
**Type**: patch
**Target**: 2027-01-31
**Status**: 6-phase prep ready

### What will ship

- Community-reported bug fixes
- Performance: auto-rotate cache
- Bug Bounty: process any Critical/High findings
- Spec: [docs/V4.1.2-PATCH-PREP.md](docs/V4.1.2-PATCH-PREP.md) (12 KB, 6 phases)

---

## V4.2.0 — Minor (DESIGN PHASE, Q2 2027)

**Tag**: (TBD)
**Type**: minor
**Target**: 2027-06-30
**Status**: Design only

### What is planned

4 features:
- Per-tenant rate limiting (Redis sliding window)
- ABAC (attribute-based access control, OPA-style)
- Secret versioning (KV history + rollback)
- Approval workflow (request → approve → issue)

### Documents

- [DESIGN-V4.2.0.md](docs/DESIGN-V4.2.0.md) (18 KB)

---

## V3.8.x — Stable (LEGACY, EOL 2027-01-01)

**Tag**: (multiple, see git tags)
**Type**: stable (3.8.x line)
**Status**: Critical fixes only until 2027-01-01

V3.8 was the previous major line. v3.8 clients remain compatible with
V4.x server (V4 was designed backward-compatible for v3.8 REST API and
secrets YAML schema).

See [RELEASE-NOTES-v4.1.0.md §Migration from v3.8](RELEASE-NOTES-v4.1.0.md)
for migration details.

---

## How to use this index

1. **Looking for what changed in a specific version**: click the version's
   release notes link above.
2. **Planning an upgrade**: see the corresponding upgrade guide
   ([SDK-UPGRADE-GUIDE.md](docs/SDK-UPGRADE-GUIDE.md) for V4.1.0 → V4.1.1).
3. **Tracking what's in origin**: see [AWAITING-USER.md](AWAITING-USER.md)
   for current user decisions and PR merge order.
4. **Verifying release readiness**: run
   `node scripts/verify-v4.1.1-release.mjs --strict`.
5. **Future releases**: see [ROADMAP-post-1.0.md](ROADMAP-post-1.0.md).

---

## Reference

- [README.md](README.md)
- [CHANGELOG.md](CHANGELOG.md)
- [STATUS.md](STATUS.md)
- [ROADMAP-post-1.0.md](ROADMAP-post-1.0.md)
- [AWAITING-USER.md](AWAITING-USER.md)
- [docs/DOCS-INDEX.md](docs/DOCS-INDEX.md) (72 doc files index)
- [docs/V4.1.1-FINAL-STATE.md](docs/V4.1.1-FINAL-STATE.md) (1-page summary)
- [docs/V4.1.1-COMMITS.md](docs/V4.1.1-COMMITS.md) (commit hash index)

---

**Document version**: 2026-09-06 (V4.1.1 release prep)
**Releases indexed**: 6 (V4.0, V4.1.0, V4.1.1, V4.1.2, V4.2.0, V3.8.x)
**Last verified**: session 17 (22 commit ready for V4.1.1)
