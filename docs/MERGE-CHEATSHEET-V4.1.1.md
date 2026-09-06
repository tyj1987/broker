# V4.1.1 Merge Cheatsheet

> **One-pager for the 34-PR merge sequence.**
> Companion to `AWAITING-USER.md V13` (status doc) and `RUNBOOK-v4.1.1.md` (post-merge ops).
> Last verified: 2026-09-06 — `node scripts/verify-v4.1.1-release.mjs --strict` returns **40 FAIL + 15 WARN** (no green) on master + unmerged branches.

## 0. Current state (pre-merge, 2026-09-06)

```
Preflight:  ✗ 9 FAIL + 9 WARN + 2 PASS  (broker V4.1.0, no V4.1.1 entry in CHANGELOG,
                                          no RELEASE-NOTES-v4.1.1.md, all SDKs V4.1.0)
4-SDK parity: ✗ 34 FAIL + 6 WARN + 7 PASS  (Python has BrokerError+ConnError but no
                                              parse_broker_error; Go missing 6 fields;
                                              CLI missing everything; VSCode missing 8 fields)
```

**Bottom line**: master is V4.1.0 + minor V4.1.1 docs branches. All 4 SDKs and broker core are still in feature branches.

## 1. Merge order (34 PRs in 4 tiers, ~125 min total)

> **Tactic**: Always rebase onto master **before** merging. If `git merge` reports conflicts, **rebase the feature branch first** (`git rebase origin/master` from the branch), then merge. Don't try to resolve merge conflicts on master.

### Tier 0 — Unblock the verify scripts (5 min, 2 PRs)

These are the scripts the verify-all runner itself depends on. Without them, the runner literally can't run.

| # | Branch | Commit | What it unblocks |
|---|--------|--------|------------------|
| 1 | `feat/release-preflight-check` | `10faca4` | `scripts/preflight-v4.1.1.mjs` (the actual checker) |
| 2 | `feat/verify-sdk-v4.1.1-parity` | `1a92da5` | `scripts/verify-sdk-v4.1.1-parity.mjs` (4-SDK contract) |

After: re-run verify — should now report actual content FAILs instead of "script not found".

### Tier 1 — Core V4.1.1 code (45 min, 6 PRs)

**The must-haves** — without these, no V4.1.1 release exists.

| # | Branch | Commit | What it ships |
|---|--------|--------|---------------|
| 3 | `release/v4.1.1` | pre-existing | broker `package.json` 4.1.1, `version.js`, `CHANGELOG.md` [4.1.1] entry |
| 4 | `release/v4.1.1-sdk-parity-notes` | pre-existing | `RELEASE-NOTES-v4.1.1.md` (8 KB), SDK parity section |
| 5 | `feat/sdk-python-exceptions-v4.1.1` | `9a0c5f7` | Python: `parse_broker_error`, `request_id`, `retry_after`, `to_dict`, `is_retryable` property |
| 6 | `feat/sdk-go-errors-v4.1.1` | `6052779` | Go: `BrokerConnectionError`, `ParseBrokerError`, `IsRetryable()`, `RequestID`, `RetryAfter`, `ToMap()` |
| 7 | `feat/sdk-cli-errors-v4.1.1` | `ba6da09` | Node CLI: `BrokerError`, `BrokerConnectionError`, `parseBrokerError`, `isRetryable`, `requestId`, `retryAfter`, `toString`, `toJSON` |
| 8 | `feat/sdk-vscode-errors-v4.1.1` | `f0a6dd1` | VSCode: `parseBrokerError`, `isRetryable`, `requestId`, `retryAfter`, `toString`, `toJSON`, `mtlsRequest`, User-Agent `secret-broker-vscode/4.1.1` |

After: re-run verify — preflight FAILs should drop to 0-1, 4-SDK FAILs should drop to ~5 (docs cross-refs only).

### Tier 2 — V4.1.1 critical docs (15 min, 7 PRs)

Documents that **directly reference V4.1.1 SDK contract** and will be linked from V4.1.1-COMPLETE / RELEASE-NOTES.

| # | Branch | Commit | What it ships |
|---|--------|--------|---------------|
| 9 | `docs/sdk-v4.1.1-parity-reference` | `20c5e6d` | `docs/SDK-REFERENCE.md` — 4-SDK BrokerError contract (canonical) |
| 10 | `docs/sdk-upgrade-guide-v4.1.1` | `172682a` | `docs/SDK-UPGRADE-GUIDE.md` — V4.1.0 → V4.1.1 migration |
| 11 | `docs/v4.1.1-error-code-registry` | `068f944` | `docs/ERROR-CODES.md` — 25 broker error codes |
| 12 | `docs/v4.1.1-final-state` | `641a1f4` | `docs/V4.1.1-FINAL-STATE.md` — 1-page executive summary |
| 13 | `docs/v4.1.1-commits-index` | `cd62a38` | `docs/V4.1.1-COMMITS.md` — 33 commits × 11 sections |
| 14 | `docs/sdk-v4.1.1-error-examples` | pre-existing | `examples/sdk-error-handling-v4.1.1/` (+466 lines, 4 SDKs) |
| 15 | `docs/v4.1.1-announcement-templates` | `605554e` | `docs/ANNOUNCEMENT-TEMPLATES-v4.1.1.md` — 10 platforms |

After: re-run verify — preflight should be **0 FAIL**, 4-SDK parity should be **0 FAIL** (assuming Tier 1 merged cleanly).

### Tier 3 — Process + index + archive (60 min, 19 PRs)

**Safe order: chore → docs(process) → docs(index) → docs(archive)**.
None of these conflict with code, but they're ordered by dependency: CODEOWNERS needs all 4 SDK code present (Tier 1), PR template references CODEOWNERS, etc.

**chore (7 PRs)**:
| # | Branch | Commit | What it ships |
|---|--------|--------|---------------|
| 16 | `chore/editorconfig-v4.1.1` | `c66e99f` | `.editorconfig` (cross-editor consistency) |
| 17 | `chore/codeowners-v4.1.1` | `f2122c0` | `.github/CODEOWNERS` (4-SDK routing) |
| 18 | `chore/pr-template-v4.1.1` | `9539784` | `.github/PULL_REQUEST_TEMPLATE.md` (V4.1.1-era, 30+ areas, 14 SDK items) |
| 19 | `chore/issue-templates-v4.1.1` | `2f24995` | `.github/ISSUE_TEMPLATE/` (bug + feature, V4.1.1) |
| 20 | `chore/vscode-settings-v4.1.1` | `bc9f20c` | `.vscode/settings.json` |
| 21 | `chore/vscode-launch-v4.1.1` | `744149d` | `.vscode/launch.json` |
| 22 | `chore/vscode-tasks-v4.1.1` | `be10b39` | `.vscode/tasks.json` |

**docs(process + index + archive) (12 PRs)**:
| # | Branch | Commit | What it ships |
|---|--------|--------|---------------|
| 23 | `docs/awaiting-user-v13` | `5ba6130` | `AWAITING-USER.md V13` (the merge roadmap) |
| 24 | `docs/roadmap-v4.1.1-sdk-parity-status` | `8ab4670` | `ROADMAP-post-1.0.md` (13/13 status table) |
| 25 | `docs/architecture-v4.1.1` | `f54325b` | `ARCHITECTURE.md` (V4.1.1 SDK parity, 22 PR state) |
| 26 | `docs/verify-v4.1.1` | `2f62c93` | `VERIFY.md` (795 tests + verify-all) |
| 27 | `docs/contributing-v4.1.1` | `d14f6a7` | `CONTRIBUTING.md` |
| 28 | `docs/security-v4.1.1-update` | `283b213` | `SECURITY.md` (cert-as-session + SDK redaction) |
| 29 | `docs/agents-md-broker-onboarding` | `715ba09` | `AGENTS.md` (15.4 KB onboarding) |
| 30 | `docs/faq-v4.1.1` | `3e85bbb` | `docs/FAQ.md` (10 Q&As) |
| 31 | `docs/runbook-v4.1.1` | `c90b48f` | `docs/RUNBOOK-v4.1.1.md` (8-step release manual) |
| 32 | `docs/releases-index-v4.1.1` | `de2a866` | `RELEASES.md` (6-release index) |
| 33 | `docs/docs-index-v4.1.1` | `00863a2` | `docs/DOCS-INDEX.md` (72 files, 290 KB) |
| 34 | `docs/v4.1-complete-archive-v4.1.1` | `e6bc69d` | `V4.1-COMPLETE.md` (V4.1.0 SUPERSEDED + V4.1.1 appendix) |

After: re-run verify — expect **0 FAIL + 0 WARN**, exit code 0. Repo is GA-ready.

## 2. Merge commands (PowerShell on Windows)

```powershell
# 0. Start clean on master
cd E:\broker
git checkout master
git pull --rebase origin master

# 1-34. Merge each PR. Pattern:
#   git merge --no-ff origin/<branch> -m "merge: <branch> into master (#N)"
# 
# If conflict: cd to the feature branch, git rebase origin/master, resolve,
#              push back, then come back to master and retry merge.

# Bulk merge via loop (verify each before next):
$branches = @(
  'feat/release-preflight-check',
  'feat/verify-sdk-v4.1.1-parity',
  'release/v4.1.1',
  'release/v4.1.1-sdk-parity-notes',
  'feat/sdk-python-exceptions-v4.1.1',
  'feat/sdk-go-errors-v4.1.1',
  'feat/sdk-cli-errors-v4.1.1',
  'feat/sdk-vscode-errors-v4.1.1',
  # ... (full list above)
)
foreach ($b in $branches) {
  Write-Host "=== Merging $b ===" -ForegroundColor Cyan
  git merge --no-ff "origin/$b" -m "merge: $b into master"
  if ($LASTEXITCODE -ne 0) {
    Write-Host "CONFLICT on $b — abort and rebase" -ForegroundColor Red
    git merge --abort
    break
  }
  # Optional: re-run verify after each tier
}

# After all 34: push to origin
git push origin master
```

## 3. Post-merge verification (5 min)

```powershell
# Tier 0 done:
node scripts/verify-v4.1.1-release.mjs --strict
# Expect: preflight FAILs drop to 0; 4-SDK still 34 FAILs

# Tier 1 done:
node scripts/verify-v4.1.1-release.mjs --strict
# Expect: preflight 0 FAIL, 4-SDK FAILs drop to ~5 (docs cross-refs)

# Tier 2 done:
node scripts/verify-v4.1.1-release.mjs --strict
# Expect: 0 FAIL, 0 WARN, exit 0
```

## 4. Tag + release (10 min, Linux only — Windows can't sign binaries)

> **This step requires a Linux/macOS shell.** The `scripts/release/v4.1.1.sh` builds 8 platform-specific assets (Linux + macOS + Windows for x64 + arm64) that bash signs.

```bash
# On a Linux host (or WSL on Windows):
git clone https://github.com/tyj1987/broker.git /tmp/broker-v4.1.1
cd /tmp/broker-v4.1.1
git checkout v4.1.0    # or master if already merged
# (Re-apply the 34 PRs if you haven't merged yet, or just use master if you have)

git tag -a v4.1.1 -m "V4.1.1 GA — see RELEASE-NOTES-v4.1.1.md"
git push origin v4.1.1

bash scripts/release/v4.1.1.sh --upload --publish
# Builds 8 assets + MANIFEST.md, uploads to GitHub Release id <auto>
# Uses RELEASE-NOTES-v4.1.1.md as release body
```

## 5. Post-release (52trz.com deploy + announce, 20 min)

```bash
# 5a. Upgrade 52trz.com V3.8.0 → V4.1.1 (zero-downtime)
ssh root@52trz.com
cd /opt/broker
git fetch && git checkout v4.1.1
npm ci --production
sudo systemctl restart broker
mavis cert login --client admin  # smoke
# See DEPLOY-52TRZ.md for full sequence

# 5b. Announce (10 platforms)
# Open docs/ANNOUNCEMENT-TEMPLATES-v4.1.1.md, copy each section to:
#   - email (Gmail/Outlook)
#   - Slack #broker-releases
#   - Twitter / X
#   - LinkedIn
#   - Hacker News (Show HN)
#   - GitHub Discussion
#   - status page
#   - internal wiki
#   - 2 more (per template)
```

## 6. After all 5 steps: close-out

Once V4.1.1 is on GitHub Release and 52trz.com is on V4.1.1:

1. Update AWAITING-USER.md → V14 (kick off V4.1.2 patch prep, see `feat/v4.1.2-patch-prep`)
2. Sync 12 in-progress Notion tasks → done (broker V4.1.1 release)
3. Create V4.1.1-COMPLETE.md (post-release summary, ~10 KB) — replaces V4.1.1 appendix in V4.1-COMPLETE.md
4. (Optional) ROADMAP-post-1.0.md → add V4.1.1 column with delivery date 2026-09-06, link to release
5. (Optional) Schedule cron: V4.1.1 upgrade reminder for 52trz.com users (V3.8.0 → V4.1.1)

---

## Appendix: Why this cheatsheet exists

`AWAITING-USER.md V13` is the **status document** — it explains *what* needs to happen and *why* (10 sections, ~15 KB).
`RUNBOOK-v4.1.1.md` is the **operational manual** — it explains *how* to do the post-merge release (8 steps, 12 KB).
This file is the **executable cheatsheet** — one-pager you can paste commands from, organized by tier.

If you only have 30 minutes: **Tier 0 + Tier 1** gets you a technically releasable V4.1.1. Tier 2-3 are docs polish.
If you have 2 hours: do all 4 tiers, then run `verify-v4.1.1-release.mjs --strict` and expect exit 0.
