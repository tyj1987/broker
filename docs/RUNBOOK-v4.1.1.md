# V4.1.1 Release Runbook

> **Step-by-step manual for shipping broker V4.1.1.**
> Use after merging all V4.1.1 PRs per [AWAITING-USER.md V13](../AWAITING-USER.md).
>
> **Audience**: maintainer with merge access + a Linux/macOS shell (release script
> is bash; preflight is Node.js cross-platform).
>
> **Time budget**: ~30 min (10 min for review + 5 min for tag + 5 min for build +
> 5 min for upload + 5 min for smoke).

---

## Pre-release checklist (read first)

Before running the release:

- [ ] **All 4 SDK V4.1.1 PRs merged** (Python 9a0c5f7, Go 6052779, CLI ba6da09, VSCode f0a6dd1).
- [ ] **release/v4.1.1 merged** to master (broker fix + version bump + 14 files).
- [ ] **4 docs/release PRs merged** (SDK-REFERENCE 20c5e6d, AWAITING-USER V13 5ba6130,
       ROADMAP 8ab4670, SDK-UPGRADE-GUIDE 172682a, RELEASE-NOTES + CHANGELOG + STATUS
       b3fb75c / 4222d76).
- [ ] **preflight script passes** — `node scripts/preflight-v4.1.1.mjs` returns 0.
- [ ] **`scripts/release/v4.1.1.sh` exists** (from PR `f19558a`).
- [ ] **No uncommitted local changes** (`git status` clean).
- [ ] **On master branch** with all 27 PRs in.

If any item is unchecked, **STOP** and follow [AWAITING-USER.md V13 §"推荐 merge 顺序"](../AWAITING-USER.md#推荐-merge-顺序-8-10-步共-70-min).

---

## Step 1 — Preflight (2 min)

```bash
# Verify the release is ready to ship
node scripts/preflight-v4.1.1.mjs
```

**Expected output**: All checks PASS, exit code 0. If any FAIL or WARNING
(without `--strict` you can ignore warnings), the script tells you exactly
which file/branch is missing. Fix and re-run.

```bash
# Strict mode (warnings = fail) — recommended for release
node scripts/preflight-v4.1.1.mjs --strict
```

---

## Step 2 — Tag v4.1.1 (3 min)

```bash
# Make sure you're on master with all V4.1.1 PRs merged
git checkout master
git pull origin master

# Verify HEAD is the release commit (broker fix + 4 SDK V4.1.1 + 4 SDK parity docs)
git log --oneline -10

# Tag the release (annotated tag, signed if you have a GPG key configured)
git tag -a v4.1.1 -m "V4.1.1 GA — see RELEASE-NOTES-v4.1.1.md

Includes:
- broker: mTLS cert-as-session fix + DEP0187 startup clean + version bump
- 4 SDKs: unified BrokerError + parseBrokerError + retry (5xx/429/connection)
  + auto-redact body on construction
- 166 SDK tests (was 54, +112)
- Backward compatible with V4.1.0"

# Push the tag
git push origin v4.1.1
```

**Expected output**: `To https://github.com/tyj1987/broker.git
* [new tag] v4.1.1 -> v4.1.1`

If you see `Tag v4.1.1 already exists`, someone (you, in a prior run) already
tagged. Use `git tag -d v4.1.1 && git push origin :refs/tags/v4.1.1` to delete
the local + remote tag, then re-tag.

---

## Step 3 — Build release assets (5-10 min)

```bash
# Build 8 assets + SHA-256 + MANIFEST.md
bash scripts/release/v4.1.1.sh
```

**Expected output**:

```
==> Preflight checks
✓ git
✓ node
✓ python3
✓ pip
✓ go
✓ zip
==> Git tag v4.1.1 verified at abc1234
==> Building source tarball...
✓ release-assets/broker-4.1.1-src.tar.gz
==> Building source zip...
✓ release-assets/broker-4.1.1-src.zip
==> Building Python wheel...
✓ sdk/python/dist/secret_broker-4.1.1-py3-none-any.whl
==> Building Python sdist...
✓ sdk/python/dist/secret_broker-4.1.1.tar.gz
==> Building Go SDK binaries (4 platforms)...
✓ sdk/go/bin/broker-cli-linux-amd64
✓ sdk/go/bin/broker-cli-linux-arm64
✓ sdk/go/bin/broker-cli-darwin-amd64
✓ sdk/go/bin/broker-cli-windows-amd64.exe
==> Computing SHA-256 for 8 assets...
✓ release-assets/MANIFEST.md
```

**Time**: ~5-10 minutes (Python build 30s + Go cross-compile 4 × 30s + git archive 5s).

If anything fails, the script exits with non-zero and prints the failing
command. Common failures:

- **`openssl not found`**: install via `apt install openssl` / `brew install openssl`.
- **`go: command not found`**: install Go 1.22+ from https://go.dev/dl/.
- **`python3 not found`**: install Python 3.9+ from https://python.org.

---

## Step 4 — Verify SHA-256 (1 min)

```bash
# Inspect the MANIFEST
cat release-assets/MANIFEST.md
```

**Expected output** (8 assets + SHA-256 + sizes):

```markdown
# Broker V4.1.1 Release Manifest

Generated 2026-09-06T12:34:56Z

| Asset | Size | SHA-256 |
|-------|------|---------|
| broker-4.1.1-src.tar.gz | 1.2 MB | abc123... |
| broker-4.1.1-src.zip | 1.4 MB | def456... |
| secret_broker-4.1.1-py3-none-any.whl | 23 KB | ... |
| secret_broker-4.1.1.tar.gz | 18 KB | ... |
| broker-cli-linux-amd64 | 8.4 MB | ... |
| broker-cli-linux-arm64 | 8.0 MB | ... |
| broker-cli-darwin-amd64 | 8.4 MB | ... |
| broker-cli-windows-amd64.exe | 8.5 MB | ... |
```

**Verify locally** (optional):

```bash
# On Linux/macOS:
shasum -a 256 release-assets/*.{tar.gz,zip,whl,exe}

# On Windows PowerShell:
Get-FileHash release-assets\*.tar.gz, *.zip, *.whl, *.exe -Algorithm SHA256
```

The hash output should match MANIFEST.md exactly.

---

## Step 5 — Upload to GitHub Release (3 min)

```bash
# Authenticate `gh` CLI first (if not already)
gh auth status

# Upload + auto-publish (skips draft)
bash scripts/release/v4.1.1.sh --upload --publish
```

**Expected output**:

```
==> Uploading 8 assets to GitHub Release v4.1.1...
✓ Source code (zip)
✓ Source code (tar.gz)
✓ Python wheel
✓ Python sdist
✓ Linux AMD64 binary
✓ Linux ARM64 binary
✓ macOS AMD64 binary
✓ Windows AMD64 binary
==> Release v4.1.1 published: https://github.com/tyj1987/broker/releases/tag/v4.1.1
```

**If you want to review the release first** (draft mode):

```bash
# Upload as draft (no auto-publish)
bash scripts/release/v4.1.1.sh --upload

# Then visit https://github.com/tyj1987/broker/releases and review
# Click "Publish release" when ready
```

**GitHub API rate limit**: 5000/hr for authenticated users. Should not be
an issue for 8 assets.

---

## Step 6 — Smoke test (2 min)

Verify the release is downloadable + has correct SHA-256:

```bash
# Download the source tarball
curl -L -o /tmp/broker-4.1.1.tar.gz https://github.com/tyj1987/broker/archive/refs/tags/v4.1.1.tar.gz

# Verify SHA-256
shasum -a 256 /tmp/broker-4.1.1.tar.gz
# Should match release-assets/MANIFEST.md "broker-4.1.1-src.tar.gz" row.

# Extract + verify version
mkdir -p /tmp/broker-test && tar -xzf /tmp/broker-4.1.1.tar.gz -C /tmp/broker-test --strip-components=1
cd /tmp/broker-test
cat broker/version.js
# Should print: module.exports = { BROKER_VERSION: '4.1.1', ... };
```

**Expected**: tarball extracts cleanly, version file shows `4.1.1`.

---

## Step 7 — Production upgrade (52trz.com, 5 min, optional)

> Skip if you don't run a production instance. The release ships whether
> or not you upgrade your own install.

```bash
# SSH into the production host
ssh user@broker.52trz.com

# Backup (safety net)
sudo cp -a /opt/secret-broker/secrets /opt/secret-broker/secrets.bak.$(date +%Y%m%d)
sudo cp -a /opt/secret-broker/pki /opt/secret-broker/pki.bak.$(date +%Y%m%d)
sudo cp -a /opt/secret-broker/audit /opt/secret-broker/audit.bak.$(date +%Y%m%d)

# In-place upgrade (zero downtime, zero schema change)
cd /opt/secret-broker
sudo git fetch
sudo git checkout v4.1.1
sudo npm install --omit=dev   # install only prod deps
sudo systemctl restart secret-broker

# Smoke
sleep 3
curl -k --cert /opt/secret-broker/pki/clients/admin.crt \
        --key /opt/secret-broker/pki/clients/admin.key \
        https://broker.52trz.com:8443/health
# Expected: {"status":"ok","version":"4.1.1",...}

# Verify mavis AI agent (or similar cert-only client) can now login via mTLS
curl -k --cert /opt/secret-broker/pki/clients/mavis.crt \
        --key /opt/secret-broker/pki/clients/mavis.key \
        -c /tmp/mavis-cookies.txt \
        -X POST https://broker.52trz.com:8443/api/v1/login \
        -H 'Content-Type: application/json' \
        -d '{}'
# Expected: 200 OK + Set-Cookie: broker_session=... (V4.1.0: 403 "No password configured for this client")

# Cleanup
rm /tmp/mavis-cookies.txt
```

**Rollback** (if something goes wrong — unlikely with this patch):

```bash
cd /opt/secret-broker
sudo git checkout v4.1.0
sudo systemctl restart secret-broker
# Restore config if needed:
# sudo cp -a secrets.bak.YYYYMMDD/* secrets/
# sudo cp -a pki.bak.YYYYMMDD/* pki/
```

---

## Step 8 — Close out (5 min)

### 8a. Update Notion (if using)

Mark the 12 in-progress Notion tasks (V4.1.1 patch + 4 SDK + 4 design specs +
3 packaging) as **Done** with the release date.

### 8b. Update AWAITING-USER

The current V13 lists 27 PRs. After merging, mark each section as ✅
merged. **Do not** delete AWAITING-USER.md — it serves as audit trail.
Create V14 in 2026-10-01 for V4.1.2 prep.

### 8c. Send release announcement

```text
Subject: [broker] V4.1.1 released

Hi team,

broker V4.1.1 is GA. Highlights:
- mTLS cert-as-session fix (Mavis / Claude / Codex / etc. AI agents
  can now login via mTLS path)
- 4 SDK unified error contract (Python, Go, Node CLI, VSCode)
- Built-in retry (5xx / 429 / connection, exponential backoff)
- 0 vulnerabilities, 795 total tests
- Backward compatible with V4.1.0

Release: https://github.com/tyj1987/broker/releases/tag/v4.1.1
Upgrade guide: docs/SDK-UPGRADE-GUIDE.md
Migration: same 8 calling surfaces, no API change

Production upgrade: 5 min, zero downtime.

— Mavis
```

### 8d. Mark AWAITING-USER.md V13 sections

For each PR in V13:

```bash
# Edit AWAITING-USER.md: change "## 1. V4.1.1 patch (P2 #9) — PR ready"
# to "## 1. V4.1.1 patch (P2 #9) — ✅ merged 2026-09-06"
# ... etc for each section.

git checkout master
git add AWAITING-USER.md
git commit -m "docs(awaiting-user): V13.1 — mark V4.1.1 sections as merged"
git push origin master
```

---

## Reference

- [AWAITING-USER.md V13](../AWAITING-USER.md) — 27 PR + 8-10 步 merge 顺序
- [RELEASE-NOTES-v4.1.1.md](../RELEASE-NOTES-v4.1.1.md) — V4.1.1 GitHub Release body
- [CHANGELOG.md](../CHANGELOG.md) — V4.1.1 history entry
- [SDK-UPGRADE-GUIDE.md](SDK-UPGRADE-GUIDE.md) — V4.1.0 → V4.1.1 SDK migration
- [ROADMAP-post-1.0.md](../ROADMAP-post-1.0.md) — 13/13 items status
- [STATUS.md](../STATUS.md) — project state
- [scripts/release/v4.1.1.sh](../scripts/release/v4.1.1.sh) — bash build + upload
- [scripts/preflight-v4.1.1.mjs](../scripts/preflight-v4.1.1.mjs) — pre-tag sanity check
- [DEPLOY-52TRZ.md](../DEPLOY-52TRZ.md) — 52trz.com deployment details
- [RUNBOOK.md](../RUNBOOK.md) — general broker operations

---

**Document version**: 2026-09-06 (V4.1.1 release prep)
**Last verified**: preflight script self-test (10faca4) — 3 PASS / 8 WARN / 9 FAIL
on master before merge; will return 0 after all V4.1.1 PRs merged.
