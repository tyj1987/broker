# ⏸ Awaiting user — 2026-09-06 (session 3)

broker **V4.1.1 patch** + **P2 #7 Homebrew tap formula** + **P2 #8 Snap/apt/winget manifests** 都已推 origin, **等 user 审 3 个 PR**。

---

## 1. V4.1.1 patch (P2 #9) — PR ready

- **Branch**: `origin/release/v4.1.1` @ de88c01 (2 commits ahead master)
  - `c8598e9` cherry-pick `f3a7cc7` (broker mTLS cert-as-session)
  - `de88c01` release: V4.1.1 patch (14 files: version bump + 1 critical fix + 1 startup clean + tests + docs)
- **PR URL**: https://github.com/tyj1987/broker/pull/new/release/v4.1.1

### 范围

| Type | Item |
|------|------|
| **Fix** | mTLS cert-as-session (cherry-pick f3a7cc7) |
| **Fix** | test:phase-f-backup-probes `BROKER_VERSION === '4.1.0'` → `'4.1.1'` |
| **Fix** | broker startup DEP0187 DeprecationWarning (server.js line 168/210: `if (AGE_KEY_FILE && existsSync(AGE_KEY_FILE))`) |
| **Change** | Version bump 4.1.0 → 4.1.1 (7 files: broker + 4 SDKs) |
| **Docs** | CHANGELOG [4.1.1] + RELEASE-NOTES-v4.1.1.md + ROADMAP §9 done + STATUS.md + AWAITING-USER.md |

### 数字证据

- Tests: **629/0** (broker 601 + Python SDK 28)
- Audit: `npm audit --omit=dev` = **0 vulnerabilities**
- Python SDK: **0 hard dependencies** (pip-audit N/A)
- Broker 启动 stderr: **零 warning** (Node 22+ DEP0187 已修)
- `X-Broker-Version=4.1.1` header 端到端 OK

### User 决断 (5 + 5 + 5 min)

1. 审 PR `release/v4.1.1` (5 min)
2. Merge → master (1 min)
3. Tag v4.1.1 + GitHub Release (8 assets, 跟 V4.1.0 同):
   ```bash
   git checkout master && git pull
   git tag -a v4.1.1 -m "V4.1.1 GA — security & correctness patch (mTLS cert-as-session)"
   git push origin v4.1.1
   # then create GitHub Release with RELEASE-NOTES-v4.1.1.md as body + 8 assets
   ```
4. (Optional) 52trz.com V4.1.0 → V4.1.1 升级 (5 min, 零停机)

---

## 2. Homebrew tap formula (P2 #7) — PR ready

- **Branch**: `origin/feat/homebrew-tap-prep` @ 07d1c8f (2 commits)
  - `7ed68ef` feat(homebrew): add formula
  - `07d1c8f` chore(roadmap): §7 PARTIAL
- **PR URL**: https://github.com/tyj1987/broker/pull/new/feat/homebrew-tap-prep
- **3 files** (534 lines): `deploy/homebrew/broker.rb` + `deploy/homebrew/README.md` + `docs/HOMEBREW.md`
- **ROADMAP §7**: PARTIAL (formula + docs ready)

### User 决断 (建 homebrew-broker tap, 10 min)

1. 建 GitHub repo `tyj1987/homebrew-broker` (公开 MIT)
2. 推 formula (3 步 cp + commit + push)
3. 算 V4.1.1 tarball SHA256 + 替换 placeholder
4. `brew audit --strict tyj1987/broker/broker` 验证
5. Merge PR `feat/homebrew-tap-prep` → master

---

## 3. Snap / apt / winget manifests (P2 #8) — PR ready

- **Branch**: `origin/feat/snap-apt-winget-prep` @ 08b1c7e (1 commit)
  - `08b1c7e` feat(packaging): add Snap / apt / winget manifests
- **PR URL**: https://github.com/tyj1987/broker/pull/new/feat/snap-apt-winget-prep
- **18 files** (~21 KB, 941 insertions): `snap/` + `deploy/apt/` + `winget/` + `docs/SNAP-APT-WINGET.md`
- **ROADMAP §8**: PARTIAL (3 manifests + 1 build script + 3 README ready)

### User 决断 (3 registries, 1-4 周 审核周期, 但 maintainer work 10-30 min/each)

#### Snap Store (~10 min maintainer work, 1-2 周审核)
```bash
sudo snap install snapcraft --classic
sudo snap install lxd
lxd init --auto
# 算 V4.1.1 source SHA256 + 替换 placeholder in snap/snapcraft.yaml
cd /path/to/broker && snapcraft
snapcraft login
snapcraft upload --release=edge secret-broker_4.1.1_amd64.snap
# (等 1-2 周 Microsoft 审核) → promote to stable
```

#### Launchpad PPA (~30 min maintainer work, 1-4 小时 Launchpad build)
```bash
# GPG key + Launchpad account: 10 min
# gem install fpm
bash deploy/apt/build-deb.sh           # build 当前 arch
for arch in amd64 arm64 armhf; do
  ARCH=$arch bash deploy/apt/build-deb.sh
done
debsigs --sign=origin secret-broker_4.1.1-1_amd64.deb
dput ppa:tyj1987/broker secret-broker_4.1.1-1_amd64.changes
# (等 5-15 min/arch Launchpad build) → PPA live
```

#### winget-pkgs (~10 min maintainer work, 1-4 周 Microsoft 审核)
```bash
# Fork + clone microsoft/winget-pkgs
mkdir -p manifests/t/tyj1987/broker/4.1.1/
cp winget/tyj1987.broker.* manifests/t/tyj1987/broker/4.1.1/
# 算 V4.1.1 zip SHA256 + 替换 placeholder
git checkout -b tyj1987-broker-4.1.1
git add manifests/t/tyj1987/broker/4.1.1/
git commit -m "New package: tyj1987.broker version 4.1.1"
git push origin tyj1987-broker-4.1.1
# (PR 提 https://github.com/microsoft/winget-pkgs/compare) → 1-4 周审核
```

---

## 资源 ready

- **Local broker**: stopped (port 8443 free)
- **Tests passed**: 629/0 (V4.1.1)
- **3 PRs ready** (等 user 审):
  - `origin/release/v4.1.1` @ de88c01
  - `origin/feat/homebrew-tap-prep` @ 07d1c8f
  - `origin/feat/snap-apt-winget-prep` @ 08b1c7e
- **52trz.com**: V3.8.0, uptime 15+ days (still waiting V3→V4 upgrade — 跟 V4.1.1 无关)
- **本地脏树**: 7 untracked (secrets-detail / 水电站材料 / lease_schedule / sdk/vscode/out / .pytest-tmp / broker/docs) — 仍待 user 决断"进主干/丢弃/仅私有运维"

## ROADMAP post-1.0 推进状态

- ✅ P0 #1 Real CI on GH
- ✅ P0 #2 Real GitHub release (V4.1.0)
- 🔄 P1 #3 Cloud marketplace (大活, 5 marketplace, 6-12 周)
- 🔄 P1 #4 SOC 2 Type 1 (大活, 8-12 周)
- 🔄 P1 #5 ISO 27001 Annex A (大活, 4-6 周)
- 🔄 P2 #6 Tauri desktop client (大活, 6-8 周)
- 🔄 **P2 #7 Homebrew tap** — PARTIAL (formula ready, 等 user tap repo)
- 🔄 **P2 #8 Snap/apt/winget** — PARTIAL (manifests ready, 等 user 推 registries)
- ✅ **P2 #9 V4.1.1 patch** — DONE (PR ready)
- 🔄 P2 #10 V4.1.2 patch (target 2027-01-31, 远期)
- 🔄 P3 #11 Mobile clients (target 2027-03-31)
- 🔄 P3 #12 V4.2.0 (target 2027-06-30)
- 🔄 P3 #13 Marketplace self-service (target 2027-06-30)
