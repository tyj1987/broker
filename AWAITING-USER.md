# ⏸ Awaiting user — 2026-09-06 (session 2)

broker **V4.1.1 patch** + **P2 #7 Homebrew tap formula** 都已推 origin, **等 user 审 PR**。

---

## 1. V4.1.1 patch (P2 #9) — PR ready

- **Branch**: `origin/release/v4.1.1` (2 commits ahead master)
  - `c8598e9` cherry-pick `f3a7cc7` (broker mTLS cert-as-session)
  - `84bbb0a` release: V4.1.1 patch (14 files: version bump + 1 critical fix + 1 startup clean + tests + docs)
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

### User 决断 (按优先级)

1. **审 PR** (5 min): 看 `release/v4.1.1` 的 2 commit + 14 file diff
2. **Merge 到 master** (1 min): `gh pr merge --squash` 或 web 端 merge
3. **Tag v4.1.1** (1 min):
   ```bash
   git checkout master && git pull
   git tag -a v4.1.1 -m "V4.1.1 GA — security & correctness patch (mTLS cert-as-session)"
   git push origin v4.1.1
   ```
4. **GitHub Release** (5 min, 跟 V4.1.0 同样的 8 assets):
   - `RELEASE-NOTES-v4.1.1.md` 作 body
   - 8 assets: source tarball + zip, Python wheel + sdist, 4 Go SDK binaries
5. **(Optional) 52trz.com V4.1.0 → V4.1.1** (5 min): 零停机, 零 schema 改
   ```bash
   ssh user@broker.52trz.com "cd /opt/secret-broker && git fetch && git checkout v4.1.1 && npm install --omit=dev && systemctl restart secret-broker"
   curl.exe -sk https://broker.52trz.com:8443/health
   ```

---

## 2. Homebrew tap formula (P2 #7) — PR ready

- **Branch**: `origin/feat/homebrew-tap-prep` (2 commits ahead master)
  - `7ed68ef` feat(homebrew): add formula
  - `07d1c8f` chore(roadmap): §7 PARTIAL
- **PR URL**: https://github.com/tyj1987/broker/pull/new/feat/homebrew-tap-prep
- **3 files** (534 lines): `deploy/homebrew/broker.rb` + `deploy/homebrew/README.md` + `docs/HOMEBREW.md`
- **ROADMAP §7**: PARTIAL (formula + docs ready, awaiting user to publish tap)

### User 决断 (建 homebrew-broker tap repo, 10 min)

1. **建 GitHub repo** `tyj1987/homebrew-broker` (公开, MIT license)
   - https://github.com/organizations/tyj1987/repositories/new
2. **本地 clone + 推 formula**:
   ```bash
   git clone https://github.com/tyj1987/homebrew-broker.git
   cd homebrew-broker
   mkdir Formula
   cp ../broker/deploy/homebrew/broker.rb Formula/broker.rb
   # 算 SHA256: curl -L https://github.com/tyj1987/broker/archive/refs/tags/v4.1.1.tar.gz | shasum -a 256
   # 编辑 Formula/broker.rb: 替换 PLACEHOLDER_SHA256_V4_1_1_TARBALL 为真实 hash
   # 写 README.md (参考 deploy/homebrew/README.md §"第一次发布")
   git add Formula/broker.rb README.md
   git commit -m "feat: add broker formula v4.1.1"
   git push origin master
   ```
3. **`brew audit` 验证**:
   ```bash
   brew tap tyj1987/broker
   brew install --build-from-source tyj1987/broker/broker
   brew test tyj1987/broker/broker
   brew audit --strict tyj1987/broker/broker
   ```
4. **Merge PR** `feat/homebrew-tap-prep` 到 master (1 min)

### 已知公式限制

- 第一次 release 用 `--build-from-source` (慢); 后续可以本地 build bottle 推 GitHub Release 加速
- 没 bottle: 安装耗时 ≈ 3-5 分钟 (含 Node 20 下载)
- 没 manpage: `secret-broker --help` 已足够 (7 命令)

---

## 资源 ready

- **Local broker**: stopped (port 8443 free)
- **Tests passed**: 629/0 (V4.1.1)
- **V4.1.1 branch**: `origin/release/v4.1.1` (PR ready, 2 commits)
- **Homebrew prep branch**: `origin/feat/homebrew-tap-prep` (PR ready, 2 commits)
- **52trz.com**: V3.8.0, uptime 15+ days (still waiting V3→V4 upgrade — 跟 V4.1.1 无关)
- **本地脏树**: 7 untracked (secrets-detail / 水电站材料 / lease_schedule / sdk/vscode/out / .pytest-tmp / broker/docs) — 仍待 user 决断"进主干/丢弃/仅私有运维"
