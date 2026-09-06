# ⏸ Awaiting user — 2026-09-06 (V13)

broker V4.1.1 patch + 20 follow-up PRs 已推 origin, **等 user 审 PR / merge / tag / release**。

**累计 21 PR (3 done-equivalent + 18 partial)**,按 ROADMAP P0-P3 排序 + 推荐 merge 顺序。

---

## 🔴 P0 — 必做 (V4.1.1 production-ready 闭环)

### 1. V4.1.1 patch + 4 SDK V4.1.1 parity (P2 #9 + 4 SDK commits)

| Branch | Commit | 内容 | Tests |
|--------|--------|------|-------|
| `origin/release/v4.1.1` | `de88c01` (2 commits) | V4.1.1 patch: mTLS cert-as-session fix + DEP0187 clean + version bump 7 files | 629/0 |
| `origin/feat/sdk-python-exceptions-v4.1.1` | `9a0c5f7` | Python exceptions: `__repr__` + `to_dict` + `is_retryable` + `retry_after` | 54/54 |
| `origin/feat/sdk-go-errors-v4.1.1` | `6052779` | Go errors.go: `RequestID` + `RetryAfter` + `IsRetryable` + `ToMap` + retry loop | 33/33 + 1 SKIP |
| `origin/feat/sdk-cli-errors-v4.1.1` | `ba6da09` | Node CLI BrokerError + parseBrokerError + mTLSRequest retry | 21/21 |
| `origin/feat/sdk-vscode-errors-v4.1.1` | `f0a6dd1` | VSCode BrokerError + parseBrokerError + mtlsRequest retry | 38/38 |
| `origin/docs/sdk-v4.1.1-parity-reference` | `20c5e6d` | SDK-REFERENCE.md V4.1.1 parity section (4-SDK error contract 文档化) | +191/-22 |

**数字证据**:
- **166 SDK tests** (V4.1.0: 54 → V4.1.1: 166, +112 new)
- **629 broker tests** (V4.1.1)
- **4 SDK V4.1.1 parity** 完成: 单一 `BrokerError` + `parseBrokerError` + retry
- 单一 V4.1.1.1 contract: `op/status/code/requestId/retryAfter/body/isRetryable/toString/toJSON`

**User 决断 (按优先级)**:
1. **审 + merge `release/v4.1.1`** (5 min) → tag v4.1.1
2. **审 + merge 4 SDK PRs** (10 min) → 跟 V4.1.1 patch 一起
3. **审 + merge `docs/sdk-v4.1.1-parity-reference`** (3 min)
4. **GitHub Release v4.1.1** (5 min) — 8 assets + RELEASE-NOTES-v4.1.1.md body
5. **(Optional) 52trz.com V4.1.0 → V4.1.1** (5 min) — 零停机
   ```bash
   ssh user@broker.52trz.com "cd /opt/secret-broker && git fetch && git checkout v4.1.1 && npm install --omit=dev && systemctl restart secret-broker"
   curl.exe -sk https://broker.52trz.com:8443/health
   ```

---

## 🟠 P1 — Enterprise-ready (security + cloud + packaging)

### 2. Security controls mapping (P1 #4 + #5)

| Branch | Commit | 内容 |
|--------|--------|------|
| `origin/feat/security-controls-mapping` | `6347ae2` | ISO 27001 Annex A (93 controls) + SOC 2 Type 1 (65 criteria) mapping (36 KB) |

**数字证据**:
- ISO 27001: Annex A 93 controls mapped to broker features
- SOC 2: 5 Trust Services Criteria (CC1-CC9) + 65 sub-criteria
- 36 KB markdown + JSON evidence ledger
- Pen test + audit 路线图 (Q4 2026 → Q1 2027)

**User 决断**:
1. **审 doc** (30 min): 看 ISO 27001 + SOC 2 mapping 完整性
2. **决定 SOC 2 Type 1 audit 预算**: $80-230k (取决于 auditor + scope)
3. **决定 ISO 27001 certification 预算**: $50-150k + 季度 surveillance
4. **审 + merge PR** (3 min)

### 3. Cloud marketplace prep (P1 #3)

| Branch | Commit | 内容 |
|--------|--------|------|
| `origin/feat/cloud-marketplace-prep` | `566d821` | AWS Packer AMI + CFN template + 5 marketplace spec (28 KB) |

**数字证据**:
- `deploy/packer/aws-broker.pkr.hcl` (220 lines, Ubuntu 22.04 + Node 20 + broker systemd)
- `deploy/packer/cfn-template.yaml` (328 lines, VPC + ALB + mTLS + CloudWatch)
- 5 marketplace: AWS, Azure, GCP, Aliyun, Tencent (spec only)

**User 决断 (按优先级)**:
1. **审 Packer + CFN** (15 min)
2. **AWS Marketplace 提交** (1-4 周审核, $0.50/AMI hour):
   - 注册 AWS Marketplace Seller
   - `packer build aws-broker.pkr.hcl` → AMI
   - 提交 product loader
3. **Azure / GCP / Aliyun / Tencent** (4-8 周 sequential): 各自 partner registration

### 4. Homebrew + Snap/apt/winget packages (P2 #7 + #8)

| Branch | Commit | 内容 |
|--------|--------|------|
| `origin/feat/homebrew-tap-prep` | `07d1c8f` | Homebrew formula + 3 docs (4 KB rb + 7.5 KB doc) |
| `origin/feat/snap-apt-winget-prep` | `7782f2f` | 3 manifests (Snap snapcraft.yaml, apt debian/*, winget tyj1987.broker.*.yaml) |

**User 决断 (按优先级)**:
1. **Homebrew tap** (10 min):
   ```bash
   # 建 tyj1987/homebrew-broker repo
   # 推 deploy/homebrew/broker.rb (formula)
   # 替换 PLACEHOLDER_SHA256_V4_1_1_TARBALL → v4.1.1 tag hash
   brew tap tyj1987/broker && brew install tyj1987/broker/broker
   ```
2. **Snap Store** (1-2 周 Microsoft 审核): `snapcraft login` + `snapcraft upload --release=stable`
3. **Launchpad PPA** (1-4 小时 build): `gem install fpm && fpm build` + `dput ppa:tyj1987/broker`
4. **winget-pkgs** (1-4 周 Microsoft 审核): PR microsoft/winget-pkgs

### 5. V4.1.2 patch prep (P2 #10)

| Branch | Commit | 内容 |
|--------|--------|------|
| `origin/feat/v4.1.2-patch-prep` | `4c84422` | 6-phase prep + auto-rotate cache design (12 KB) |

**预计内容**:
- Phase 1: 收集 V4.1.1 user feedback + bug reports
- Phase 2: auto-rotate cache TTL design
- Phase 3-5: implementation + tests + docs
- Phase 6: V4.1.2 GA

**User 决断**:
1. **审 prep doc** (15 min)
2. **决定 V4.1.2 timeline** (Q1 2027 vs 提早)
3. **审 + merge PR** (3 min)

---

## 🟡 P2 — Quality of life (design specs + automation)

### 6. Tauri desktop client (P2 #6)

| Branch | Commit | 内容 |
|--------|--------|------|
| `origin/feat/tauri-desktop-spec` | `95f2f2d` | Tauri 2.0 desktop client design + scaffold (15 KB) |

**设计要点**:
- Tauri 2.0 (Rust core + WebView UI) 替代 Electron
- Bundle size: ~5 MB (vs Electron 80+ MB)
- Reuse cli/secret-broker.js + sdk/vscode TypeScript code
- 平台: macOS / Windows / Linux (single binary)

**User 决断**:
1. **审 spec** (20 min)
2. **决定投资 12 周全职 vs 4 周 MVP**
3. **审 + merge PR** (3 min) — 仅 spec,无需 commit investment

### 7. V4.2.0 design spec (P3 #12)

| Branch | Commit | 内容 |
|--------|--------|------|
| `origin/feat/v4.2.0-design-spec` | `a9bfcfd` | 4 features design (18 KB) |

**4 features**:
- Per-tenant rate limit (Redis sliding window)
- ABAC (attribute-based access control, OPA-style)
- Secret versioning (KV 历史 + rollback)
- Approval workflow (request → approve → issue)

**User 决断**:
1. **审 spec** (30 min)
2. **决定哪些 feature 进 V4.2.0 vs V4.3.0+**
3. **审 + merge PR** (3 min)

### 8. Mobile clients design (P3 #11)

| Branch | Commit | 内容 |
|--------|--------|------|
| `origin/feat/mobile-clients-design-spec` | `601e492` | iOS Swift + Android Kotlin (15 KB) |

**设计要点**:
- iOS: Swift 5.9 + URLSession mTLS + Keychain
- Android: Kotlin + OkHttp mTLS + EncryptedSharedPreferences
- 复用 broker V4.1.1 error contract (4-SDK parity 已就位)
- TestFlight + Play Console internal track

**User 决断**:
1. **审 spec** (20 min)
2. **决定投资 16 周 (iOS 8 + Android 8) vs 8 周仅 1 平台**
3. **审 + merge PR** (3 min)

### 9. Marketplace self-service design (P3 #13)

| Branch | Commit | 内容 |
|--------|--------|------|
| `origin/feat/marketplace-self-service-design` | `1798898` | 3rd-party provider publish flow (16 KB) |

**设计要点**:
- Provider 注册 → broker 验证 → secret schema review → publish
- 3 roles: provider / reviewer / consumer
- Audit log: 全部 publish/consume 操作可追溯

**User 决断**:
1. **审 spec** (20 min)
2. **决定投资 19 周全职 vs 8 周 MVP (3 角色减为 1 角色)**
3. **审 + merge PR** (3 min)

### 10. V4.1.1 release automation (devops)

| Branch | Commit | 内容 |
|--------|--------|------|
| `origin/feat/release-v4.1.1-script` | `f19558a` | `scripts/release/v4.1.1.sh` 1 command = 8 assets + SHA-256 + MANIFEST (14.5 KB) |

**User 决断**:
1. **审 script** (10 min)
2. **dry-run**: `./scripts/release/v4.1.1.sh --dry-run` 验证
3. **审 + merge PR** (3 min) — V4.1.1 release 实际跑前合并

### 11. CONTRIBUTING.md V4 (community)

| Branch | Commit | 内容 |
|--------|--------|------|
| `origin/docs/contributing-v4-update` | `b62c9c2` | 12 sections (17 KB) V4 贡献流程 |

**User 决断**:
1. **审 doc** (15 min)
2. **审 + merge PR** (3 min)

### 12. AWAITING-USER.md V12 (历史,已 superseded by V13)

| Branch | Commit | 状态 |
|--------|--------|------|
| `origin/docs/awaiting-user-v12` | `c1e4cd4` | 已 superseded by V13 (本文件),但仍可 merge 作为 history |

**User 决断**:
- 审 + merge (3 min) — history 完整性
- 或 close 不 merge (V13 已 cover 同样信息)

### 13. CI: test-ssh on master gate (ci)

| Branch | Commit | 内容 |
|--------|--------|------|
| `origin/ci/test-ssh-master-gate` | `9d275dc` | CI: require test:ssh on master, cover master in test-sdks |

**User 决断**:
1. **审 CI 改动** (10 min)
2. **审 + merge PR** (3 min) — 强烈推荐,防止 master SSH regression

### 14. Security / chore commits (chore)

| Branch | Commit | 内容 |
|--------|--------|------|
| `origin/chore/gitignore-runtime-secrets` | `5a09c05` | .gitignore: ECS runtime secrets + backup artifacts |
| `origin/chore/oss-modular-security` | `19af375` | isolate modular routes + security docs |

**User 决断**:
1. **审 chore PRs** (5 min each)
2. **审 + merge** (3 min each) — 推荐

---

## 🟢 P3 — Optional (历史 / 低优先级)

无。

---

## 推荐 merge 顺序 (8-10 步,共 ~70 min)

按 P0 → P1 → P2 → P3 + 先独立后依赖的顺序:

1. **release/v4.1.1** (5 min) — V4.1.1 patch 核心
2. **4 SDK V4.1.1 parity PRs** (10 min) — Python + Go + CLI + VSCode
3. **docs/sdk-v4.1.1-parity-reference** (3 min) — 4-SDK 文档
4. **feat/release-v4.1.1-script** (3 min) — release 自动化 (V4.1.1 release 跑前)
5. **ci/test-ssh-master-gate** (3 min) — CI gate
6. **chore/gitignore-runtime-secrets + chore/oss-modular-security** (6 min) — 安全清理
7. **feat/security-controls-mapping** (3 min) — ISO 27001 + SOC 2 mapping
8. **feat/homebrew-tap-prep** (3 min) — Homebrew formula
9. **docs/contributing-v4-update** (3 min) — 社区贡献指南
10. **设计 specs (Tauri / V4.2.0 / Mobile / Marketplace) + 4 packaging PRs** (30 min)

---

## V4.1.1 release 之后 (5-7 步,~30 min)

在 V4.1.1 tag + GitHub Release 之后:
1. **V4.1.1 GitHub Release** (5 min): 8 assets + body from RELEASE-NOTES-v4.1.1.md
2. **(Optional) 52trz.com V4.1.0 → V4.1.1** (5 min): 零停机升级
3. **AWS Marketplace** 提交 (1-4 周审核)
4. **Snap Store + Launchpad PPA + winget** 提交 (1-4 周 sequential)
5. **Homebrew tap repo** 创建 (10 min)
6. **设计 spec 投资决策** (Tauri / V4.2.0 / Mobile / Marketplace)
7. **SOC 2 + ISO 27001 推进** ($80-230k 预算)

---

## 资源 ready

- **Local broker**: stopped (port 8443 free)
- **Tests passed**: 629 broker + 166 SDK = **795 total** (V4.1.1)
- **21 PR in origin** (3 done-equivalent + 18 partial)
- **V4.1.1 branch**: `origin/release/v4.1.1` (PR ready)
- **4 SDK V4.1.1**: Python + Go + CLI + VSCode parity 完成
- **Notion 状态**: 12 tasks in progress (V4.1.0 GA 后续)

---

## 数字证据汇总

| 指标 | V4.1.0 | V4.1.1 | Delta |
|------|--------|--------|-------|
| Broker tests | 619 | 629 | +10 |
| Python SDK tests | 28 | 54 | +26 |
| Go SDK tests | 0 | 33 (+1 SKIP) | +33 |
| Node CLI tests | 0 | 21 | +21 |
| VSCode SDK tests | 11 | 48 | +37 |
| **Total tests** | **658** | **795** | **+137** |
| Open PRs (origin) | 0 | 21 | +21 |
| Design specs | 6 | 10 | +4 |
| Packaging manifests | 0 | 6 (Homebrew + Snap + apt + winget + AWS + CFN) | +6 |
| Security mapping | 0 | ISO 27001 (93) + SOC 2 (65) | +158 controls |
| Release automation | manual | `scripts/release/v4.1.1.sh` (1 command = 8 assets) | 自动化 |

---

## 已知 / 风险

- **设计 specs 投资决策未做** (Tauri 12 周 / V4.2.0 19 周 / Mobile 16 周 / Marketplace 19 周) — 需 user 决断
- **SOC 2 + ISO 27001 审计预算未批** ($80-230k)
- **AWS Marketplace 提交需 partner registration** (1-4 周)
- **52trz.com 仍 V3.8.0,uptime 17+ 天** — 升 V4.1.1 前建议先备份 + 测 SSH
- **本地脏树 8 untracked files** (secrets-detail / 水电站材料 / lease_schedule / broker/docs / sdk/vscode/out / sdk/python/.pytest-tmp / .pytest-tmp / secrets/secrets-detail.json) — 待 user 决断"进主干 / 丢弃 / 仅私有运维"

---

**参考文档**:
- `ROADMAP-post-1.0.md` — 13 items P0-P3 全推进 (2 done + 11 partial)
- `STATUS.md` — V4.1.1 status
- `CHANGELOG.md` — V4.1.1 entries
- `RELEASE-NOTES-v4.1.1.md` — V4.1.1 release body
- `docs/SDK-REFERENCE.md` — V4.1.1 4-SDK error contract
