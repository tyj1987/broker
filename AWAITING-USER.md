# ⏸ Awaiting user — 2026-09-06 (12 PR 累计)

broker **V4.1.0 GA** 后续 12 个 PR 全部推到 `origin/`, **等 user 主导决策** (merge + tag + release + marketplace 提交)。

---

## 概览 (12 PR in origin)

| # | Branch | Commit | ROADMAP | 工作量 | User work |
|---|---|---|---|---|---|
| 1 | `release/v4.1.1` | de88c01 | P2 #9 ✅ | 1 critical fix + 1 startup clean, 629/0 tests | merge + tag v4.1.1 + GitHub Release (8 assets) |
| 2 | `feat/homebrew-tap-prep` | 07d1c8f | P2 #7 | Formula + 3 docs, 534 lines | 建 homebrew-broker repo + 推 formula + brew audit |
| 3 | `feat/snap-apt-winget-prep` | 7782f2f | P2 #8 | 3 manifests + 1 build script + 3 README, 1079 lines | snapcraft upload + dput PPA + winget-pkgs PR |
| 4 | `feat/tauri-desktop-spec` | 95f2f2d | P2 #6 | Design + scaffold, 939 lines | 决定要不要 14 周全职推 Phase 2-6 |
| 5 | `feat/security-controls-mapping` | 6347ae2 | P1 #4 #5 | 2 mapping docs (36 KB) | 决定 pen test 预算 ($30-80k) + auditor 委托 ($50-150k) |
| 6 | `feat/cloud-marketplace-prep` | 566d821 | P1 #3 | 5-marketplace spec + AWS Packer + CFN, 1065 lines | build AMI + AWS Marketplace partner 申请 |
| 7 | `feat/v4.2.0-design-spec` | a9bfcfd | P3 #12 | 4 features design, 546 lines | 决定要不要 12-15 周全职推 V4.2.0 |
| 8 | `feat/mobile-clients-design-spec` | 601e492 | P3 #11 | iOS + Android design, 296 lines | 决定要不要 6 个月全职推 iOS + Android |
| 9 | `feat/marketplace-self-service-design` | 1798898 | P3 #13 | 3rd-party provider design, 431 lines | 决定要不要 19 周全职推 V4.3.0 |
| 10 | `feat/v4.1.2-patch-prep` | 4c84422 | P2 #10 | 6-phase prep + SLA, 344 lines | 社区反馈收集 + auto-rotate cache (1 week) |
| 11 | `docs/contributing-v4-update` | b62c9c2 | (community) | 17 KB V4 贡献指南 | merge 后社区参与者有清晰流程 |
| 12 | `feat/release-v4.1.1-script` | f19558a | (devops) | 14.5 KB release automation | merge 后 V4.1.1 release 1 command |

**总输出**: 12 PR / 15 files docs / ~183 KB 总内容

---

## 🔥 Critical path (1 个, P2 #9)

### 1. V4.1.1 patch (5+5+5+5 min)

- **Branch**: `origin/release/v4.1.1` @ de88c01
- **PR URL**: https://github.com/tyj1987/broker/pull/new/release/v4.1.1
- **What**: 1 critical fix (mTLS cert-as-session, cherry-pick f3a7cc7) + 1 startup clean (DEP0187 DeprecationWarning) + version bump 4.1.0→4.1.1 (7 files) + tests + docs
- **Tests**: 629/0 (broker 601 + Python SDK 28)
- **Audit**: `npm audit --omit=dev` = 0 vulnerabilities
- **Reviewer needed**: 1 (tyj1987) — small surgical patch

**Steps**:
```bash
# 1. Review PR (5 min)
gh pr view release/v4.1.1 --web

# 2. Merge to master (1 min)
gh pr merge release/v4.1.1 --squash --delete-branch

# 3. Tag + push (1 min)
git checkout master && git pull
git tag -a v4.1.1 -m "V4.1.1 GA — security & correctness patch (mTLS cert-as-session)"
git push origin v4.1.1

# 4. Build 8 release assets (5 min, automated by scripts/release/v4.1.1.sh)
# Pre-req: PR #12 (release-v4.1.1-script) must be merged first
git pull
bash scripts/release/v4.1.1.sh              # build + SHA + MANIFEST
cat release-assets/MANIFEST.md             # review

# 5. Create GitHub Release + upload 8 assets (5 min)
gh release create v4.1.1 \
  --title "V4.1.1 — security & correctness patch" \
  --notes-file RELEASE-NOTES-v4.1.1.md \
  --target master
# Then upload 8 assets via gh release upload v4.1.1 <asset> --clobber
# (or use: bash scripts/release/v4.1.1.sh --upload)

# 6. (Optional) 52trz.com V4.1.0 → V4.1.1 upgrade (5 min, zero-downtime)
ssh user@broker.52trz.com "cd /opt/secret-broker && git fetch && git checkout v4.1.1 && npm install --omit=dev && systemctl restart secret-broker"
curl.exe -sk https://broker.52trz.com:8443/health
# Expect: {"version":"4.1.1", ...}
```

**Acceptance**: `version: "4.1.1"` in `/health` response, no test failures, 0 vulns.

---

## 📦 Marketplace / distribution (4 个, P1 #3 + P2 #7 #8)

### 2. Homebrew tap (10 min, P2 #7)

- **Branch**: `origin/feat/homebrew-tap-prep` @ 07d1c8f
- **PR URL**: https://github.com/tyj1987/broker/pull/new/feat/homebrew-tap-prep
- **What**: 3 files (`deploy/homebrew/broker.rb` + `README.md` + `docs/HOMEBREW.md`)

**Steps**:
```bash
# 1. Create GitHub repo tyj1987/homebrew-broker (public, MIT license)
gh repo create tyj1987/homebrew-broker --public --license MIT

# 2. Clone + push formula
git clone https://github.com/tyj1987/homebrew-broker.git
cd homebrew-broker
mkdir Formula
cp ../broker/deploy/homebrew/broker.rb Formula/

# 3. Compute SHA-256 of V4.1.1 tarball
SHA=$(curl -sL https://github.com/tyj1987/broker/archive/refs/tags/v4.1.1.tar.gz | shasum -a 256 | awk '{print $1}')
echo "SHA256: $SHA"

# 4. Edit Formula/broker.rb — replace PLACEHOLDER_SHA256_V4_1_1_TARBALL with $SHA
$EDITOR Formula/broker.rb

# 5. Commit + push
cat > README.md <<'EOF'
# tyj1987/homebrew-broker
Homebrew tap for [Secret Broker](https://github.com/tyj1987/broker).
brew tap tyj1987/broker
brew install broker
EOF
git add Formula/broker.rb README.md
git commit -m "feat: add broker formula v4.1.1"
git push origin master

# 6. Verify
brew tap tyj1987/broker
brew install --build-from-source tyj1987/broker/broker
brew test tyj1987/broker/broker
brew audit --strict tyj1987/broker/broker

# 7. Merge PR in broker repo
gh pr merge feat/homebrew-tap-prep --squash --delete-branch
```

**Acceptance**: `brew install tyj1987/broker/broker` succeeds on macOS + Linux.

### 3. Snap / apt / winget (30-60 min, 1-4 周审核, P2 #8)

- **Branch**: `origin/feat/snap-apt-winget-prep` @ 7782f2f
- **PR URL**: https://github.com/tyj1987/broker/pull/new/feat/snap-apt-winget-prep
- **What**: 19 files (3 manifests + 1 build script + 3 README + 1 zh-CN user guide)

**Sub-step 3a: Snap Store (~10 min, 1-2 周审核)**:
```bash
sudo snap install snapcraft --classic
sudo snap install lxd && lxd init --auto
# Edit snap/snapcraft.yaml — replace PLACEHOLDER_SHA256_V4_1_1_TARBALL with real hash
cd broker && snapcraft
snapcraft login
snapcraft upload --release=edge secret-broker_4.1.1_amd64.snap
# (等 Microsoft 审核 1-2 周) → snapcraft release 推到 stable
```

**Sub-step 3b: Launchpad PPA (~30 min, 1-4 小时 build)**:
```bash
gem install fpm
for arch in amd64 arm64 armhf; do
  ARCH=$arch bash deploy/apt/build-deb.sh
done
debsigs --sign=origin secret-broker_4.1.1-1_amd64.deb
dput ppa:tyj1987/broker secret-broker_4.1.1-1_amd64.changes
# (等 5-15 min/arch Launchpad build) → PPA live
```

**Sub-step 3c: winget-pkgs (~10 min, 1-4 周 Microsoft 审核)**:
```bash
git clone https://github.com/tyj1987/winget-pkgs.git
mkdir -p manifests/t/tyj1987/broker/4.1.1/
cp broker/winget/tyj1987.broker.* manifests/t/tyj1987/broker/4.1.1/
# Edit manifests — replace PLACEHOLDER_SHA256 with V4.1.1 zip SHA
git checkout -b tyj1987-broker-4.1.1
git add manifests/t/tyj1987/broker/4.1.1/
git commit -m "New package: tyj1987.broker version 4.1.1"
git push origin tyj1987-broker-4.1.1
# Open PR microsoft/winget-pkgs (审核 1-4 周)
```

**Acceptance**: 3 registries list `broker` / `secret-broker` / `tyj1987.broker`.

### 6. Cloud marketplace — 5 marketplaces (1-3 weeks, P1 #3)

- **Branch**: `origin/feat/cloud-marketplace-prep` @ 566d821
- **PR URL**: https://github.com/tyj1987/broker/pull/new/feat/cloud-marketplace-prep
- **What**: 7 files (5-marketplace spec + AWS Packer template + CloudFormation)

**Sub-step 6a: AWS Marketplace (~10 min maintainer + 1-4 周 AWS 审核, target 2026-10-15)**:
```bash
# 1. Install Packer
brew install hashicorp/tap/packer  # or download from packer.io

# 2. Build AMI
cd broker
packer init deploy/packer/
cat > variables.pkrvars.hcl <<EOF
region          = "us-east-1"
broker_version  = "4.1.1"
instance_type   = "t3.small"
ami_name_prefix = "secret-broker"
share_account_ids = ["<your-test-aws-account-id>"]
EOF
packer build -var-file=variables.pkrvars.hcl deploy/packer/aws-broker.pkr.hcl

# 3. Test launch (via CloudFormation)
aws cloudformation deploy \
  --template-file deploy/packer/cfn-template.yaml \
  --stack-name secret-broker-test \
  --parameter-overrides InstanceType=t3.small SSHKeyName=<keypair> \
                       VpcId=<vpc> SubnetId=<subnet> BrokerVersion=4.1.1 \
  --capabilities CAPABILITY_IAM
aws cloudformation wait stack-create-complete --stack-name secret-broker-test

# 4. Verify /health
BROKER_URL=$(aws cloudformation describe-stacks --stack-name secret-broker-test \
  --query 'Stacks[0].Outputs[?OutputKey==`BrokerURL`].OutputValue' --output text)
curl -k "$BROKER_URL/health"
# Expect: {"status":"ok","version":"4.1.1",...}

# 5. Cleanup
aws cloudformation delete-stack --stack-name secret-broker-test

# 6. Submit to AWS Marketplace Management Portal
#    (https://aws.amazon.com/marketplace/management/tour/)
#    Steps: Create server product → AMI us-east-1 + us-west-2 + eu-west-1 →
#    Categories: Security > Identity & Access Management →
#    Pricing: BYOL ($0) + $0.10/hour option →
#    EULA: standard AWS Marketplace EULA →
#    Support: broker@52trz.com, 48h response →
#    Submit (审核 1-4 weeks)
```

**Sub-steps 6b-6e** (Azure / GCP / Aliyun / Tencent): follow same pattern after AWS approved, sequential 1 week apart.

**Acceptance**: 5 marketplace listings live, install count tracked in `BrokerCacheStat`.

---

## 📋 Design specs (4 个, P3 #11 #12 #13 + P2 #6)

### 4. Tauri desktop (P2 #6)
- **Branch**: `origin/feat/tauri-desktop-spec` @ 95f2f2d
- **What**: 15 KB design + scaffold (`desktop/` Rust workspace + Solid.js)
- **Decision needed**: 14-week full-time investment for Phases 2-6 (mTLS client, REST/WS, tray, auto-update, polish). Or defer to community contributors.

### 7. V4.2.0 (P3 #12)
- **Branch**: `origin/feat/v4.2.0-design-spec` @ a9bfcfd
- **What**: 4 features (per-tenant rate limit + ABAC + secret versioning + approval workflow), 18 KB design
- **Decision needed**: 12-15 week full-time implementation. Or break into smaller RFCs (e.g. just ABAC, just secret versioning).

### 8. Mobile clients (P3 #11)
- **Branch**: `origin/feat/mobile-clients-design-spec` @ 601e492
- **What**: 15 KB iOS Swift + Android Kotlin design
- **Decision needed**: 6 months full-time, $125 upfront + $99/year (Apple Developer). Or start with iOS only first.

### 9. Marketplace self-service (P3 #13)
- **Branch**: `origin/feat/marketplace-self-service-design` @ 1798898
- **What**: 16 KB 3rd-party provider publish design (V4.3.0)
- **Decision needed**: 19-week full-time. Or split: registry repo first (2 weeks), CLI subcommands (6 weeks), first 5 community templates (4 weeks).

### 10. V4.1.2 patch prep (P2 #10)
- **Branch**: `origin/feat/v4.1.2-patch-prep` @ 4c84422
- **What**: 12 KB V4.1.2 prep (6-phase plan + bug bounty pipeline + auto-rotate cache design)
- **Decision needed**: 4.5 weeks full-time starting 2027-01-01. Or implement auto-rotate cache now (1 week) without waiting.

### 5. Security controls (P1 #4 #5)
- **Branch**: `origin/feat/security-controls-mapping` @ 6347ae2
- **What**: 36 KB mapping (ISO 27001: 93 controls, 39% implemented; SOC 2: 65 criteria, 46% implemented)
- **Decision needed**: budget $80-230k for SOC 2 Type 1 readiness (pen test $30-80k + auditor $50-150k). Or self-attest with bug bounty only.

**For all 6 design specs**: user reads design, decides whether to invest in implementation. If yes, decide if full-time or community-driven.

---

## 🛠️ DevOps / community (2 个)

### 11. CONTRIBUTING.md V4
- **Branch**: `origin/docs/contributing-v4-update` @ b62c9c2
- **What**: 17 KB V4.1+ contribution guide (12 sections: issues, code, style, architecture, testing, templates, SDKs, WebAuthn approval, audit format, release, review, community)
- **Decision needed**: 5 min review + merge. Improves community contribution clarity.

### 12. V4.1.1 release script
- **Branch**: `origin/feat/release-v4.1.1-script` @ f19558a
- **What**: 14.5 KB bash script (8 assets build + SHA-256 + auto-MANIFEST.md + optional `--upload` to GitHub Release)
- **Decision needed**: 5 min review + merge. **Required for V4.1.1 release** (script #12 is a dependency of release #1).

---

## 📅 Recommended order (by user ROI)

### Week 1 (high-impact + low-risk)
1. **#12 release-v4.1.1-script** (5 min) — prerequisite for #1
2. **#1 V4.1.1 patch** (15 min) — actual code fix landing
3. **#1 V4.1.1 release** (10 min) — tag + GitHub Release + 8 assets
4. **#2 homebrew-tap-prep** (10 min) — easiest marketplace

### Week 2-3 (medium effort, high reach)
5. **#11 CONTRIBUTING.md V4** (5 min) — quick win
6. **#3 snap-apt-winget-prep** (1-4 weeks) — 3 registries
7. **#6 cloud-marketplace-prep** (1-4 weeks) — AWS Marketplace

### Week 4-12 (low effort, long timeline)
8. **#10 v4.1.2-patch-prep** (1-2 weeks) — auto-rotate cache + community feedback
9. **#5 security-controls-mapping** (1-3 weeks) — pen test + auditor engagement
10. **#4 #7 #8 #9 design specs** — review only, decide on investment (Q2-Q3 2027)

---

## 🏗️ Backend state

- **Local broker**: stopped (port 8443 free)
- **Tests passed**: 629/0 (V4.1.1)
- **git tags**: v4.1.0 (annotated, on origin)
- **Origin branches**: 12 PR branches (all synced)
- **52trz.com**: V3.8.0, uptime 15+ days (still waiting V3→V4 upgrade — separate from V4.1.1)

## 📦 Local dirty tree (still untracked, separate decision)

7 untracked files (待 user 决断"进主干/丢弃/仅私有运维"):
- `secrets/secrets-detail.json` (明文 secrets, 不能进开源)
- `水电站融资租赁方案_1亿_15年.md` + `.xlsx` (私人材料)
- `lease_schedule_hydropower.py` + `_excel.py` (个人项目)
- `sdk/vscode/out/` (编译产物, 应该 gitignore)
- `sdk/python/.pytest-tmp/` (测试临时目录, 应该 gitignore)
- `broker/docs/` (autogen 目录, 应该 gitignore)

**Recommended .gitignore additions**:
```
sdk/vscode/out/
sdk/python/.pytest-tmp/
broker/docs/
```

**Recommend discard**:
```
secrets/secrets-detail.json   # 安全:含明文 secrets
水电站融资租赁方案_1亿_15年.{md,xlsx}  # 私人材料
lease_schedule_hydropower*.py  # 个人项目
```

**Decision**: 1 line in this file counts as the audit trail. No git operations until user 决断.

---

## 🔗 Refs

- **12 PR URLs**: 上面 table
- **Documentation**:
  - [STATUS.md](STATUS.md) — V4.1.0 GA sentinel
  - [ARCHITECTURE.md](ARCHITECTURE.md) — broker architecture
  - [CHANGELOG.md](CHANGELOG.md) — version history
  - [CONTRIBUTING.md](CONTRIBUTING.md) — V4 contribution guide
  - [ROADMAP-post-1.0.md](ROADMAP-post-1.0.md) — 13 P0-P3 items
  - [SECURITY.md](SECURITY.md) — bug bounty
  - [DEPLOY-52TRZ.md](DEPLOY-52TRZ.md) — 52trz.com V3→V4 (separate)
- **Design docs** (10+ in `docs/`):
  - `DESIGN-V4-ROADMAP.md`, `DESIGN-V4-MASTER-PLAN.md`, `DESIGN-V4-SECURITY-MODEL.md` (V4 era)
  - `DESIGN-V4.2.0.md` (V4.2.0, P3 #12)
  - `DESIGN-MOBILE-CLIENTS.md` (P3 #11)
  - `DESIGN-MARKETPLACE-SELF-SERVICE.md` (P3 #13)
  - `DESIGN-TAURI-DESKTOP.md` (P2 #6)
  - `CLOUD-MARKETPLACE.md` (P1 #3)
  - `SECURITY-CONTROLS-ISO27001.md` (P1 #5)
  - `SECURITY-CONTROLS-SOC2.md` (P1 #4)
  - `V4.1.2-PATCH-PREP.md` (P2 #10)
  - `HOMEBREW.md`, `SNAP-APT-WINGET.md` (P2 #7 #8 user guides)
  - `RELEASE-NOTES-v4.1.1.md` (P2 #9 release body)
  - `V4.1-COMPLETE.md` (V4.1.0 per-task plan vs actual)
  - `VERIFY.md` (1-line verification)
  - `FAQ.md` (16 Q&A)

---

**Maintainer**: tyj1987
**Last updated**: 2026-09-06 20:46 SGT
**Session count**: 12 (~12 hours)
**Total PRs queued**: 12
**Estimated total user work**: 1-4 weeks (depending on how many marketplaces + design implementation)
