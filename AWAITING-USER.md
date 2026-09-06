# ⏸ Awaiting user — 2026-09-06 (session 4)

broker **V4.1.1 patch** + **P2 #7 Homebrew tap formula** + **P2 #8 Snap/apt/winget manifests** + **P2 #6 Tauri desktop Phase 1 scaffold** 都已推 origin, **等 user 审 4 个 PR**。

---

## 1. V4.1.1 patch (P2 #9) — PR ready

- **Branch**: `origin/release/v4.1.1` @ de88c01 (2 commits ahead master)
  - `c8598e9` cherry-pick `f3a7cc7` (broker mTLS cert-as-session)
  - `de88c01` release: V4.1.1 patch (14 files, 383 / 46)
- **PR URL**: https://github.com/tyj1987/broker/pull/new/release/v4.1.1
- **Tests**: 629/0 (broker 601 + Python SDK 28)
- **Audit**: `npm audit --omit=dev` = 0 vulnerabilities
- **DEP0187 修**: broker 启动零 stderr warning
- **User 决断 (5+5+5 min)**: 审 PR → merge → tag v4.1.1 → GitHub Release (8 assets) → (optional) 52trz.com 升级

---

## 2. Homebrew tap formula (P2 #7) — PR ready

- **Branch**: `origin/feat/homebrew-tap-prep` @ 07d1c8f (2 commits, 4 files, +534 / -3)
- **PR URL**: https://github.com/tyj1987/broker/pull/new/feat/homebrew-tap-prep
- **ROADMAP §7 PARTIAL**: formula + docs ready
- **User 决断 (10 min)**: 建 `tyj1987/homebrew-broker` GitHub repo + 推 formula + 算 SHA256 + `brew audit --strict` + merge PR

---

## 3. Snap / apt / winget manifests (P2 #8) — PR ready

- **Branch**: `origin/feat/snap-apt-winget-prep` @ 7782f2f (2 commits, 19 files, +1079 / -26)
- **PR URL**: https://github.com/tyj1987/broker/pull/new/feat/snap-apt-winget-prep
- **ROADMAP §8 PARTIAL**: 3 manifests + 1 build script + 3 README ready
- **User 决断 (30-60 min maintainer work, 1-4 周审核)**: Snap (snapcraft upload) + apt PPA (gem install fpm + dput) + winget-pkgs (PR microsoft/winget-pkgs)

---

## 4. Tauri desktop Phase 1 scaffold (P2 #6) — PR ready

- **Branch**: `origin/feat/tauri-desktop-spec` @ 8562375 (1 commit, 15 files, +857 / -6)
- **PR URL**: https://github.com/tyj1987/broker/pull/new/feat/tauri-desktop-spec
- **ROADMAP §6 PARTIAL**: Phase 1 spec + scaffold done
- **Range**: docs/DESIGN-TAURI-DESKTOP.md (15 KB) + desktop/ (Tauri 2.x + Solid.js + Rust scaffold, "Hello broker" page)
- **Open questions** (see docs §8): 5 个需要 user 决断
  1. License: MIT vs closed-source
  2. Distribution: Tauri updater first, then Snap/winget?
  3. Mobile: keep separate (Swift/Kotlin per P3 #11) or Tauri mobile
  4. CLI: sidecar binary (Tauri embed) or Rust port
  5. Multi-tenant: single-tenant first (推荐) or multi-tenant from start
- **User 决断 (审 + merge, ~10 min)**: 审 spec + scaffold → merge PR → user 决定要不要 14 周全职推 Phases 2-6
- **V0.1.0 alpha target**: 2026-12-15 (Phases 1-4)
- **V1.0.0 GA target**: 2027-Q1 (Phases 1-6)

---

## 资源 ready

- **Local broker**: stopped (port 8443 free)
- **Tests passed**: 629/0 (V4.1.1)
- **4 PRs ready** (等 user 审):
  - `origin/release/v4.1.1` @ de88c01
  - `origin/feat/homebrew-tap-prep` @ 07d1c8f
  - `origin/feat/snap-apt-winget-prep` @ 7782f2f
  - `origin/feat/tauri-desktop-spec` @ 8562375
- **52trz.com**: V3.8.0, uptime 15+ days (still waiting V3→V4 upgrade — 跟 V4.1.1 无关)
- **本地脏树**: 7 untracked (secrets-detail / 水电站材料 / lease_schedule / sdk/vscode/out / .pytest-tmp / broker/docs) — 仍待 user 决断"进主干/丢弃/仅私有运维"

## ROADMAP post-1.0 推进状态

- ✅ P0 #1 Real CI on GH
- ✅ P0 #2 Real GitHub release (V4.1.0)
- 🔄 P1 #3 Cloud marketplace (大活, 5 marketplace, 6-12 周)
- 🔄 P1 #4 SOC 2 Type 1 (大活, 8-12 周)
- 🔄 P1 #5 ISO 27001 Annex A (大活, 4-6 周)
- 🔄 **P2 #6 Tauri desktop** — PARTIAL (Phase 1 done, 14 周全职待 Phases 2-6)
- 🔄 **P2 #7 Homebrew tap** — PARTIAL (formula ready, 等 user tap repo)
- 🔄 **P2 #8 Snap/apt/winget** — PARTIAL (manifests ready, 等 user 推 registries)
- ✅ **P2 #9 V4.1.1 patch** — DONE (PR ready)
- 🔄 P2 #10 V4.1.2 patch (target 2027-01-31, 远期)
- 🔄 P3 #11 Mobile clients (target 2027-03-31)
- 🔄 P3 #12 V4.2.0 (target 2027-06-30)
- 🔄 P3 #13 Marketplace self-service (target 2027-06-30)
