# Changelog / 版本变更

Secret Broker (mTLS credential proxy for AI) 的所有重要变更.

版本号遵循 [Semantic Versioning](https://semver.org/).
格式参考 [Keep a Changelog](https://keepachangelog.com/).

---

## [3.4.0] - 2026-08-21

### 概述

**Phase B.5 — 模块化表面完成（opt-in cutover）**。  
`routes/*` 覆盖 health / static / auth / me / secrets / services / clients / proxy；  
通过 `USE_MODULAR_ROUTES` 与接线脚本渐进切换，**默认仍走 legacy `server.js` 分支**，避免一次性大删。

### Added

- `broker/routes/secrets.js` / `services.js` / `clients.js` / `proxy.js`（B.4）
- `broker/routes/auth.js` / `me.js`（B.3）
- `broker/lib/session.js`、`lib/build-route-deps.js`
- `PUBLIC_HANDLERS` / `API_HANDLERS` / `dispatch`
- `scripts/broker/apply-phase-b4-server-wire.mjs`
- `scripts/broker/apply-phase-b5-cutover.mjs`
- `docs/PHASE-B5-CUTOVER.md`
- 测试：`test-routes-auth-me.js`、`test-routes-b4.js`；`npm run test:modular`

### Changed

- `BROKER_VERSION` / `package.json` → **3.4.0**

### Safety

- 零新 npm 依赖
- 未设置 `USE_MODULAR_ROUTES` 时行为与 3.3.x 对齐（在完成 Phase A/B.2 wire 的前提下）
- 删除 legacy 内联实现推迟到生产冒烟之后

---

## [3.3.0] - 2026-08-21

### 概述

**Phase B 模块化（第一批）**：从 `server.js` 抽出可独立测试的基础设施，零新依赖。

### Added

- `broker/lib/sops.js` / `http.js` / `zip.js` / `audit.js` / `rate-limit.js` / `index.js`
- `broker-test/test-lib-phase-b.js`
- `docs/PHASE-B-MODULARIZE.md`

### Changed

- `package.json` / `version.js` → **3.3.0**

---

## [3.2.0] - 2026-08-21

### 概述

**Phase A 加固**：版本对齐、证书默认 90 天、API Key IP 白名单基础设施。

### Added

- `broker/version.js`、`lib/ip-allowlist.js`、`api-keys.isClientIpAllowed`
- `broker-test/test-ip-allowlist.js`、`scripts/broker/apply-phase-a-server-wire.mjs`

### Changed

- `cert-issuer` 默认 **90 天**；`package.json` → 3.2.0

---

## [3.1.2] - 2026-08-16

（历史条目见仓库更早 commit。）
