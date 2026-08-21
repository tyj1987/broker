# Changelog / 版本变更

Secret Broker (mTLS credential proxy for AI) 的所有重要变更.

版本号遵循 [Semantic Versioning](https://semver.org/).
格式参考 [Keep a Changelog](https://keepachangelog.com/).

---

## [3.3.0] - 2026-08-21

### 概述

**Phase B 模块化（第一批）**：从 `server.js` 抽出可独立测试的基础设施，零新依赖。
`server.js` 行为暂不变；后续 PR 再接线并删除内联副本。

### Added

- `broker/lib/sops.js` — `sopsDecrypt` / `sopsEncryptAtomic`
- `broker/lib/http.js` — `send` / `readBody` / `jsonError`（`X-Broker-Version` 读自 `BROKER_VERSION`）
- `broker/lib/zip.js` — `buildZip` / `computeCrc32`
- `broker/lib/audit.js` — `createAudit(auditDir)` → audit / read / SSE bus
- `broker/lib/rate-limit.js` — `parseRateLimit` / `createRateLimiter`
- `broker/lib/index.js` — 统一 re-export
- `broker-test/test-lib-phase-b.js`
- `docs/PHASE-B-MODULARIZE.md` — 目标目录与 B.2 路由拆分计划

### Changed

- `broker/package.json` / `version.js` → **3.3.0**

### Next

- Phase B.2：`routes/*` 按域拆分 + `server.js` 改为 import 新 lib 并删重复实现
- 仍建议本地跑一次 Phase A 的 `apply-phase-a-server-wire.mjs`（若尚未接线）

---

## [3.2.0] - 2026-08-21

### 概述

**Phase A 加固**：版本对齐、证书默认 90 天、API Key IP 白名单基础设施。
不引入新 npm 依赖。

### Added

- `broker/version.js` — 单一版本源
- `broker/lib/ip-allowlist.js` — 精确 IP + IPv4 CIDR 匹配
- `api-keys.isClientIpAllowed`
- `broker-test/test-ip-allowlist.js`
- `scripts/broker/apply-phase-a-server-wire.mjs`
- `docs/PHASE-A-SERVER-WIRE.md`

### Changed

- `cert-issuer` 默认 **90 天**
- `package.json` → 3.2.0

---

## [3.1.2] - 2026-08-16

（历史条目见仓库更早 commit。）
