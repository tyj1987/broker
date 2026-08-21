# Changelog / 版本变更

Secret Broker (mTLS credential proxy for AI) 的所有重要变更.

版本号遵循 [Semantic Versioning](https://semver.org/).
格式参考 [Keep a Changelog](https://keepachangelog.com/).

---

## [3.7.0] - 2026-08-21

### 概述

**Phase E — 运维加固（零新依赖）**：优雅退出（SIGTERM/SIGINT drain）、配置与路径预检。

### Added

- `broker/lib/shutdown.js` — `installGracefulShutdown` / `rejectIfShuttingDown`
- `broker/lib/config-validate.js` — `validateBrokerConfig` / `preflightPaths` / `formatValidationReport`
- Env: `SHUTDOWN_TIMEOUT_MS`（默认 15000）
- `docs/PHASE-E-OPS.md`
- `broker-test/test-phase-e-ops.js`；`npm run test:ops`

### Changed

- `BROKER_VERSION` / `package.json` → **3.7.0**

### Wire

见 `docs/PHASE-E-OPS.md`：listen 后安装 shutdown；load config 后 `validateBrokerConfig`；handle 入口 503 when draining。

---

## [3.6.0] - 2026-08-21

Phase D — traceparent、request context、审计采样/保留。见 `docs/PHASE-D-TRACING-AUDIT.md`。

---

## [3.5.0] - 2026-08-21

Phase C — metrics、ready/live、JSON logs。

---

## [3.4.0] - 2026-08-21

Phase B.5 — 模块化表面 + `USE_MODULAR_ROUTES`。

---

## [3.3.0] / [3.2.0] - 2026-08-21

Phase B lib；Phase A 加固。

---

## [3.1.2] - 2026-08-16

（历史条目见仓库更早 commit。）
