# Changelog / 版本变更

Secret Broker (mTLS credential proxy for AI) 的所有重要变更.

版本号遵循 [Semantic Versioning](https://semver.org/).
格式参考 [Keep a Changelog](https://keepachangelog.com/).

---

## [3.8.0] - 2026-08-21

### 概述

**Phase F — 备份清单与依赖探针（零新依赖）**。

### Added

- `broker/lib/backup.js` — `buildBackupManifest` / `redactConfigForExport` / `writeBackupManifest`
- `broker/lib/probes.js` — TCP/HTTP probes、`probesFromConfig`、`runProbes`
- `broker/routes/ops.js` — admin `backup-manifest` / `config-export`
- `/ready` 支持 `deps.runReadyProbes`
- Env: `READY_PROBES=0` 关闭探针
- `docs/PHASE-F-BACKUP-PROBES.md`
- `npm run test:backup`

### Changed

- `BROKER_VERSION` / `package.json` → **3.8.0**

---

## [3.7.0] - 2026-08-21

Phase E — graceful shutdown、config preflight。见 `docs/PHASE-E-OPS.md`。

---

## [3.6.0] – [3.2.0] - 2026-08-21

Phases D–A：追踪/审计、可观测、模块化、加固。

---

## [3.1.2] - 2026-08-16

（历史条目见仓库更早 commit。）
