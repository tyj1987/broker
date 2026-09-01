# Changelog / 版本变更

Secret Broker (mTLS credential proxy for AI) 的所有重要变更.

版本号遵循 [Semantic Versioning](https://semver.org/).
格式参考 [Keep a Changelog](https://keepachangelog.com/).

---

## [4.0.0-design] - 2026-09-01 (设计阶段)

### 概述

**V4 设计定稿**：AI-First 凭据管理平台。

- **6 种认证因子**：mTLS / Password / TOTP / WebAuthn / SMS / Recovery(从 2 升到 6)
- **40+ 服务商模板**：从 6 升到 40+,覆盖代码/AI/云/容器/CDN/支付/通信/数据库/监控/SSH
- **8 种调用入口**：CLI / SDK (Node+Python+Go) / MCP / REST / WebSocket / SSH / OIDC / Skill
- **风险评分 + MFA Policy**：5 维评分,动态要求 0-2 因子
- **Auto-Rotate 引擎**：凭据到期前 14 天告警,自动 rotate,1-click rollback
- **Workload Identity**：K8s/ECS Pod 0 AK,broker 取 STS 临时凭证
- **SDK Sync 工具**：从 OpenAPI 自动同步 30+ 服务商最新格式
- **100% OpenAPI 3.1 schema**:SDK 自动生成
- **零信任纵深防御**:6 个不变量 + STRIDE 威胁建模 + 5 类 IR 剧本

### 文档

- `docs/DESIGN-V4-MASTER-PLAN.md` (主设计)
- `docs/DESIGN-V4-IDENTITY-MFA.md` (身份认证 + MFA)
- `docs/DESIGN-V4-PROVIDER-TEMPLATES.md` (40+ 模板)
- `docs/DESIGN-V4-API-CALLING-STANDARDS.md` (8 种调用入口 + OpenAPI)
- `docs/DESIGN-V4-SECURITY-MODEL.md` (零信任 + IR)
- `docs/DESIGN-V4-ROADMAP.md` (6 个月实施路线图)
- `docs/QUICKSTART.md` (5 分钟上手)

### 兼容性

- v3.8 client 完全兼容(V4 不破坏 v3 API)
- 升级路径:`secret-broker migrate v3-to-v4` 一键迁移

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
