# Changelog / 版本变更

Secret Broker (mTLS credential proxy for AI) 的所有重要变更.

版本号遵循 [Semantic Versioning](https://semver.org/).
格式参考 [Keep a Changelog](https://keepachangelog.com/).

---

## [3.5.0] - 2026-08-21

### 概述

**Phase C — 可观测性（零新依赖）**：进程内指标、Prometheus 文本、就绪/存活探针、结构化 JSON 日志。

### Added

- `broker/lib/metrics.js` — counters / latency histogram / `prometheusText` / `timedRequest`
- `broker/lib/log.js` — JSON 日志（`BROKER_LOG_LEVEL`）
- `broker/routes/metrics.js` — `GET /metrics`, `/metrics.json`
- `/live`, `/healthz`, `/ready`, `/readyz`（`routes/health.js`）
- `docs/PHASE-C-OBSERVABILITY.md`
- `broker-test/test-phase-c-obs.js`；`npm run test:obs`

### Changed

- `BROKER_VERSION` / `package.json` → **3.5.0**
- `PUBLIC_HANDLERS` 包含 `handleMetrics`

### Security

- 可选 `METRICS_REQUIRE_AUTH=1` 限制指标接口为 admin

---

## [3.4.0] - 2026-08-21

**Phase B.5** — 模块化表面完成，`USE_MODULAR_ROUTES` opt-in cutover。详见上一代 CHANGELOG 条目与 `docs/PHASE-B5-CUTOVER.md`。

---

## [3.3.0] / [3.2.0] - 2026-08-21

Phase B.1 lib 抽取；Phase A 加固（版本、90d 证书、IP 白名单）。

---

## [3.1.2] - 2026-08-16

（历史条目见仓库更早 commit。）
