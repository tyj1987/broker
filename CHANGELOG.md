# Changelog / 版本变更

Secret Broker (mTLS credential proxy for AI) 的所有重要变更.

版本号遵循 [Semantic Versioning](https://semver.org/).
格式参考 [Keep a Changelog](https://keepachangelog.com/).

---

## [3.6.0] - 2026-08-21

### 概述

**Phase D — 追踪与审计策略（零新依赖）**：W3C `traceparent` 续传、请求上下文（ALS）、审计采样与按天保留清理。

### Added

- `broker/lib/trace.js` — parse / continue / outbound headers
- `broker/lib/request-context.js` — `AsyncLocalStorage` request scope
- `broker/lib/audit-policy.js` — `shouldSampleAudit` / `withAuditSampling` / `pruneAuditFiles`
- Env: `AUDIT_SAMPLE_RATE`, `AUDIT_RETAIN_DAYS`
- `docs/PHASE-D-TRACING-AUDIT.md`
- `broker-test/test-phase-d-trace-audit.js`；`npm run test:trace`

### Changed

- `BROKER_VERSION` / `package.json` → **3.6.0**

### Wire

See Phase D doc — wrap `handle` with `runWithRequestContext`; inject trace headers on proxy; optional audit sampling + prune in cron.

---

## [3.5.0] - 2026-08-21

Phase C — metrics, `/ready` `/live`, JSON logs. See `docs/PHASE-C-OBSERVABILITY.md`.

---

## [3.4.0] - 2026-08-21

Phase B.5 — modular surface, `USE_MODULAR_ROUTES` opt-in.

---

## [3.3.0] / [3.2.0] - 2026-08-21

Phase B lib extract; Phase A hardening.

---

## [3.1.2] - 2026-08-16

（历史条目见仓库更早 commit。）
