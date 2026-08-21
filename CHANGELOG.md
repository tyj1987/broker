# Changelog / 版本变更

Secret Broker (mTLS credential proxy for AI) 的所有重要变更.

版本号遵循 [Semantic Versioning](https://semver.org/).
格式参考 [Keep a Changelog](https://keepachangelog.com/).

---

## [3.2.0] - 2026-08-21

### 概述

**Phase A 加固**（分支 `optimize/phase-a-hardening`）：版本对齐、证书默认 90 天、API Key IP 白名单基础设施。
不引入新 npm 依赖。

### Added

- `broker/version.js` — `BROKER_VERSION = 3.2.0` 单一版本源
- `broker/lib/ip-allowlist.js` — 精确 IP + IPv4 CIDR 匹配（零依赖）
- `api-keys.isClientIpAllowed(k, remoteIp)` — 供 server 鉴权调用
- `broker-test/test-ip-allowlist.js` — allowlist 单元测试
- `docs/PHASE-A-SERVER-WIRE.md` — server.js 5 处接线清单

### Changed

- `broker/package.json` version `2.0.0` → `3.2.0`
- `cert-issuer.issueClientCert` 默认有效期 **365 → 90 天**（`DEFAULT_CERT_DAYS`）
- 返回值增加 `days` 字段便于审计

### Security

- API Key `ip_whitelist` 字段此前仅存储未校验；现提供完整匹配实现，server 接线后即可生效
- 明文 password → scrypt 仍由启动时 `migrate-v2-to-v3` 幂等处理（既有行为）

### 待接线（见 PHASE-A-SERVER-WIRE.md）

- server.js 中 `X-Broker-Version` / banner / `issueAndPersist({days:365})` / `getApiKeyIdentity` IP 检查

---

## [3.1.2] - 2026-08-16

（历史条目见仓库 master；本文件在 phase-A 分支以 3.2.0 为最新条目。）
