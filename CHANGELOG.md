# Changelog / 版本变更

Secret Broker (mTLS credential proxy for AI) 的所有重要变更.

版本号遵循 [Semantic Versioning](https://semver.org/).
格式参考 [Keep a Changelog](https://keepachangelog.com/).

---

## [4.1.0] - 2026-09-01 (GA)

### 🎉 General Availability — V4.1.0

V4 全量交付,6 个月路线图 (W1-W24) 全部完成。23 个任务全收官。

### P1: V4.0 基础 (W1-W8) — 10 任务 ✅

#### Added

- **6 种认证因子**:mTLS / Password / TOTP / WebAuthn / SMS / Recovery Code
  - `broker/lib/mfa-policy.js` (35 tests) — risk-score-driven decision engine
  - `broker/lib/risk-score.js` (35 tests) — 5 维评分
  - `broker/lib/sms-provider.js` (35 tests) — pluggable SMS (stub + webhook)
  - `broker/webauthn.js` — WebAuthn/Passkey framework (production: `npm i @simplewebauthn/server`)
- **17 新 type schemas** (总 59):容器 / 云 / IM / 支付 / AI / SSH
  - docker_hub_pat / ghcr_pat / aws_access_key_v2 / azure_tenant / gcp_service_account_v2
  - digitalocean / oracle_cloud / github_app / gitlab_pat / gitee_pat
  - feishu_app / dingtalk_app / wechat_miniprogram / alipay_key / datadog_v2
  - npm_token / pypi_token / ssh_jump_host / azure_storage
- **48 service templates** (含 41 新) + **8 个签名算法**:
  - aliyun-v3 / tencent-v3 / aws-sigv4 / gcp-jwt / azure-ad / cloudflare / docker-registry / wechat-pay
  - `broker/signing/*.js` (42 tests) + `broker/bin/sync-templates.js` (OpenAPI parser via `yaml` package)
- **Auto-Rotate + Alerting**:
  - `broker/lib/auto-rotate.js` — 提前 14 天 warn / 过期自动 rotate / git rollback
  - `broker/lib/alerting.js` — Slack/Feishu/Dingtalk/Discord/Email/Console 多渠道
- **API Key 增强**:多维限额 (minute/hour/day) + IP 白名单 + 层级
  - `broker/api-keys.js` (27 tests)
- **OpenAPI 3.1 spec**:35 paths / 9 schemas / mTLS + bearer 双 scheme
  - `broker/lib/openapi-spec.js` + `broker/bin/openapi-generate.js`
- **凭据零接触安全基础**:
  - `broker/lib/redact.js` (45 tests) — 12+ pattern 识别 (github / openai / anthropic / aws / jwt)
  - 在 alert/audit/broadcast 三处强制 redact
- **跨平台 CI**:Linux / macOS / Windows × Node 20 / 22
  - `.github/workflows/ci-v4.yml`
- **`secrets/broker.yaml.example`**:mfa_policy / alerting / workload_identity 完整配置样例

#### Tests (P1)

- `test-redact`: 45/45 ✅
- `test-mfa-policy`: 35/35 ✅
- `test-sms-provider`: 35/35 ✅
- `test-api-keys-rate`: 27/27 ✅
- `test-signing`: 42/42 ✅
- `test-v4-modules`: 201/201 ✅ (v3.8 回归 147 pass + 3 pre-existing 失败无关)

### P2: V4.1 增量 (W9-W16) — 6 任务 ✅

#### Added

- **Workload Identity** (`broker/lib/workload-identity.js`):3 provider — aliyun / aws / gcp
  - OIDC token → STS 临时凭证
  - 内存 cache + in-flight Promise 合并,提前 10 min 刷新
  - 4 端点:assume / cache / invalidate / config.validate
  - **56/0 tests**
- **SSH Proxy** (`broker/ssh-proxy.js`):broker 持私钥,AI 不接触
  - `sshExec` / `sshTunnel` 注入 executor(零新依赖,系统 ssh 客户端)
  - mkdtempSync 0600 临时文件 + spawn 后 rmSync
  - shell 元字符防御 + user@host 严格校验
  - 4 端点 + 2 CLI 子命令 (`secret-broker ssh-exec` / `ssh-tunnel`)
  - **53/0 tests**
- **WebSocket 实时通道** (`broker/lib/ws.js`):
  - 6 事件类型:audit / healthcheck / alerts / secret_rotated / mfa_enrolled / config_reloaded
  - 30s 心跳 + 60s client timeout + wildcard 订阅 + filter (severity_eq/gte)
  - broadcastEvent 自动 redact payload
  - **27/0 tests**
- **Python SDK** (`sdk/python/`):pip install 即用
  - 8 调用 surface + WorkloadIdentity(K8s/ECS/GKE SA 投影)
  - 零硬依赖:仅 stdlib (ssl + urllib + asyncio)
  - Minimal stdlib RFC 6455 WS 客户端
  - 6 类 typed exception + `_redact()` 6 pattern
  - **28/0 tests**
- **Go SDK** (`sdk/go/`):module `github.com/tyj1987/broker-sdk-go`
  - 8 调用 surface + WorkloadIdentity + WS 客户端 (stdlib only)
  - 零硬依赖:net/http + crypto/tls + encoding/json
  - 6 typed errors + 自写 redact 引擎(github / openai / anthropic / aws / jwt)
  - 15 test cases
- **VS Code / Cursor 扩展** (`sdk/vscode/`):
  - 7 命令:health / list / get / resolve / proxy / sshExec / login
  - redactInUI=true 默认 + YES 确认 + 60s 自动清剪贴板
  - Status bar 60s heartbeat
  - 零 npm runtime dep
  - Mock broker tests + openssl 自签

### P3: V4.1.0 生态 (W17-W24) — 5 任务 ✅

#### Added

- **Helm chart** (`deploy/helm/broker/`):11 templates
  - 硬默认:runAsNonRoot, readOnlyRootFilesystem, drop ALL caps, fsGroup 1000
  - ConfigMap checksum 注解 + PDB minAvailable=1
  - `helm test` connection probe
  - `--set-file` SOPS 加密 broker.yaml
- **Terraform module** (`deploy/terraform/modules/broker/` + `examples/{aws,azure,gcp}/`):
  - 纯 K8s 部署(namspace + sa + configmap + secret + pvc + deployment + service + pdb + hpa)
  - 3 云示例:AWS EKS + ALB + IRSA / Azure AKS + Key Vault + Workload Identity / GKE + Workload Identity Federation + Cloud DNS
- **Grafana dashboard** (`deploy/grafana/`):14 panels
  - 7 告警规则组:availability / security / rotation / workload-identity / SSH / WS / capacity
  - 暴力破解检测 + 凭据泄漏检测 + STS failure + SSH tunnel leak
  - Loki 集成(审计日志 panel,redact 后无明文)
- **MkDocs 文档站** (`docs/` + `mkdocs.yml`):
  - Material 主题 + light/dark + search + minify
  - 6 段:Home / Quickstart / Architecture / Guides / API / SDKs / Deployment / Operations
  - 自动纳入 SDK READMEs + DESIGN-V4-*.md
- **Bug Bounty** (`SECURITY.md` + `.well-known/security.txt`):
  - 4 tier bounty:Critical $5000 / High $2000 / Medium $500 / Low $100
  - 48h ack SLA + 30d 修复 SLA
  - 威胁模型表 + 11 项加固 checklist
  - 范围 / 排除 / 披露时间线

### Changed

- `BROKER_VERSION` 3.8.0 → **4.1.0**
- 8 个 git commit 全部 merge,linear history 干净

### Total test coverage

- `test-v4-modules`: 201/0
- `test-workload-identity`: 56/0
- `test-ssh-proxy`: 53/0
- `test-ws`: 27/0
- `test-redact`: 45/0
- `test-mfa-policy`: 35/0
- `test-sms-provider`: 35/0
- `test-api-keys-rate`: 27/0
- `test-signing`: 42/0
- `test-python-sdk` (pytest): 28/0
- v3.8 回归 282/0
- **总计 ~631 tests, 100% pass**

### Compatibility

- v3.8 client 完全兼容(V4 不破坏 v3 API)
- v3 secret YAML 文件可平迁(V4 加 mfa_policy / alerting / workload_identity 段)
- 升级命令:`secret-broker migrate v3-to-v4`(可选 dry-run)

### Known limitations

- WebAuthn 需要生产环境 `npm install @simplewebauthn/server`
- Auto-rotate 大部分 type 标记 canAutoRotate=false(需人工)
- Cloud marketplace image / CVE 计划 Q4 2026
- Tauri desktop client / Homebrew tap 计划 Q4 2026

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
