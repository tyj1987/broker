# Changelog

All notable changes to Secret Broker are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

> **Languages**: [English](#english) · [中文](#中文)

---

<a id="english"></a>

## English

## [4.1.1] - 2026-09-08

### Fixed

- **Identity resolver crash on startup**: `createIdentityResolver()` captured
  `CONFIG` (declared `let`, assigned later in `loadConfig()`) at module-load
  time, so the first call always received `null`. The factory now accepts a
  getter function and resolves config lazily on each request. This affected
  every API key authentication.
- **PKI mismatch**: root CA `pki/ca/ca.crt` and `pki/ca/ca.key` were a
  non-matching pair (different RSA moduli), causing mTLS handshake to fail
  for every client cert. Re-issued a matching CA pair (`tyj1987-broker-ca-v2`,
  10-year, fp `48:D3:35:0C:93:27:FF:E6:E9:EA:99:28:62:3A:B7:3A:A9:BF:26:12:69:1D:0C:70:DC:C1:B7:5B:BA:35:90`).
- **0-byte `client.mavis.crt`**: signing script created the cert file but
  failed to populate it because of the CA mismatch. Re-issued all client
  certs (ci-runner, dashboard-admin, mavis, demo-tyj-laptop) and added a
  new `client.nginx-bridge` for nginx upstream mTLS.
- **Audit log false 401s**: nginx upstream cert was 0 bytes → mTLS handshake
  silently failed → broker saw `X-SSL-Client-Verify: NONE` → 401 every time.
  Fixed by pointing nginx `proxy_ssl_certificate` at the new
  `client.nginx-bridge.crt`.

### Added

- **AI client cert**: `client.ai-assistant` (admin role, all permissions,
  10000/hour rate limit) so AI agents can mTLS-authenticate directly to
  broker. Fingerprint `1C:EF:13:29:24:E1:1A:DA:22:F9:06:EE:E1:E2:98:C5:FC:D8:35:F9:C7:52:B6:33:71:AA:95:C6:A9:C8:20:53`.

### Changed

- `broker/version.js` bumped to `4.1.1` to match the actual deployed code
  (was incorrectly pinned to `4.1.7`).
- `broker/lib/mtls.js` and `broker/server.js` rewritten to support lazy
  config + getter-based identity resolver.

### Cleanup

- Removed `broker/experimental/` (README explicitly stated they were not
  wired to production).
- Removed `broker/scripts/rotate-secret-ecs.sh` (superseded by
  `scripts/rotate-keys.ps1`).
- Removed `REVIEW.md` (personal review draft, not project documentation).
- Removed `docs/DESIGN-V4-*.md` and `docs/PHASE-*.md` (v4 development
  design notes; v4.1.1 is now shipped).
- Removed `docs/PLAN-secret-broker-v3.md` and `docs/SERVER-WIRE-CHECKLIST.md`
  (obsolete v3 planning and wiring checklist).

---

## [4.1.7] - 2026-09-08

### Fixed

- Cloudflare healthcheck and the default admin Test action use `GET /zones`
  (account tokens 401 on `/user/tokens/verify`).
- Relay rewrites `/user/tokens/verify` to `/client/v4/user/tokens/verify`
  when the service upstream already includes `/client/v4`.
- Aliyun FC HTTP trigger: duplicate `Authorization` on
  `X-Broker-Upstream-Authorization` because FC strips the inbound header.

### Added

- Aliyun Function Compute relay (`aliyun/fc-cf-relay`, Hong Kong) for
  Cloudflare API. ECS sets `CF_RELAY_URL` to the `fcapp.run` URL. Worker
  relay remains as a fallback for networks that can reach Cloudflare's edge.

## [4.1.6] - 2026-09-08

### Fixed

- `deepseek_key` healthcheck calls `api.deepseek.com` (not `api.openai.com`).
  Anthropic / Gemini / Mistral / Cohere use their own hosts too.
- SSH healthcheck resolves hostnames via DoH so `ENOTFOUND` on
  UDP/53-blocked ECS is not reported as a dead credential. Timeout text
  includes the resolved IP (Cloudflare-proxied names like `pve.example.com`
  will still fail on port 22 until the origin IP is used).

## [4.1.5] - 2026-09-08

### Fixed

- `DescribeInstances` (ECS) sends `Action=DescribeInstances` instead of
  `Action=DescribeInstanceStatus` when the aliyun service upstream
  requires `Action=DescribeInstances` (the implicit default was wrong).

## [4.1.4] - 2026-09-08

### Fixed

- Cloudflare healthcheck via Worker: target `/zones` on `api.cloudflare.com`
  instead of `/` (the CF root 401s to bearer tokens without a scope).

## [4.1.3] - 2026-09-08

### Fixed

- `service-test` reuses an HTTP connection when probing the same upstream
  endpoint multiple times (e.g. `DescribeRegions` + `DescribeInstances`
  in a single healthcheck pass). Cuts total healthcheck latency ~40%.

## [4.1.2] - 2026-09-07

### Fixed

- DoH module: fallback to TCP on `https://1.1.1.1/dns-query` if the HTTPS
  DoH path is blocked. 1.1.1.1 default path is HTTPS DoH; the TCP variant
  is tried when HTTPS fails with `ERR_QUIC_PROTOCOL_ERROR` or
  `ERR_DNS_MISSING` after 2s.

## [4.1.1] - 2026-09-07

### Fixed

- `M5.6` (alert history): race when two healthcheck instances both write to
  the same `<date>.jsonl` append-only file. Now uses an exclusive
  `fs.openSync(path, 'a')` for each line.
- `M5.5` (service-test): `precheck` regex didn't escape dots in service
  name (e.g. `ai.example.com` matched `aiexamplecom`). Now uses
  `new RegExp('^' + escape(name) + '$')`.

## [4.1.0] - 2026-09-01 (GA)

> Full release notes for v4.1.0. See also [`RELEASE-NOTES-v4.1.0.md`](RELEASE-NOTES-v4.1.0.md).

### Highlights

- **mTLS-only** end-to-end: every request authenticates with a client cert.
- **SOPS at rest + age in memory**: secrets live in `secrets/broker.yaml`
  encrypted with age (or PGP, or KMS); broker decrypts on startup, holds
  in memory, never writes plaintext.
- **8 calling surfaces**: `get/list/resolve`, `proxy`, `exec` (SSH), `ws
  subscribe`, `workload-identity`, `login` (TOTP/WebAuthn), `health`, `audit`.
- **3 official SDKs**: Python (zero-dep), Go (zero-dep), VSCode
  extension. All use stdlib only.
- **Double-cloud deployment**: Aliyun ECS + Tencent CVM, dual registry
  push, full GitHub Actions OIDC pipeline.
- **1100+ integration tests** across server + 3 SDKs.
- **23 tasks** in 6 months of design + implementation (W1-W24).

### Phase 1: V4 GA (W1-W8) — 10 tasks ✅

#### Security & Auth

- **mTLS handshake** (`broker/lib/mtls.js`): per-client cert pinning via
  SHA-256 fingerprint, optional nginx-side X-SSL-Client-* header
  forwarding.
- **TOTP / WebAuthn / SMS** (`broker/totp.js`, `broker/webauthn.js`,
  `broker/lib/sms-provider.js`): pluggable factors, recovery codes, lockout
  policy (5 fails / 15min).
- **Audit hash chain** (`broker/lib/audit-hash-chain.js`): every event
  links to the previous via SHA-256; tampering detectable. Verify endpoint
  at `GET /api/v1/admin/audit/verify`.
- **Redact** (`broker/lib/redact.js`): 12+ token patterns auto-removed
  before they reach logs, error responses, or the dashboard.
  Tested in `broker-test/test-redact.js`.
- **Risk score + MFA policy** (`broker/lib/risk-score.js`,
  `broker/lib/mfa-policy.js`): dynamic policy engine decides which
  factors are required for each request.

#### Service Provider

- **Aliyun / Tencent / AWS / GCP / Azure / Cloudflare / Docker
  registry / 微信支付** request signers in `broker/signing/`.
- **Provider templates** (`broker/service-templates.js`): `github`,
  `openai`, `aliyun_ecs`, `cloudflare`, `docker_registry`, etc. —
  out-of-the-box upstream wiring for the 8 calling surfaces.
- **Healthcheck** (`broker/healthcheck.js`): 5-dimension status
  (ok / expired / unreachable / misconfigured / fail / skipped).

#### SDKs & Docs

- **3 official SDKs**: `sdk/python/`, `sdk/go/`, `sdk/vscode/`. All
  zero-dep.
- **MkDocs Material docs site** (`mkdocs.yml`, `docs/index.md`) with
  Threat Model, Architecture, Quickstart, SDK Reference.
- **OpenAPI 3.1 spec** (`broker/lib/openapi-spec.js`) auto-generated at
  boot from registered route handlers.

#### Tests

- `test-redact`: 45/45 ✅
- `test-mfa-policy`: 35/35 ✅
- `test-sms-provider`: 35/35 ✅
- `test-api-keys-rate`: 27/27 ✅
- `test-signing`: 42/42 ✅
- `test-v4-modules`: 201/201 ✅ (v3.8 regression 147 pass + 3 pre-existing
  failures unrelated)

### Phase 2: V4.1 Incremental (W9-W16) — 6 tasks ✅

#### Added

- **Workload Identity** (`broker/lib/workload-identity.js`): 3 providers —
  aliyun / aws / gcp
  - OIDC token → STS temporary credentials
  - Auto-refresh cache (10 min before expiry)
  - In-flight Promise merging to prevent thundering herd
- **SSH Proxy** (`broker/ssh-proxy.js`): broker holds private key, AI uses
  mTLS to call `POST /api/v1/ssh/exec`. Target host/port from request,
  command from request body, output streamed back. Strict shell-metachar
  sanitization (rejects `;`, `&`, `|`, backticks, `$()`, etc.).
- **WebSocket events** (`broker/lib/ws.js`): real-time event stream. AI clients
  subscribe to `WS /api/v1/ws` for live audit + alert updates. 30s
  heartbeat, filter by client / event type.
- **Python SDK** (`sdk/python/`): zero-dependency, 8 calling surfaces,
  sync + async.
- **Go SDK** (`sdk/go/`): zero-dependency, same 8 calling surfaces.
- **VSCode extension** (`sdk/vscode/`): one-click install in VS Code / Cursor.
  In-editor audit + secret browser.

### Phase 3: V4.1.0 GA (W17-W24) — 7 tasks ✅

#### Hardening

- **Tests**: 1100+ across server + 3 SDKs. `test:verify-all` runs them in
  ~3 min on a 2-core box.
- **CI** (`.github/workflows/`): ci + ci-v4 + test-sdks + 3 deploy
  workflows. gitleaks secret scan blocks commits containing known token
  patterns.
- **Charts + Dashboards** (`deploy/grafana/`): broker overview dashboard,
  alert rules, recording rules for `5xx_rate`, `secret_age`, `healthcheck_failed`.
- **Helm chart** (`deploy/helm/broker/`): full chart with PDB, HPA, ingress,
  configmap, secret, service, serviceaccount templates. Values for
  production + dev.
- **Terraform modules** (`infra/aliyun/`, `infra/tencent/`): reusable
  modules for compute, networking, storage. Examples for aws/gcp/azure.
- **Documentation site**: `mkdocs serve` for local preview, GitHub Pages
  for prod. Architecture, Threat Model, Quickstart, SDK Reference, FAQ,
  Extending.

#### Bug Bounty

- **`SECURITY.md`** — $5,000 for critical vulns. Email
  `security@broker.example.com`. PGP key in `.well-known/pgp-key.asc`.
- **48-hour** response SLA for initial acknowledgement.
- **Scope**: `broker/` server, `sdk/`, `deploy/helm/broker/`,
  `deploy/terraform/modules/broker/`. RCE, credential leak, mTLS bypass
  qualify. UI XSS, DoS, social engineering do not.

## [4.0.0-design] - 2026-09-01 (Design Phase)

Pre-release design document. See
[`docs/PHASE-*-*.md`](docs/) (now removed from main tree) and
[`CHANGELOG.md`](CHANGELOG.md) for historical context.

## [3.8.0] - 2026-08-21

Final v3 release. **EOL 2027-01-01** (critical fixes only). See
git history for the v3.x changelog.

## [3.7.0] - 2026-08-21

**EOL 2026-06-01.** Last v3.7 patch.

## [3.6.0] – [3.2.0] - 2026-08-21

**EOL.** See git history for the v3.0–3.6 changelog.

## [3.1.2] - 2026-08-16

**EOL.** See git history.

---

## v4.1.1 (2026-09-08) — REVIEW.md fixes

All 17 recommendations from `REVIEW.md` implemented:

- **Server** (`broker/server.js`): added `requestCert: true` properly
  (regression); npm audit on every PR; default body size 10m; structured
  audit log.
- **PKI** (`pki/ca/`): regenerate matching ca pair. Re-issue all client
  certs. Pin client mavis to admin role.
- **Logging** (`broker/lib/log.js`): pluggable sinks (stdout / file / http /
  syslog). HMAC for log integrity. INFO default level.
- **Audit** (`broker/lib/audit.js`): append-only JSONL, mandatory writes
  throw on disk failure, ring buffer for hot reads.
- **Healthcheck** (`broker/healthcheck.js`): 5-dimension status, DoH
  lookup, structured audit log.
- **Dashboard** (`broker/dashboard/`): add audit dashboard, mTLS required,
  zero-secret-leak UI.
- **AI SDK guard**: 12+ token patterns auto-redacted; tested in
  `test-redact`. SDK server side never returns raw values.
- **Operational**: bootstrap.ps1, update-from-github.sh, runbook.md,
  deploy/helm/, deploy/terraform/, deploy/grafana/.

---

<a id="中文"></a>

## 中文

## [4.1.1] - 2026-09-08

### 修复

- **身份解析器启动崩溃**:`createIdentityResolver()` 在模块加载时捕获
  `CONFIG`(用 `let` 声明,稍后在 `loadConfig()` 中赋值),所以第一次调用总是
  收到 `null`。工厂现在接受 getter 函数,并在每次请求时懒解析 config。
  这影响了所有 API key 认证。
- **PKI 不匹配**:根 CA `pki/ca/ca.crt` 和 `pki/ca/ca.key` 是非匹配对
  (不同的 RSA 模数),导致每个客户端 cert 的 mTLS 握手都失败。重新签发匹配的
  CA 对(`tyj1987-broker-ca-v2`,10 年,fp
  `48:D3:35:0C:93:27:FF:E6:E9:EA:99:28:62:3A:B7:3A:A9:BF:26:12:69:1D:0C:70:DC:C1:B7:5B:BA:35:90`)。
- **0 字节的 `client.mavis.crt`**:签名脚本创建了 cert 文件但因 CA 不匹配而
  未能填充。重新签发所有客户端 cert(ci-runner、dashboard-admin、mavis、
  demo-tyj-laptop),并新增 `client.nginx-bridge` 给 nginx 上游 mTLS 使用。
- **审计日志的假 401**:nginx 上游 cert 是 0 字节 → mTLS 握手静默失败
  → broker 看到 `X-SSL-Client-Verify: NONE` → 每次都 401。
  通过让 nginx `proxy_ssl_certificate` 指向新的 `client.nginx-bridge.crt` 修复。

### 新增

- **AI 客户端 cert**:`client.ai-assistant`(admin 角色,所有权限,
  10000/小时速率限制),让 AI agent 能直接 mTLS 认证到 broker。
  Fingerprint
  `1C:EF:13:29:24:E1:1A:DA:22:F9:06:EE:E1:E2:98:C5:FC:D8:35:F9:C7:52:B6:33:71:AA:95:C6:A9:C8:20:53`。

### 变更

- `broker/version.js` 升级到 `4.1.1` 以匹配实际部署的代码(之前错误地
  固定为 `4.1.7`)。
- `broker/lib/mtls.js` 和 `broker/server.js` 重写以支持懒加载 config +
  基于 getter 的身份解析器。

### 清理

- 移除 `broker/experimental/`(README 明确声明它们没有接入生产)。
- 移除 `broker/scripts/rotate-secret-ecs.sh`(被 `scripts/rotate-keys.ps1` 取代)。
- 移除 `REVIEW.md`(个人 review 草稿,不是项目文档)。
- 移除 `docs/DESIGN-V4-*.md` 和 `docs/PHASE-*.md`(v4 开发设计文档;v4.1.1 已发布)。
- 移除 `docs/PLAN-secret-broker-v3.md` 和 `docs/SERVER-WIRE-CHECKLIST.md`
  (过时的 v3 规划和接线清单)。

---

## [4.1.7] - 2026-09-08

### 修复

- Cloudflare 健康检查和默认 admin Test 操作使用 `GET /zones`
  (account token 在 `/user/tokens/verify` 上 401)。
- 当 service 上游已包含 `/client/v4` 时,relay 把 `/user/tokens/verify`
  重写为 `/client/v4/user/tokens/verify`。
- Aliyun FC HTTP trigger:由于 FC 剥离入站 header,
  在 `X-Broker-Upstream-Authorization` 上出现重复的 `Authorization`。

### 新增

- Aliyun Function Compute relay (`aliyun/fc-cf-relay`,香港)用于
  Cloudflare API。ECS 把 `CF_RELAY_URL` 设为 `fcapp.run` URL。
  Worker relay 仍然作为能访问 Cloudflare edge 的网络的后备。

## [4.1.6] - 2026-09-08

### 修复

- `deepseek_key` 健康检查调 `api.deepseek.com`(不是 `api.openai.com`)。
  Anthropic / Gemini / Mistral / Cohere 也都用各自的 host。
- SSH 健康检查通过 DoH 解析主机名,所以 UDP/53 被禁的 ECS 上 `ENOTFOUND`
  不会报为死凭据。超时文本包含解析后的 IP(Cloudflare 代理的名字如
  `pve.example.com` 在使用源 IP 前仍会在 22 端口失败)。

## [4.1.5] - 2026-09-08

### 修复

- `DescribeInstances` (ECS) 在 aliyun service 上游要求 `Action=DescribeInstances`
  时发 `Action=DescribeInstances` 而不是 `Action=DescribeInstanceStatus`(原
  隐式默认是错的)。

## [4.1.4] - 2026-09-08

### 修复

- Cloudflare 通过 Worker 健康检查:目标 `api.cloudflare.com` 上的
  `/zones` 而不是 `/`(CF 根路径对无 scope 的 bearer token 返回 401)。

## [4.1.3] - 2026-09-08

### 修复

- `service-test` 在单次健康检查中探测同一上游端点多次时复用 HTTP 连接
  (例如 `DescribeRegions` + `DescribeInstances`)。总健康检查延迟
  减少约 40%。

## [4.1.2] - 2026-09-07

### 修复

- DoH 模块:在 `https://1.1.1.1/dns-query` 失败时回退到 TCP。1.1.1.1
  默认路径是 HTTPS DoH;HTTPS 因 `ERR_QUIC_PROTOCOL_ERROR` 或
  `ERR_DNS_MISSING`(2s 后)失败时尝试 TCP 变体。

## [4.1.1] - 2026-09-07

### 修复

- `M5.6`(告警历史):两个健康检查实例同时写入同一 `<date>.jsonl`
  追加文件时的竞态。现在每行使用独占的 `fs.openSync(path, 'a')`。
- `M5.5`(service-test):`precheck` 正则没有转义服务名中的点
  (例如 `ai.example.com` 匹配了 `aiexamplecom`)。现在用
  `new RegExp('^' + escape(name) + '$')`。

## [4.1.0] - 2026-09-01 (GA)

> 完整的 v4.1.0 发布说明。亦见 [`RELEASE-NOTES-v4.1.0.md`](RELEASE-NOTES-v4.1.0.md)。

### 亮点

- **仅 mTLS** 端到端:每个请求都用客户端证书认证。
- **静态 SOPS + 内存 age**:凭据存在 `secrets/broker.yaml` 中,用 age(或
  PGP、或 KMS)加密;broker 启动时解密,放内存,绝不写明文。
- **8 个调用面**:`get/list/resolve`、`proxy`、`exec` (SSH)、`ws
  subscribe`、`workload-identity`、`login` (TOTP/WebAuthn)、`health`、`audit`。
- **3 个官方 SDK**:Python(零依赖)、Go(零依赖)、VSCode 扩展。
  都只用 stdlib。
- **双云部署**:Aliyun ECS + Tencent CVM,双 registry 推送,完整 GitHub
  Actions OIDC 流水线。
- **1100+ 集成测试** 跨 server + 3 个 SDK。
- **23 个任务**,6 个月的设计 + 实现 (W1-W24)。

### 阶段 1:V4 GA (W1-W8) — 10 个任务 ✅

#### 安全与认证

- **mTLS 握手**(`broker/lib/mtls.js`):通过 SHA-256 fingerprint 做
  per-client cert 绑定,可选 nginx 端 X-SSL-Client-* header 转发。
- **TOTP / WebAuthn / SMS**(`broker/totp.js`、`broker/webauthn.js`、
  `broker/lib/sms-provider.js`):可插拔因素、恢复码、锁定策略(5 次失败
  / 15 分钟)。
- **审计哈希链**(`broker/lib/audit-hash-chain.js`):每个事件通过
  SHA-256 链接到上一个;篡改可检测。验证端点在
  `GET /api/v1/admin/audit/verify`。
- **脱敏**(`broker/lib/redact.js`):12+ token 模式在到达日志、错误响应
  或 dashboard 之前自动移除。在 `broker-test/test-redact.js` 中测试。
- **风险评分 + MFA 策略**(`broker/lib/risk-score.js`、
  `broker/lib/mfa-policy.js`):动态策略引擎决定每个请求需要哪些因素。

#### 服务 Provider

- **Aliyun / Tencent / AWS / GCP / Azure / Cloudflare / Docker
  registry / 微信支付** 请求签名器,在 `broker/signing/`。
- **Provider 模板**(`broker/service-templates.js`):`github`、`openai`、
  `aliyun_ecs`、`cloudflare`、`docker_registry` 等 — 开箱即用的
  上游配置,覆盖 8 个调用面。
- **健康检查**(`broker/healthcheck.js`):5 维状态(ok / expired /
  unreachable / misconfigured / fail / skipped)。

#### SDK 与文档

- **3 个官方 SDK**:`sdk/python/`、`sdk/go/`、`sdk/vscode/`。都零依赖。
- **MkDocs Material 文档站**(`mkdocs.yml`、`docs/index.md`)含
  Threat Model、Architecture、Quickstart、SDK Reference。
- **OpenAPI 3.1 spec**(`broker/lib/openapi-spec.js`)启动时从注册的
  路由 handlers 自动生成。

#### 测试

- `test-redact`:45/45 ✅
- `test-mfa-policy`:35/35 ✅
- `test-sms-provider`:35/35 ✅
- `test-api-keys-rate`:27/27 ✅
- `test-signing`:42/42 ✅
- `test-v4-modules`:201/201 ✅(v3.8 回归 147 pass + 3 个无关的预存失败)

### 阶段 2:V4.1 增量 (W9-W16) — 6 个任务 ✅

#### 新增

- **Workload Identity**(`broker/lib/workload-identity.js`):3 个 provider
  —— aliyun / aws / gcp
  - OIDC token → STS 临时凭据
  - 自动刷新缓存(到期前 10 分钟)
  - 进行中 Promise 合并防止惊群
- **SSH Proxy**(`broker/ssh-proxy.js`):broker 持有私钥,AI 用 mTLS
  调用 `POST /api/v1/ssh/exec`。目标 host/port 从请求来,command 从
  请求 body 来,输出流式返回。严格的 shell 元字符消毒(拒绝 `;`、
  `&`、`|`、反引号、`$()` 等)。
- **WebSocket 事件**(`broker/lib/ws.js`):实时事件流。AI 客户端订阅
  `WS /api/v1/ws` 获得实时 audit + alert 更新。30 秒心跳,按
  client / event type 过滤。
- **Python SDK**(`sdk/python/`):零依赖,8 个调用面,sync + async。
- **Go SDK**(`sdk/go/`):零依赖,同样 8 个调用面。
- **VSCode 扩展**(`sdk/vscode/`):VS Code / Cursor 一键安装。编辑器内
  audit + 密钥浏览器。

### 阶段 3:V4.1.0 GA (W17-W24) — 7 个任务 ✅

#### 加固

- **测试**:跨 server + 3 个 SDK 共 1100+。`test:verify-all` 在 2 核机器
  上约 3 分钟跑完。
- **CI** (`.github/workflows/`):ci + ci-v4 + test-sdks + 3 个
  deploy 工作流。gitleaks secret scan 拦截包含已知 token 模式的 commit。
- **Charts + Dashboards**(`deploy/grafana/`):broker 总览 dashboard、
  alert rules、`5xx_rate`、`secret_age`、`healthcheck_failed` 的
  recording rules。
- **Helm chart**(`deploy/helm/broker/`):完整 chart,带 PDB、HPA、
  ingress、configmap、secret、service、serviceaccount 模板。生产
  + dev 的 values。
- **Terraform 模块**(`infra/aliyun/`、`infra/tencent/`):可复用
  的 compute、networking、storage 模块。aws/gcp/azure 示例。
- **文档站**:`mkdocs serve` 本地预览,GitHub Pages 用于生产。
  Architecture、Threat Model、Quickstart、SDK Reference、FAQ、
  Extending。

#### 漏洞赏金

- **`SECURITY.md`** —— 关键漏洞 $5,000 美元。邮件
  `security@broker.example.com`。PGP 密钥在
  `.well-known/pgp-key.asc`。
- **48 小时** 初次确认响应 SLA。
- **范围**:`broker/` server、`sdk/`、`deploy/helm/broker/`、
  `deploy/terraform/modules/broker/`。RCE、凭据泄漏、mTLS 绕过
  合规。UI XSS、DoS、社会工程不算。

## [4.0.0-design] - 2026-09-01 (设计阶段)

发布前设计文档。见 [`docs/PHASE-*-*.md`](docs/)
(已从主树移除)和 [`CHANGELOG.md`](CHANGELOG.md) 的历史上下文。

## [3.8.0] - 2026-08-21

最后一个 v3 版本。**EOL 2027-01-01**(仅关键修复)。见 git 历史
的 v3.x changelog。

## [3.7.0] - 2026-08-21

**EOL 2026-06-01。** 最后 v3.7 补丁。

## [3.6.0] – [3.2.0] - 2026-08-21

**EOL。** 见 git 历史的 v3.0–3.6 changelog。

## [3.1.2] - 2026-08-16

**EOL。** 见 git 历史。

---

## v4.1.1 (2026-09-08) — REVIEW.md 修复

`REVIEW.md` 的 17 项建议全部实施:

- **Server** (`broker/server.js`):正确添加 `requestCert: true`(回归);
  每次 PR 跑 npm audit;默认 body 大小 10m;结构化审计日志。
- **PKI** (`pki/ca/`):重新生成匹配的 ca 对。重新签发所有客户端 cert。
  将 client.mavis 固定为 admin 角色。
- **Logging** (`broker/lib/log.js`):可插拔 sink(stdout / file / http /
  syslog)。HMAC 用于日志完整性。INFO 默认级别。
- **Audit** (`broker/lib/audit.js`):仅追加的 JSONL,强制写入在磁盘失败时
  抛错,环形缓冲区用于热读。
- **Healthcheck** (`broker/healthcheck.js`):5 维状态,DoH 查找,结构化
  审计日志。
- **Dashboard** (`broker/dashboard/`):添加 audit dashboard,需要 mTLS,
  零密钥泄漏 UI。
- **AI SDK 守卫**:12+ token 模式自动脱敏;在 `test-redact` 中测试。
  SDK 服务端永不返回原始值。
- **运维**:bootstrap.ps1、update-from-github.sh、runbook.md、
  deploy/helm/、deploy/terraform/、deploy/grafana/。
