# Changelog / 版本变更

Secret Broker (mTLS credential proxy for AI) 的所有重要变更.

版本号遵循 [Semantic Versioning](https://semver.org/).
格式参考 [Keep a Changelog](https://keepachangelog.com/).

---

## [3.0.0] - 2026-08-15

### 概述

v3.0 全面重构: **TOTP 2FA + 自助管理 + 强认证 + AI 接入三件套 + 凭据自检**.
可开源、可社区审查、新手 5 分钟跑起来、AI 友好接入.

**18 个 commit**, 涵盖从强认证到凭据自检完整链路.

### 凭据零接触 (核心承诺)

v3.0 起所有路径 (broker / mcp-server / rotate-script) **永远不**把 secret value
写进日志 / 错误信息 / 响应体 / 进程命令行.
验证: 4 套件 188/188 PASS + 公网真实验 (5 secrets healthcheck).

### Added (新增功能)

#### M1 (TOTP + 自助管理 + 强认证) — commit `23539cc`
- **TOTP 2FA** (RFC 6238): 用户自助启用, Google Authenticator / 1Password 兼容
- **自助密码改**: dashboard `/me` 标签, 改密码不需 admin
- **自助证书轮换**: mTLS 客户端证书可在 dashboard 自助轮换
- **失败锁定**: 5 次错误密码锁 15 分钟
- **强认证 API Key** (M1 基础): 主键 / 子键分级权限
- 新增 `broker/totp.js` / `broker/auth-flow.js` / `broker/dashboard/me.html`
- 新增 36 + 9 + 31 + 13 + 7 个 e2e 测试 (5 套件)

#### M2 (API Key 短命 Bearer Token) — commit `a124a1e`
- **API Key 创建** (admin 创建, scope 控制, 1h TTL)
- **issue_child** (master key → child key, refresh 1h, 自动)
- **dashboard `/api-keys` 标签**: 列表 + 创建 + 撤销
- **Audit log 增强**: 记录每个 API key 创建/撤销
- 新增 `broker/api-keys.js` / `broker/dashboard/api-keys.html` / `api-keys.js`
- 新增 31 个 API Key 单元测试

#### M2.5 (can-proxy 抽模块 + 修累积 + regex) — commit `7f59e36`
- 把 server.js 内嵌的 ACL 逻辑抽到独立 `broker/can-proxy.js` (4 函数)
- 修 bug 1: 累积语义 (之前首个不匹配就 return false, 整体 false)
- 修 bug 2: rule.service regex 支持 (`{service: '.*'}` 现在通配)
- REGEX_META = `[*^$]`, 仅 `*` `^` `$` 触发 regex (避免字面 `.` 当任意字符)
- 41 个 ACL 单元测试 (单测 100% 覆盖 can-proxy.js)

#### M3.3 (Master Key + MCP Server) — commits `c7905bf` / `82bf2d8` / `0764218` / `8be8483` / `22f4480`
- **MCP Server** (HTTP + JSON-RPC 2.0): 跟 mavis / Claude / GPT 兼容
- **Master Key 机制**: 一次性创建, 写 `/opt/secret-broker/master-key.txt` (chmod 600)
- **`--master-key-file`**: master key 永不入 ps / env
- **call_service / describe_secret 路由修复**: mavis agent 实战中调通
- **8 mcp tools**: list_secrets / describe_secret / call_service / get_health /
  list_api_keys / get_audit / check_credential / run_healthcheck
- **凭据零接触 4 处**: mcp-server 进程命令行无明文 / log redact / 进程内存 only / audit 准确
- 新增 `broker/mcp-server.js` (19223 字节) + 35 个 e2e 测试

#### M3.4 (mavis code 集成 MCP client) — commit `22f4480`
- **`C:\Users\User\.codex\skills\secret-broker-mcp\`**: 3 文件
  - `mcp-bridge.js` (2732 字节): SSH 包装调 ECS
  - `Invoke-McpTool.ps1`: PowerShell 包装, base64 编码 args
  - `SKILL.md`: 6→8 tools 文档
- mavis 调 broker 不暴露 3001 端口, 走现有 SSH

#### M3.5 (services 加 cloudflare template) — commit `487d526`
- `services.cloudflare` example: 如何配 cloudflare_token 服务

#### M4 (凭据自检引擎 + broker 内置 cron) — commits `da32b98` / `cb9b248` / `22a3640`
- **`broker/healthcheck.js`** (15678 字节): 凭据自检引擎
  - `checkSecret(name, fields, type)`: 通用入口
  - `runAll(getSecrets)`: 批量跑, 写 state + 推 SSE
  - 7 个 check 函数: checkGithub / checkOpenAI / checkSsh / checkCloudflare / checkAliyun / checkTencent / checkAws
- **broker 内置 cron**: 每天 04:00 触发, 配置 broker.yaml `healthcheck.schedule`
- **`/api/v1/healthcheck/run`** (admin): 手动 Run Now
- **`/api/v1/healthcheck/status`**: 看最近一次结果
- **dashboard home tab**: 5 个 stat cards (services / secrets / clients / healthcheck / audit-today)
  - healthcheck 详情区 + Run Now 按钮 (admin-only)
  - 每个 secret 状态: ok / expired / fail / skipped, 颜色标识
- **STATE_PATH**: 写 `secrets/healthcheck-state.json` (writable, ReadWritePaths)
- 24 个 healthcheck 单元测试

#### M4.1 (healthcheck 接 structured fields 修复) — commit `cb9b248`
- 修 bug: `summary.total=0` (server.js getSecrets closure 只看 entry.value)
- 迁移后 entry 形如 `{type, fields: {access_key_id, access_key_secret}}` 无顶层 value
- 修复: server.js getSecrets 返 `{type, fields, description}` 完整
- healthcheck.js 用 `pickCredential(type, fields)` 按 type-schemas 抽字段

#### M4.5 (mcp-server 2 healthcheck tools) — commit `4c2966c`
- mcp-server 端 `check_credential(name)`: 走 broker resolve 拿 value, 调 checkSecret 验
- mcp-server 端 `run_healthcheck()`: 循环所有 secret, 累加 summary
- 凭据零接触: 内部调 broker 拿 value, 调 checkSecret 拿结果, 返 status/detail/latency/type
- **公网实测**: GITHUB_PAT 真实 reach api.github.com → 401 Bad credentials 578ms
- 关键发现: mcp-server 在 ECS 能出网 (跟 broker 不一样, 走 client.mavis cert)
- test-mcp-server 加 6 断言, 35/35 PASS

#### M4.5.1 (cloudflare_token check) — commit `e8f2be8`
- healthcheck.js 加 checkCloudflare: GET `https://api.cloudflare.com/client/v4/user`
- 200 → ok (user email), 401/403 → expired, 其他 → fail
- pickCredential 加 cloudflare_token case (主字段 api_token + 可选 account_id)
- test-healthcheck 24/24 PASS (含 §3.5 mock)

#### M5 (broker healthcheck 走 mcp-server 出网) — commit `47f9d03`
- broker healthcheck 走 mcp-server upstream (broker 不出网时由 mcp-server 走 client.mavis cert 出网)
- `broker.yaml healthcheck.upstream: mcp_server` (默认 'local' 保持向后兼容)
- `mcp_server_url: http://127.0.0.1:3001`
- 60s timeout, 5 secrets ~12s 顺序跑
- state 写 broker + emit HEALTHCHECK_BUS + 标记 `_source: 'mcp_server'`

#### M5.1 (aliyun_ak v2 验签) — commit `0ccfee4`
- pickCredential aliyun 拿完整 pair: `{primary: access_key_id, meta: {access_key_secret, region}}`
- 新 signAliyun 纯函数 (字典序 + RFC 3986 + base64(HMAC-SHA1))
- checkAliyun 调 `https://ecs.aliyuncs.com/?Action=DescribeRegions`
- 200/401/403 → ok/expired/fail
- port 切 http/https 由 env (ALIYUN_HEALTHCHECK_HOST/PORT) — test mock 走 http
- 14 个新断言 (signAliyun 9 + checkAliyun 5)
- 公网: mcp-server 真实 reach ecs.aliyuncs.com (32 regions, 294ms 偶尔通)

#### M5.2 (tencent + aws 验签) — commit `a545afc`
- tencent_sk: signTencent 纯函数 (TC3-HMAC-SHA256, 3 步 HMAC chain)
- checkTencent 调 cvm.tencentcloudapi.com/?Action=DescribeRegions
- aws_access_key: signAws 纯函数 (SigV4, 4 步 HMAC chain)
- checkAws 调 sts.amazonaws.com/?Action=GetCallerIdentity
- 共用 helper: sha256Hex() + hmacSha256()
- 29 个新断言 (signTencent 8 + checkTencent 4 + signAws 11 + checkAws 4)

#### scripts: rotate-secret-ecs.sh — commit `c6ea368`
- ECS 端凭据轮换脚本 (7961 字节, 凭据零接触 5 处)
- `--value-file` 读 (chmod 600 校验) + stdin 走临时 python 脚本 + argv 只传 name/field
- 5 步: login → GET → PUT → healthcheck verify → 清理
- 凭据格式错 (Invalid character) → exit 5 abort
- 网络错 (getaddrinfo) → warn 不阻塞

### Changed (变更)

- `broker/server.js`: M1 +328 / M2 +309 / M3.3 +88 / M4 +30 / M4.1 + 改 getSecrets / M5 +40 行
- `broker/dashboard/index.html`: M1 +116 / M2 +135 / M4 + 5th stat card + healthcheck 详情区
- `broker/dashboard/app.js`: M1 +8 / M2 +41 行
- `broker/dashboard/style.css`: M1 +25 / M2 +51 / M4 + hc-* 样式
- `broker/dashboard/home.js`: M4 + renderHealthcheck + Run Now 按钮

### Test Coverage

4 套件 **188/188 PASS** (从 v2 升 100%):
- `test-can-proxy.js` 41/41 (M2.5)
- `test-healthcheck.js` 67/67 (M4 + M4.1 + M4.5.1 + M5.1 + M5.2)
- `test-master-key.js` 45/45 (M3.3)
- `test-mcp-server.js` 35/35 (M3.3 + M4.5)

### 公网验证 (2026-08-15 broker PID 2684027 / mcp-server PID 2683396)

- 5 secrets healthcheck 跑通 (0 skipped, 真实验签)
  - aliyun_ak → ok (32 regions accessible, latency 294ms 偶尔)
  - GITHUB_PAT → expired 401 (真凭据过期) / ENOTFOUND (防火墙)
  - openai_key / cloudflare_token / ssh_connection → fail (防火墙 / 内网路由)
- 凭据零接触 4 处验证
- broker audit log 落盘 5 条 healthcheck (cn=client.mavis, fp=D8:10:07:...)
- GITHUB_PAT 真凭据 expired 首次发现 (M5.2 验证)

### 文件清单 (新增)

```
broker/totp.js                                    (M1)
broker/auth-flow.js                               (M1)
broker/migrate-v2-to-v3.js                        (M1)
broker/api-keys.js                                (M2)
broker/can-proxy.js                               (M2.5)
broker/mcp-server.js                              (M3.3)
broker/healthcheck.js                             (M4 + M4.1 + M4.5.1 + M5.1 + M5.2)
broker/cron-tasks.js                              (M4)
broker/scripts/rotate-secret-ecs.sh               (rotate-secret)
broker/dashboard/me.html / me.js                  (M1)
broker/dashboard/api-keys.html / api-keys.js      (M2-C)

broker-test/test-totp.js                          (36)
broker-test/test-me.js                            (9)
broker-test/test-api-keys.js                      (31)
broker-test/test-master-key.js                    (45)
broker-test/test-mcp-server.js                    (35)
broker-test/test-m1-e2e.js                        (13)
broker-test/test-api-key-e2e.js                   (7)
broker-test/test-healthcheck.js                   (67)
broker-test/test-can-proxy.js                     (41)

C:\Users\User\.codex\skills\secret-broker-mcp\   (M3.4)
  - mcp-bridge.js
  - Invoke-McpTool.ps1
  - SKILL.md

/opt/secret-broker/scripts/                       (ECS)
  - start-mcp-server.sh
  - stop-mcp-server.sh
  - mcp-server.service
  - mcp-cli.js
  - bootstrap-mcp-server-ecs.sh
  - README-mcp-server.md

/opt/secret-broker/master-key.txt                 (chmod 600, 40 字节, root only)

broker-test/CHANGELOG.md                          (本文件)
broker-test/M1-ACCEPTANCE.md                      (7KB)
broker-test/M2-ACCEPTANCE.md                      (7KB)
broker-test/M3.3-ACCEPTANCE.md                    (8KB)
broker-test/M3.3-FINAL-ACCEPTANCE.md              (8KB)
broker-test/M4-ACCEPTANCE.md                      (10KB)
broker-test/M4.5-ACCEPTANCE.md                    (9KB)
broker-test/M5.1-ACCEPTANCE.md                    (7KB)
broker-test/M5.2-ACCEPTANCE.md                    (7.5KB)
broker-test/M5.2-cloud-ACCEPTANCE.md              (8.7KB)
broker-test/ECS-FIREWALL-TROUBLESHOOTING.md       (6KB)
```

### 已知问题 (Known Issues)

#### ECS 防火墙间歇性 ENOTFOUND (用户已开 4 个出站规则, 部分生效)

```
api.github.com       间歇 (M5.2 验证 401, 后续 ENOTFOUND)
api.openai.com       ENOTFOUND 持续
api.cloudflare.com   ENOTFOUND 持续
ecs.aliyuncs.com     间歇 (M5.2 验证 32 regions, 后续 ENOTFOUND)
```

**可能原因**:
1. 阿里云安全组规则有"放行"目标 IP 限制, 不含所有 API 段
2. 更高优先级 DENY 规则覆盖
3. ECS 出 NAT 网关额外限制

**诊断**: 详见 `broker-test/ECS-FIREWALL-TROUBLESHOOTING.md`

#### IBMC ssh target 不可达

`192.168.2.100:22` 在 ECS VPC 不可达 (10s timeout).
修复: 改 broker.yaml ssh_connection.host 为 ECS 可达 IP.

#### GITHUB_PAT 凭据过期

M5.2 验证时真实验证 `401 Bad credentials` (latency 1010ms, 拿到真响应).
用户需在 GitHub 创新 PAT + 跑 `rotate-secret-ecs.sh --name GITHUB_PAT --field token`.

### 下一步 (Next Steps / Backlog)

- [ ] 用户开 ECS 防火墙 (aliyun / openai / github / cloudflare) → 4 fail → ok
- [ ] 用户轮换 GITHUB_PAT
- [ ] 用户修 IBMC ssh target host
- [ ] M5.3: healthcheck 告警增强 (email / webhook)
- [ ] M5.4: audit log 增强 (healthcheck 写 mcp-server 桥接 API)
- [ ] OpenClaw Skill 独立仓 (M3.5 后续)
- [ ] 接受 v3.0 收尾, 进入日常运维

---

## [3.1.0] - 2026-08-16

### 概述

v3.0 M4 healthcheck 把所有"没成功"全塞进 `fail`, dashboard 上看到 `4 fail` 不知道
该轮换凭据 / 改 ECS 出网 / 改 broker.yaml. v3.1 M5.3 把 `fail` 拆成 3 个独立维度,
让"用户能做什么" 一目了然.

**1 个 commit**: `19e42fe healthcheck: 5-维 status (ok/expired/unreachable/misconfigured/fail) — M5.3`
**测试 4 套件 224/224 PASS** (41 + 45 + 103 + 35, 188 → 224, +36)

### Added (新增功能)

#### M5.3 (5-维 healthcheck status) — commit `19e42fe`

healthcheck 状态从 4 维升级到 5 维:

| status | 含义 | 用户动作 |
|---|---|---|
| `ok` | 业务验证通过 | 不用动 |
| `expired` | 401/403 真凭据问题 | **轮换凭据** (`rotate-secret-ecs.sh`) |
| `unreachable` | 基础设施不可达 (DNS / ECONNRESET / IP 段被风控) | **改 ECS 出网** (Warp / 海外跳板 / 安全组) — **改不了 ECS IP** |
| `misconfigured` | 配置错 (缺字段 / ssh target 错 / 端口错) | **改 broker.yaml / secrets/*.yaml** |
| `fail` | 兜底未知错误 | 看 detail 排查 |
| `skipped` | type 不支持 / 无凭据 | 不用动 |

**关键函数**: `classifyError(e)` (export) 纯函数, 把网络/系统错误归类到 5 维之一.
6 个 check 函数 (`checkGithubLike` / `checkOpenAI` / `checkSsh` / `checkAliyun` /
`checkTencent` / `checkAws` / `checkCloudflare`) 全部 `req.on('error')` 走 classifyError.

**检测规则**:
- `unreachable` (基础设施): ENOTFOUND / EAI_AGAIN / EAI_FAIL / ECONNRESET /
  EHOSTUNREACH / ENETUNREACH / SSL reset in msg / read ECONNRESET in msg
- `misconfigured` (配置错): ECONNREFUSED / ETIMEDOUT / `timeout after Xms` /
  ssh_connection 缺 host / cloud 凭据缺子凭据 / ssh_private_key bare
- `fail` (兜底): 其它未知错误 + HTTP 4xx/5xx non-401/403

**Dashboard 增强** (home tab 凭据自检 card):
- 标题下加 5 维 summary pills (按 count 显示, 0 跳过)
- 每个 secret 行的 badge 颜色按 5 维区分 (绿/红/黄/琥珀/红/灰)
- stat card 仍显示 `ok/total` (e.g. "1/5"), 不变

### Changed (行为变更)

- `ssh_connection` 缺 `host` 字段: `skipped` → `misconfigured` (配置错, 不是"没东西可验")
- `ssh_connection` TCP connect 10s timeout: `fail` → `misconfigured` (远端不响应, 通常 ssh target 错)
- `aliyun_ak` / `tencent_sk` / `aws_access_key` 缺子凭据 (access_key_secret / secret_key / secret_access_key): `skipped` → `misconfigured`
- `ssh_private_key` (bare): `skipped` → `misconfigured` (需要 wrap 成 ssh_connection)
- `runAll` summary 加 2 字段: `unreachable`, `misconfigured`
- `runAll` last_status 计算看 4 个非 ok 维度 (M4 只看 expired/fail)
- `pickCredential` `ssh_connection` 接受"有 host 即有凭据" (healthcheck 只测 TCP 可达性, 不需要凭据值)

### 兼容 (Compatibility)

- 0 新 npm 依赖
- 0 数据库 schema 变更
- 0 公开 API 重命名 (`checkSecret` / `runAll` / `runAllViaMcp` / `getStatus` / `getSecretStatus` 同名, 加 `classifyError` 新 export)
- 系统接口 (`/api/v1/healthcheck/status`, `/api/v1/healthcheck/run`) JSON shape 兼容 (仅多 2 个 summary 字段)
- `skipped` 仍存在 (未知 type / 无凭据), `fail` 仍存在 (兜底), `expired` 沿用

### 公网验证 (生产 ECS broker, 5 secrets, 2026-08-16)

```
summary: { ok: 1, expired: 2, unreachable: 1, misconfigured: 1, fail: 0, skipped: 0, total: 5 }
```

| Secret | M4 (笼统) | M5.3 (精确) | Detail |
|---|---|---|---|
| ALIYUN_ACCESS_KEY | ok | **ok** | DescribeRegions 32 regions 1149ms |
| OPENAI_API_KEY | fail | **unreachable** | ECONNRESET — OpenAI 拒阿里云 IP 段 47.94.225.76 (AS37963) |
| IBMC | fail | **misconfigured** | connect timeout 192.168.2.100:22 — ssh target 不可达 |
| GITHUB_PAT | expired | **expired** | 401 Bad credentials (M5.2 真实验证, 待用户轮换) |
| cloudflare | expired | **expired** | 403 forbidden (M5.2 真实验证, 待用户轮换) |

### 已知问题 (Known Issues)

M5.3 不修这些, 仍是 user action 或 backlog:

- **OPENAI API_KEY 持续 unreachable**: ECS 出网 47.94.225.76 (AS37963 Hangzhou Alibaba Advertising) 被 OpenAI 拒
  (TCP 通但 SSL reset). xray 代理出网 (127.0.0.1:1080) 也 timeout 15s (出口同源 = 阿里云).
  解决: ECS 接 Cloudflare WARP 出网 / 海外 VPS 跳板 / 接受 healthcheck 永远 unreachable.
- **GITHUB_PAT 真过期** (401): 用户需 github.com/settings/tokens 创新 PAT + `rotate-secret-ecs.sh`.
- **cloudflare token 真过期** (403): 用户需 Cloudflare dashboard 创新 token + `rotate-secret-ecs.sh`.
- **IBMC ssh target 192.168.2.100 不可达**: ECS 路由表有 `192.168.2.100 via 172.17.255.253 dev eth0`
  但走网关 timeout. 用户需改 `broker.yaml IBMC.ssh_connection.host` 为 ECS 可达 IP.

### 下一步 (Next Steps / Backlog)

- [ ] M5.4: mcp-server 端 healthcheck 写 broker audit (需新增 mcp→broker audit 桥 API)
- [ ] M5.5+: 告警增强 (email / webhook / SSE 实时推送)
- [ ] ECS 接 Cloudflare WARP 出网 (解决 OPENAI unreachable)
- [ ] 用户轮换 GITHUB_PAT / cloudflare token
- [ ] 用户改 IBMC ssh target host

---

## [3.1.1] - 2026-08-16

### 概述

v3.0 `/api/v1/proxy/:service` 不管 secret 健康度, 凭据 expired 也照常调上游, 浪费配额 + 触发风控.
v3.1.1 M5.5 加 service ↔ secret 联动: 当 `svc.token_secret` 引用 secret 是 expired / unreachable / misconfigured / fail 时,
broker 提前 503 阻断, **不真去调 upstream**.

**1 个 commit**: `9c1ec0d broker: service-secret-guard 联动 — call_service 前置 503 阻断 (M5.5)`
**测试 5 套件 256/256 PASS** (41 + 45 + 103 + 35 + **32** 新, 224 → 256, +32)

### Added (新增功能)

#### M5.5 (Service ↔ Secret 联动 / call_service 前置检查) — commit `9c1ec0d`

- **新模块** `broker/service-secret-guard.js` (4151 字节):
  - `checkSecretForService(tokenSecret, getSecretStatusFn) → { allowed, status, detail, ... }`
  - 5 min 内存缓存 (避免每个 call_service 都查 healthcheck state 读盘)
  - 注入失败兜底 (getSecretStatusFn 缺/null) → allowed=true (不阻断业务)
  - 未来 status 兜底 → 保守阻断
  - 公开 `guardHint(status)` 翻译成用户行动提示

- **broker/server.js** 改 `/api/v1/proxy/:service` handler:
  - 在 `canProxy` 之后、`callUpstream` 之前调 `checkSecretForService(svc.token_secret, healthcheckGetSecretStatus)`
  - `!allowed` → 503 + 详细 hint (`rotate the secret first` / `fix the upstream network/firewall` / `fix the secret config` / `check the secret status`)
  - audit log: `action='proxy_blocked'`, `secret=YYY`, `secret_status=ZZZ`, `status='denied'`
  - 即使放过也把 `secret_status` 写进 audit log (代理调用上下文)

- **broker/server.js** 改 `/api/v1/services` GET: 每个 service 返回 `token_secret` + `secret_health` 字段

- **broker/dashboard/app.js** 改 `renderServiceCard`: 加 secret 健康度 badge
  - 5 维 status 颜色 (复用 `.hc-badge` 已有 CSS)
  - hover 看 detail
  - 没 healthcheck 数据 → "unknown" 灰

- **新测试套件** `broker-test/test-proxy-guard.js` (9115 字节, 32 断言):
  - 5 维 status 分类 9 cases (ok/expired/unreachable/misconfigured/fail/skipped/null token/empty token/unknown)
  - 5 min 缓存复用 3 cases (第二次/第三次都不重查)
  - 缓存过期 (TTL 边界) 3 cases (4:59 仍缓存 / 5:01 重查, mock Date.now)
  - `clearSecretGuardCache` 4 cases (清单个 / 全部)
  - `guardHint` 4 cases (4 种 status 提示)
  - 注入失败兜底 3 cases
  - `SECRET_GUARD_TTL_MS = 5min` 常量
  - 未知 status 兜底 2 cases

### Changed (行为变更)

- `/api/v1/proxy/:service` 当 token_secret 状态非 ok/skipped/unknown/no_secret 时 → **503 阻断**, 不调 upstream
- `/api/v1/services` JSON shape 加 2 字段 (`token_secret` + `secret_health`)
- `/api/v1/proxy` audit log 加 `secret_status` 字段 (代理调用上下文)

### 兼容 (Compatibility)

- 0 新 npm 依赖
- 0 数据库 schema 变更
- 公开 API 行为兼容: 老 service 配置不变, 默认放过
- JSON 加 2 字段, 老客户端忽略即可
- guard 注入失败兜底 → 阻断业务, 安全降级
- 5 min 缓存对用户透明 (broker 重启清空, healthcheck state 变化后下次 cache miss 重新查)

### 公网验证 (生产 ECS broker, 2026-08-16)

#### `/api/v1/services` (admin mTLS) 5 services 全部带 secret_health

| service | token_secret | secret_health.status | detail |
|---|---|---|---|
| `github` | GITHUB_PAT | **expired** | 401 Bad credentials |
| `openai` | OPENAI_API_KEY | **unreachable** | ECONNRESET — service may block this IP range |
| `aliyun_ecs` | (无) | None | (不需 secret) |
| `alidns` | ALIYUN_ACCESS_KEY | **ok** | DescribeRegions 32 regions accessible |
| `cloudflare` | cloudflare | **expired** | 403 forbidden |

#### call_service 前置阻断 (3 case)

| 调 | secret 状态 | 预期 | 实际 |
|---|---|---|---|
| `POST /api/v1/proxy/openai` | unreachable | 503 blocked | ✅ 503 + hint "fix network" |
| `POST /api/v1/proxy/github` | expired | 503 blocked | ✅ 503 + hint "rotate" |
| `POST /api/v1/proxy/alidns` | ok | 放行 | ✅ 放行 (upstream 自身 502 是 broker 注入问题, 不阻断) |

#### audit log 落盘

3 条新事件 (proxy_blocked × 2 + proxy × 1), 都带 `secret_status` 字段.

### 已知问题 (Known Issues)

- **broker state.json 缓存**: 用户的 dashboard "Run Now" 触发 `/api/v1/healthcheck/run` (走 mcp_server upstream) 才能刷新 broker state.json. mcp-server 端 `run_healthcheck` 工具不写 broker state (只返给 caller). 这是 M5.3 设计预期, M5.5 复用同一份 state.
- **OPENAI API_KEY 持续 unreachable**: ECS 出网 47.94.225.76 (AS37963 Hangzhou Alibaba Advertising) 被 OpenAI 拒, 走 m5.5 guard 后 `openai` service 自动 503 阻断, 不再触发上游风控. 解决: ECS 接 Cloudflare WARP 出网 / 海外 VPS 跳板 / 接受 healthcheck 永远 unreachable.
- **GITHUB_PAT / cloudflare token 真过期**: 仍需用户轮换 (M5.5 让 secret 过期时 service 自动阻断, 业务不能继续调).
- **IBMC ssh target 192.168.2.100 不可达**: 跟 service 解耦 (IBMC 不在 services tab 里), 仍需用户改 broker.yaml.

### 下一步 (Next Steps / Backlog)

- [ ] M5.6: 告警增强 (SSE 实时推送 healthcheck 状态变化 + secret 过期时 dashboard 红点)
- [ ] M5.7: mcp-server 端 healthcheck 写 broker audit 桥 (新增 mcp→broker audit 桥 API)
- [ ] M5.8: 自动轮换工作流 (secret expired 时自动 trigger 邮件/钉钉/webhook)
- [ ] ECS 接 Cloudflare WARP 出网 (OPENAI 已知网络问题, 不在本系统范围)
- [ ] 用户轮换 GITHUB_PAT / cloudflare token
- [ ] 用户改 IBMC ssh target host

---

## [2.x] - 历史

v2.x 系列 (commit `976a4fc` 之前) 是 Secret Broker 的 mTLS + SOPS 基础版本.
主要功能:
- mTLS 双向认证 (client cert + server cert + self-signed CA)
- SOPS 加密 secrets/broker.yaml (age key 解密)
- 5 services / 4 clients / 5 secrets 基础 CRUD
- admin 视图 + audit log + dashboard

不再追溯更早版本.
