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

## [2.x] - 历史

v2.x 系列 (commit `976a4fc` 之前) 是 Secret Broker 的 mTLS + SOPS 基础版本.
主要功能:
- mTLS 双向认证 (client cert + server cert + self-signed CA)
- SOPS 加密 secrets/broker.yaml (age key 解密)
- 5 services / 4 clients / 5 secrets 基础 CRUD
- admin 视图 + audit log + dashboard

不再追溯更早版本.
