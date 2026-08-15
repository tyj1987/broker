# Secret Broker v3.0 设计文档 / Design Document

> **本版本**: v3.0 全面架构设计 (2026-08-15)
> **状态**: 设计阶段，待评审
> **作者**: Mavis (AI 架构助手) + 脱永军 (项目所有者)
> **取代**: 上一版 v3 计划（仅 Dashboard CRUD，本版覆盖身份/认证/AI接入/凭据自检全栈）
>
> 目标一句话：**把 broker 从"自己用够用"升级到"可被社区审查、可被新手 5 分钟跑起来、可被 AI 友好接入"**。

---

## 目录 / Table of Contents

0. [背景与诉求](#0-背景与诉求--background--requirements)
1. [核心设计原则](#1-核心设计原则--design-principles)
2. [现状盘点](#2-现状盘点--current-state)
3. [v3.0 目标架构](#3-v30-目标架构--target-architecture)
4. [四大改造模块 M1-M4](#4-四大改造模块--four-modules)
   - M1 [自助管理](#m1-自助管理--self-service)
   - M2 [强认证 (2FA)](#m2-强认证--strong-authentication-2fa)
   - M3 [AI 接入三件套](#m3-ai-接入三件套--ai-integration)
   - M4 [凭据自检与告警](#m4-凭据自检与告警--self-checks--alerts)
5. [数据模型变更](#5-数据模型变更--data-model-changes)
6. [API 变更清单](#6-api-变更清单--api-changes)
7. [文件改动清单](#7-文件改动清单--file-changes)
8. [生态适配 (DevOps / AI 开发者 / 个人小团队)](#8-生态适配--ecosystem)
9. [测试策略](#9-测试策略--test-strategy)
10. [迁移路径与回滚](#10-迁移路径与回滚--migration--rollback)
11. [风险与缓解](#11-风险与缓解--risks--mitigations)
12. [工作量估算与里程碑](#12-工作量估算与里程碑--estimate--milestones)
13. [明确不做的事 (Out of Scope)](#13-明确不做的事--out-of-scope)
14. [下一步](#14-下一步--next-steps)

---

## 0. 背景与诉求 / Background & Requirements

### 0.1 项目定位

`secret-broker` 是一个 mTLS 凭据代理 (credential proxy)，核心价值是：

> **让"AI / 脚本 / 任何设备"在"不接触明文"的前提下调用"需要凭据的外部 API"。**

### 0.2 当前痛点 (用户原话汇总)

| # | 痛点 | 用户原话 |
|---|---|---|
| P1 | **登录凭证管理缺失** | "默认登录给的随机值没问题，但登录凭证应该在登录后的后台中提供修改选项" |
| P2 | **无二次验证** | "要短信验证或微软的 Authenticator 这种的强验证" |
| P3 | **开源适配性差** | "开源项目可以提供相应的短信接口即可，谁部署用谁的 API 接口" |
| P4 | **AI 接入不丝滑** | "应该更便捷，比如把给 AI 的自动化调用做成 skills 或插件，甚至是标准化的提示词" |
| P5 | **缺凭据调度策略** | 用户隐含诉求：aliyun_ecs AK 看不到本机 ECS（账户归属错）这类问题应自动告警 |
| P6 | **多场景适配** | "在确保安全的情况下，任何地方均可以登录" |

### 0.3 v3.0 成功标准

| 维度 | 验收 |
|---|---|
| **安全** | 密码登录强制 TOTP；mTLS 证书 365 天自动到期；敏感操作有 audit log |
| **自助** | 每个 client 登录后能改密码 / 启 TOTP / rotate cert / 看自己活动 |
| **AI 友好** | 1) mTLS 长期 cert；2) 短命 API Key；3) MCP Server；4) OpenClaw skill — 四选一即用 |
| **可插拔** | SMS / Email / WebAuthn 都是接口契约，部署者自己接 aliyun/tencent/twilio |
| **可观测** | 凭据自检 / 证书到期 / 凭据-资源不匹配都能在 dashboard 看到 |
| **可审计** | 100% 操作有 audit；admin 可看全局，普通 client 只看自己 |
| **多场景** | 同一份代码可被 DevOps / AI 开发者 / 个人小团队用不同的 install 路径 |

---

## 1. 核心设计原则 / Design Principles

按优先级排序，冲突时**前面的赢**：

| # | 原则 | 说明 |
|---|---|---|
| 1 | **简单 > 强大** | 少一个功能 = 少一个 bug。默认开箱即用，能不加就不加。 |
| 2 | **可推敲 > 漂亮** | 所有功能都要经得起开源社区审查，逻辑必须清晰，UI 可以丑。 |
| 3 | **安全 > 便利** | 明文只在用户输入那一瞬存在浏览器内存；服务端只存 SOPS 密文；audit 100% 覆盖。 |
| 4 | **复用 > 重写** | v2.x 已经设计好 mTLS / SOPS / proxy-resolve / audit / 限流，**只补管理 API，不动核心**。 |
| 5 | **一份代码 > 多套环境** | 所有配置、所有 secrets、所有设备信息都用同一份 SOPS 文件，**不分散在 yaml/env/db 里**。 |
| 6 | **可插拔 > 内置** | 短信 / 邮件 / WebAuthn / 通知都是契约接口，默认实现 + 自定义实现并行。 |
| 7 | **零新依赖优先** | 保持现有 node 内置模块优先；新依赖必须有充分理由（不接受为了少写 100 行代码而引 1MB 依赖）。 |

---

## 2. 现状盘点 / Current State

### 2.1 一手代码量

| 类别 | 文件 | 行数 |
|---|---|---|
| 后端核心 | `broker/server.js` | 2380 |
| 证书签发 | `broker/cert-issuer.js` | 157 |
| 服务模板 | `broker/service-templates.js` | 129 |
| 类型 schema | `broker/type-schemas.js` | 534 |
| Dashboard JS | `dashboard/app.js` + `home.js` + 5 个 admin | 2490 |
| Dashboard HTML/CSS | `dashboard/index.html` + `style.css` | 1059 |
| **一手代码合计** | 10 个 .js + 2 个 .html/.css | **~7700 行** |
| 测试 | 6 套件 | 196/196 PASS |
| 依赖 | `node_modules` | 仅 `yaml` (~5MB) |

### 2.2 已有能力（不重做）

- ✅ Broker 后端：mTLS + 密码双认证、SOPS+age 静态加密、JSON Lines 审计、proxy/resolve 双模式、限流、登录锁
- ✅ ECS 公网入口：`https://broker.52trz.com` → nginx 443 → broker 8443（TLSv1.3），LE 证书自动续期
- ✅ 客户端证书 PKI：`scripts/broker/issue-client-cert.sh`、`revoke-cert.sh`
- ✅ Dashboard 5 个 Tab：动作 / 审计 / 密钥 / 服务 / 客户端
- ✅ 实时 SSE 推送、CSV/JSON 导出、敏感度标记、首页 stat cards
- ✅ 凭据轮换提醒、凭据 CRUD、客户端 CRUD、服务 CRUD
- ✅ 6 套测试稳定 (196/196 × 2 轮 = 392/392)
- ✅ DoH + IP 直连 (ECS outbound UDP/53 阻断解决)
- ✅ IMDS fallback (ECS 快照)
- ✅ ECS 凭证烟雾测试脚本

### 2.3 关键缺失 (v3.0 要补)

- ❌ **客户端自助**：登录后没有"我的资料"页，无法改密码/启 TOTP/rotate cert
- ❌ **2FA 缺失**：密码登录后不需要任何第二因素
- ❌ **短信 / 邮件 / WebAuthn 抽象接口**：完全没有
- ❌ **AI 接入 SDK/Skill/MCP**：只有 mTLS 一种方式，Web 端 AI 工具不友好
- ❌ **API Key**：只有 mTLS cert，OpenClaw Web 端用户每次都要传 cert
- ❌ **凭据-资源不匹配自动告警**：ECS AK 看不到本机 ECS 这种问题靠人肉诊断
- ❌ **Docker Compose / 一键起**：源码运行门槛高，OpenClaw 之外的人 5 分钟跑不起来
- ❌ **多场景文档**：现在的 RUNBOOK 偏向"我自己用"，缺 DevOps / AI 开发者 / 个人小团队 三种使用场景的入门指南

---

## 3. v3.0 目标架构 / Target Architecture

### 3.1 整体架构图

```
                    ┌────────────────────────────────────────┐
                    │   Secret Broker v3.0                    │
                    │                                         │
   AI Agent ─────►  │  ┌──────────────┐  ┌──────────────┐    │
   (Claude/Cline)   │  │  MCP Server  │  │  REST API    │    │
   via stdio/HTTP   │  │  (独立进程)   │  │  mTLS+API    │    │
                    │  └──────┬───────┘  │  Key+TOTP    │    │
   OpenClaw  ─────►  │         │          └──────┬───────┘    │
   (skill)          │         │                 │            │
   Web Dashboard ──►│  ┌──────┴─────────────────┴───────┐    │
   (browser)        │  │       AuthN (认证层)            │    │
                    │  │  ┌──────┬──────┬──────┬──────┐  │    │
                    │  │  │ mTLS │ TOTP │ API  │ Web  │  │    │
                    │  │  │ cert │ 6位  │ Key  │Authn │  │    │
                    │  │  └──────┴──────┴──────┴──────┘  │    │
                    │  │       (可插拔)                   │    │
                    │  └──────────────┬──────────────────┘    │
                    │  ┌──────────────┴──────────────────┐    │
                    │  │       AuthZ (授权层)             │    │
                    │  │  RBAC + 资源级 + 路径级 + scope  │    │
                    │  │  + 限速 per-client/per-secret    │    │
                    │  └──────────────┬──────────────────┘    │
                    │  ┌──────────────┴──────────────────┐    │
                    │  │   Secret Storage (SOPS+age)      │    │
                    │  │   Service Registry + Templates   │    │
                    │  │   Audit + Alert + Health-check   │    │
                    │  └─────────────────────────────────┘    │
                    └────────────────────────────────────────┘
```

### 3.2 关键流程：登录

```
1) Browser → POST /api/v1/login { client_name, password }
              ↓
   Server 验证密码
              ↓
   Server 检查 client.totp_enabled
              ├─ 已启用 TOTP:
              │    → 返 { ok: false, mfa_required: true, mfa_token: "..." }
              │    → Browser 弹 TOTP 输入框
              │    → POST /api/v1/login/mfa { mfa_token, totp_code }
              │    → Server 验 TOTP → 返 session
              └─ 未启用 TOTP:
                   → 返 { ok: true, session: "..." }
                   → Browser 跳转 Dashboard
                   → Dashboard 顶部 banner 提示"请尽快启用 TOTP"
```

### 3.3 关键流程：AI 通过 API Key 调服务

```
1) Admin 在 dashboard 创建 API Key:
   POST /api/v1/api-keys
   { name: "OpenClaw Web", scopes: ["secrets:resolve", "services:proxy"],
     allowed_secrets: ["GITHUB_PAT"], expires_at: "..." }
   ↓
   Server 返 { id, secret: "mb_live_xxxx" }   ← secret 只显示一次

2) AI / OpenClaw 调用:
   POST /api/v1/services/github/proxy
   Authorization: Bearer mb_live_xxxx
   { method: "GET", path: "/user/repos" }
   ↓
   Server 验证 API Key → 查 allowed_secrets → 自动注入 GITHUB_PAT
   ↓
   Server 调真实 GitHub API
   ↓
   AI 收到的是 GitHub 真实响应（不是 ghp_xxx 字符串）

3) audit 记录:
   { ts, cn: "client.mavis", api_key_id: "mb_live_xxxx",
     action: "proxy", service: "github", method: "GET", path: "/user/repos",
     upstream_status: 200, latency_ms: 234 }
```

### 3.4 关键流程：凭据自检

```
每日 04:00 cron 触发 healthcheck.runAll():
  对每个 secret:
    - dry_run = true
    - 调上游 (e.g. GitHub /user, Aliyun DescribeRegions)
    - 检查响应结构
    - 记录 { secret, last_checked, status, error }

  对每个 service 上游域名:
    - TCP connect 上游
    - 记录 { service, last_checked, status, latency_ms }

  对每个 client cert:
    - 检查 expires_at
    - 列出 7/14/30 天内到期的
    - 记录 + SSE 推送告警

  特殊检查 (v3.0 新增):
    - aliyun_ecs service: 调 DescribeInstances 看能否看到任何 ECS
      如果 TotalCount=0: 推 SSE alert "credential_mismatch: aliyun_ecs AK cannot see any ECS"

结果 → 写 audit log + dashboard /alerts/ 页面 + 可选 SSE 推送
```

---

## 4. 四大改造模块 / Four Modules

### M1. 自助管理 / Self-Service

**目标**：每个 client 登录后能管自己，**不再需要 SSH 到 ECS 改 yaml**。

| API | 用途 | 实现复杂度 |
|---|---|---|
| `GET /api/v1/me` | 拿自己的资料（name, role, created_at, last_password_change, TOTP 状态, 关联 API Key 数量） | S |
| `POST /api/v1/me/change-password` | 改自己密码（要旧密码 + 限速 5/h） | S |
| `POST /api/v1/me/rotate-cert` | 重发自己的 client cert（旧 cert 立即失效，签发新 cert + key，一次性返回） | S |
| `GET /api/v1/me/audit` | 只看自己（按 fingerprint 过滤）的 audit log | S |
| `POST /api/v1/me/totp/setup` | 启 TOTP，返回 `otpauth://` URL + 10 个一次性恢复码 | M |
| `POST /api/v1/me/totp/verify` | 首次配 TOTP 时验证正确性（防输错） | S |
| `POST /api/v1/me/totp/disable` | 关 TOTP（要当前 TOTP code 或 1 个恢复码） | S |
| `GET /api/v1/me/api-keys` | 列自己的 API Key | S |
| `POST /api/v1/me/api-keys` | 创建自己的 API Key（需当前 TOTP code） | M |

**Dashboard 新增页面**：
- `dashboard/me.html` - 我的资料：当前 TOTP 状态 / 改密码按钮 / 重发 cert 按钮 / 启 TOTP 流程 / 列出我最近 50 条活动

**新增文件**：
- `dashboard/me.html`, `dashboard/me.js`
- `broker/api-me.js` (路由模块)

**改动文件**：
- `server.js` (新增 ~150 行路由)
- `dashboard/index.html` (新增 "我的资料" 入口)
- `dashboard/app.js` (login 后跳转)
- `dashboard/style.css` (TOTP QR 渲染样式)

---

### M2. 强认证 / Strong Authentication (2FA)

**目标**：密码登录必须配 TOTP，mTLS 可选 TOTP（按 risk score）。

#### M2.1 TOTP 实现

**新增 `broker/totp.js`** (零 npm 依赖，~120 行)：
- RFC 6238 SHA-1
- secret 存 broker.yaml (加密) `totp_secret` (base32 32 字符) + `totp_recovery_codes_hash` (10 个 SHA-256 哈希)
- 验证函数：`verify(totp_secret, code, window=1) → boolean`
- 恢复码：8 字符 字母数字组合，10 个一次性

#### M2.2 登录流程改造

**新增 `broker/auth-flow.js`**：
- 状态机：`PASSWORD_OK → MFA_REQUIRED → MFA_OK → SESSION_OK`
- 临时 mfa_token: 5 分钟有效，单次使用
- 失败计数：5 次/15 分钟触发锁定（已有逻辑复用）

**改动 `server.js` 登录路由**：~80 行新增

#### M2.3 SMS 抽象 (Deploy 自接)

**新增目录 `broker/notifications/sms/`**：
```
broker/notifications/
├── sms/
│   ├── index.js          # 抽象接口 + provider 路由器
│   ├── aliyun.js         # 阿里云短信 (deploy 自己配 AK)
│   ├── tencent.js        # 腾讯云短信
│   ├── twilio.js         # Twilio (国际)
│   ├── http-generic.js   # 通用 HTTP webhook (deploy 自定义)
│   └── console.js        # 开发模式，输出到 stdout
└── email/
    ├── index.js
    ├── smtp.js           # SMTP (自托管/企业邮箱)
    └── sendgrid.js
```

**broker.yaml 新增**：
```yaml
notifications:
  sms:
    provider: console        # 部署者改: aliyun / tencent / twilio / http-generic / console
    access_key: ${env.SMS_AK}
    access_secret: ${env.SMS_SK}
    sign_name: "SecretBroker"
    template_login: "SMS_xxxxxx"
  email:
    provider: smtp
    smtp:
      host: smtp.example.com
      port: 587
      user: ${env.SMTP_USER}
      pass: ${env.SMTP_PASS}
      from: "broker@example.com"
```

**接口契约**：
```js
// broker/notifications/sms/index.js
class SmsProvider {
  async send({ to, template, params, locale }) { /* throws on error */ }
}
```

**部署者实现**：
- 写 `broker/notifications/sms/my-provider.js` 导出 SmsProvider 子类
- 在 `index.js` 的 provider map 加一行
- broker.yaml 改 `provider: my-provider`

#### M2.4 WebAuthn / FIDO2 (v3.0 范围，**v3.1 实现**)

- v3.0 留抽象接口 `broker/authn/webauthn.js` (空实现)
- v3.1 引入 `@simplewebauthn/server` (~50KB) 实现完整 FIDO2

---

### M3. AI 接入三件套 / AI Integration

**目标**：AI 工具 4 种方式都能接入，每种 5 分钟跑通。

#### M3.1 mTLS Client Cert (现有，加强)

**改动**：
- dashboard "我的资料" 加"重发 cert"按钮 (M1 已覆盖)
- `scripts/broker/issue-client-cert.sh` 加 `--rotate --days 90` 选项
- 默认 cert 有效期从 365 → **90 天**（强制 rotation 文化）

#### M3.2 API Key (新)

**新增 `broker/api-keys.js`** (路由 + 存储)：

| API | 用途 | 实现 |
|---|---|---|
| `POST /api/v1/api-keys` | 创建 (admin 或自己) | 需 TOTP |
| `GET /api/v1/api-keys` | 列表 (admin 看全部，自己看自己) | - |
| `GET /api/v1/api-keys/:id` | 详情 | - |
| `DELETE /api/v1/api-keys/:id` | 撤销 | 需 TOTP |
| `GET /api/v1/api-keys/:id/usage` | 最近 100 次使用 | - |

**Broker.yaml 新增**：
```yaml
api_keys: []   # 启动时从 broker.yaml 读
# 运行时新增/删除写到 broker.yaml
```

**API Key 格式**：`mb_<env>_<random>`：
- `mb_live_` 正式环境
- `mb_test_` 测试环境
- 32 字符随机 (base62)
- 显示一次后只存 SHA-256 哈希

**Auth**：`Authorization: Bearer mb_live_xxxx` (HTTPS Basic auth 不需要)

**Scope 系统**：
- `secrets:resolve` - 允许 resolve secrets
- `secrets:list` - 允许 list secrets (只看名字，不看值)
- `services:proxy` - 允许代发 API 请求
- `services:read` - 允许调只读 service actions

**约束**：
- `allowed_secrets`: 限定可 resolve 的 secret 名字（白名单）
- `allowed_services`: 限定可 proxy 的 service
- `expires_at`: 强制过期时间（默认 24h）
- `rate_limit`: 默认 100/h
- `ip_whitelist`: 可选 IP 白名单

#### M3.3 MCP Server (新)

**新增 `broker/mcp-server.js`** (独立进程, stdio 或 HTTP)：

启动方式：
```bash
# stdio (Claude Desktop, Cline)
npx @secret-broker/mcp-server --broker https://broker.52trz.com \
    --cert client.mavis.crt --key client.mavis.key --ca ca.crt

# HTTP 模式
node broker/mcp-server.js --broker https://broker.52trz.com \
    --cert ... --key ... --ca ... --port 3001
```

**MCP Tools**:
```typescript
{
  "list_secrets": {
    "description": "列出当前 client 可访问的 secrets (不显示值)",
    "inputSchema": { "type": "object", "properties": {} }
  },
  "describe_secret": {
    "description": "查看某个 secret 的元信息 (name/type/description/last_used)",
    "inputSchema": {
      "type": "object",
      "properties": { "name": { "type": "string" } },
      "required": ["name"]
    }
  },
  "call_service": {
    "description": "调外部服务 (e.g. GitHub API)。AI 拿到的是服务响应，不是密钥。",
    "inputSchema": {
      "type": "object",
      "properties": {
        "service": { "type": "string" },
        "method": { "type": "string" },
        "path": { "type": "string" },
        "query": { "type": "object" },
        "body": { "type": "object" }
      },
      "required": ["service", "method", "path"]
    }
  }
}
```

**安全**：
- AI 通过 MCP 调用，**不返回密钥明文**
- `call_service` 内部走 broker proxy
- AI 看到的是 GitHub API 响应（JSON），不是 `ghp_xxx`
- 所有调用 100% 进 audit

**协议版本**: MCP spec ≥ 2025-06-18

#### M3.4 OpenClaw Skill (新，独立仓库)

**仓库**: `secret-broker-openclaw-skill/` (独立发布)

**结构**:
```
secret-broker-openclaw-skill/
├── SKILL.md                  # 自然语言映射
├── openclaw.yaml             # OpenClaw skill 注册
├── prompts/
│   ├── github-automation.md
│   ├── aliyun-automation.md
│   └── general.md
├── examples/
│   ├── call-github-api.sh
│   ├── list-broker-secrets.sh
│   └── ai-agent-integration.md
└── README.md
```

**SKILL.md 示例**:
```markdown
# Secret Broker Skill

你是 AI 助手。当你需要调外部 API（GitHub、阿里云、OpenAI、任意 HTTP）时，
**不要让用户告诉你密钥**。而是：

1. 用 mTLS client cert 通过 broker
2. 或用 API Key 通过 broker

## 标准调用模式

GitHub:
```bash
curl --cert client.mavis.crt --key client.mavis.key --cacert ca.crt \
  https://broker.52trz.com/api/v1/services/github/proxy \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/user/repos"}'
```

API Key 模式（推荐用于 Web 端）:
```bash
curl -H "Authorization: Bearer mb_live_xxxx" \
  https://broker.52trz.com/api/v1/secrets/resolve \
  -H "Content-Type: application/json" \
  -d '{"name":"GITHUB_PAT"}'
```

## 什么时候用哪个

| 场景 | 用什么 |
|---|---|
| 长期 CI 跑批 | mTLS cert (90 天有效) |
| Web 端单次调用 | API Key (24h 有效) |
| IDE 插件 / Claude Desktop | MCP Server |
| OpenClaw 对话 | mTLS 或 API Key |
```

---

### M4. 凭据自检与告警 / Self-Checks & Alerts

**目标**：broker 能自己照看自己，不靠人盯。

#### M4.1 凭据烟雾测试 (Cron)

**新增 `broker/healthcheck.js`**:

```js
// 每个 secret 的健康检查
async function checkSecret(secret) {
  // 根据 secret.type 调对应上游的 "no-side-effect" API
  switch (secret.type) {
    case 'github_pat':  return githubPing(secret);
    case 'aliyun_ak':   return aliyunPing(secret);
    case 'openai_key':  return openaiPing(secret);
    case 'ssh_connection': return sshConnectivityCheck(secret);
    // ...
  }
}
```

**新增 `broker/cron-tasks.js`** (broker 内置 cron, 不用 systemd):

```js
// broker 启动时注册
registerCron('04:00', 'daily', healthcheck.runAll);
registerCron('00:30', 'daily', secrets.cleanupExpired);
registerCron('monday 09:00', 'weekly', reports.weekly);
```

#### M4.2 凭据-资源不匹配检测

**在 `healthcheck.js` 中新增**:
```js
// aliyun_ecs 特殊: AK 是否能看到 ECS
async function checkAliyunEcsAccountMatch(svc) {
  const r = await proxy(svc, 'GET', '/?Action=DescribeInstances&RegionId=cn-beijing');
  if (r.TotalCount === 0 && !r.RequestId?.startsWith('00')) {
    return { status: 'mismatch', detail: 'AK cannot see any ECS in 8 regions' };
  }
  return { status: 'ok' };
}
```

**告警通道**:
- 写 audit log: `action: 'credential_mismatch'`
- SSE 推到 admin dashboard
- 主页 stat card 显示红色
- **不在 v3.0 范围**: 邮件 / 短信告警 (留 v3.1)

#### M4.3 证书到期告警

```js
// 每日 04:00
const expiring = [];
for (const [name, c] of Object.entries(CONFIG.clients)) {
  if (c.cert_expires_at) {
    const days = (new Date(c.cert_expires_at) - Date.now()) / 86400000;
    if (days < 30) expiring.push({ name, days });
  }
}
if (expiring.length) SSE.broadcast('alert', { type: 'cert_expiring', clients: expiring });
```

#### M4.4 Dashboard 告警页面

**新增 `dashboard/alerts.html` + `dashboard/alerts.js`**:
- 实时 SSE 接收
- 分类显示：凭据 / 证书 / 资源匹配 / 上游连通
- 可确认/忽略
- 历史记录（最近 30 天）

---

## 5. 数据模型变更 / Data Model Changes

### 5.1 broker.yaml 加密部分新增字段

```yaml
clients:
  client.<NAME>:
    # 已有字段保持
    role: developer
    allowed_resolve: [".*"]
    allowed_proxy: ["*"]
    cert_fingerprint_sha256: "AA:BB:..."
    
    # v3.0 新增
    password_hash: "sha256$salt$..."     # password 字段升级为 hash
    password_set_at: "2026-08-15T..."
    password_expires_at: null              # 可选: 90 天强制改
    totp_secret: "BASE32..."              # 启 TOTP 才有
    totp_enabled_at: "2026-08-15T..."
    totp_recovery_codes_hash: [...]       # 10 个 SHA-256 哈希
    cert_expires_at: "2027-05-15T..."     # 自动计算
    last_password_change: "..."
    last_totp_use: "..."
    last_cert_rotation: "..."
    preferred_2fa: "totp"                 # totp | sms | webauthn | none
    phone_hash: "..."                     # SMS 找回 (hash 后存)
    failed_login_count: 0
    locked_until: null
    metadata:
      created_by: "system"                # 初始 / 邀请 / admin
      last_seen: "2026-08-15T..."
      total_audits: 0

notifications:
  sms: { provider: aliyun, access_key: ..., access_secret: ..., sign_name: ..., template_login: ... }
  email: { provider: smtp, smtp: { ... } }

api_keys: []  # 动态列表

healthcheck:
  enabled: true
  schedule: "04:00"                       # 每日触发时间
  alert_channels: ["sse"]                 # v3.0 仅 SSE, 留 email/sms/webhook 占位
```

### 5.2 SOPS 加密文件变化 (向上兼容)

- ✅ 所有新字段都是 optional，老 client 不会有
- ✅ 迁移脚本：`broker/scripts/migrate-v2-to-v3.js` 自动给老 client 加默认值
- ✅ `password` 字段自动 hash 化（启动时检测明文 password 就 hash 一次）

---

## 6. API 变更清单 / API Changes

### 6.1 新增 API (v3.0)

| Method | Path | 用途 | 认证 |
|---|---|---|---|
| GET | `/api/v1/me` | 我的资料 | session/mTLS/API Key |
| POST | `/api/v1/me/change-password` | 改密码 | session + 旧密码 |
| POST | `/api/v1/me/rotate-cert` | 重发 cert | session + TOTP |
| GET | `/api/v1/me/audit` | 我的活动 | session/mTLS/API Key |
| POST | `/api/v1/me/totp/setup` | 启 TOTP | session + 密码 |
| POST | `/api/v1/me/totp/verify` | 验证 TOTP | session |
| POST | `/api/v1/me/totp/disable` | 关 TOTP | session + TOTP/recovery |
| GET | `/api/v1/me/api-keys` | 我的 API Key | session |
| POST | `/api/v1/me/api-keys` | 创建 API Key | session + TOTP |
| DELETE | `/api/v1/me/api-keys/:id` | 撤销 API Key | session + TOTP |
| POST | `/api/v1/login/mfa` | TOTP 第二步 | mfa_token |
| POST | `/api/v1/api-keys` | 创建 API Key (admin) | session admin + TOTP |
| GET | `/api/v1/api-keys` | 列所有 API Key (admin) | session admin |
| DELETE | `/api/v1/api-keys/:id` | 撤销 API Key (admin) | session admin + TOTP |
| GET | `/api/v1/alerts` | 当前活跃告警 | session |
| POST | `/api/v1/alerts/:id/ack` | 确认告警 | session |
| POST | `/api/v1/healthcheck/run` | 手动触发健康检查 | session admin |
| GET | `/api/v1/healthcheck/status` | 凭据健康状态 | session |
| GET | `/api/v1/alerts/stream` | SSE 告警推送 | session |

### 6.2 修改 API (v3.0)

| API | 变化 |
|---|---|
| `POST /api/v1/login` | 已启用 TOTP 的 client 必须二次走 `/login/mfa`，不直接返 session |
| `POST /api/v1/login (mTLS)` | mTLS 登录可选 TOTP，risk score 决定 |
| 所有 admin API | 加 TOTP 二次验证（高危操作） |

### 6.3 不变 API (v2.0 兼容)

- 所有 `/api/v1/secrets*` `/api/v1/services*` `/api/v1/clients*` `/api/v1/audit*` 路由保持不变
- mTLS 客户端 cert 仍可直接用（无需改）
- 现有 6 套测试 196/196 仍然 PASS

---

## 7. 文件改动清单 / File Changes

### 7.1 新增文件 (v3.0)

| 文件 | 行数预估 | 用途 |
|---|---|---|
| `broker/totp.js` | 120 | RFC 6238 TOTP 实现 |
| `broker/auth-flow.js` | 200 | 登录状态机 (密码 → MFA → session) |
| `broker/api-me.js` | 200 | 我的资料 API 路由 |
| `broker/api-keys.js` | 300 | API Key CRUD + 认证 |
| `broker/api-alerts.js` | 150 | 告警 API |
| `broker/healthcheck.js` | 250 | 凭据自检引擎 |
| `broker/cron-tasks.js` | 100 | broker 内置 cron |
| `broker/notifications/sms/index.js` | 80 | 短信抽象接口 |
| `broker/notifications/sms/aliyun.js` | 150 | 阿里云短信 |
| `broker/notifications/sms/tencent.js` | 150 | 腾讯云短信 |
| `broker/notifications/sms/twilio.js` | 100 | Twilio |
| `broker/notifications/sms/http-generic.js` | 80 | 自定义 HTTP |
| `broker/notifications/sms/console.js` | 30 | 开发模式 |
| `broker/notifications/email/index.js` | 50 | 邮件抽象 |
| `broker/notifications/email/smtp.js` | 120 | SMTP |
| `broker/mcp-server.js` | 400 | MCP Server 独立进程 |
| `dashboard/me.html` | 250 | 我的资料页 |
| `dashboard/me.js` | 400 | 我的资料页逻辑 |
| `dashboard/api-keys.html` | 200 | API Key 管理 |
| `dashboard/api-keys.js` | 300 | API Key 管理逻辑 |
| `dashboard/alerts.html` | 200 | 告警中心 |
| `dashboard/alerts.js` | 350 | 告警实时推送 + 历史 |
| `docker-compose.yml` | 80 | 一键起 |
| `Dockerfile` | 40 | 镜像构建 |
| `.env.example` | 30 | 环境变量示例 |
| `docs/AUTH.md` | 中英 200 行 | 2FA / 凭据 / 登录 |
| `docs/AI-INTEGRATION.md` | 中英 250 行 | AI 接入指南 |
| `docs/OPENAPI.yaml` | 400 行 OpenAPI 3.1 | API 规范 |
| `docs/DEPLOY.md` | 中英 300 行 | 多场景部署 |
| **小计** | **~4980 行新增** | |

### 7.2 改动文件 (v3.0)

| 文件 | 改动 | 行数变化 |
|---|---|---|
| `broker/server.js` | 登录流程改造、新增 30+ 路由 | +500 |
| `broker/cert-issuer.js` | 加 cert_expires_at 字段 | +30 |
| `broker/dashboard/index.html` | 新增 4 个 tab 入口 | +80 |
| `broker/dashboard/app.js` | session 检查 + TOTP UI 流程 | +200 |
| `broker/dashboard/style.css` | TOTP QR + alerts 样式 | +200 |
| `broker/dashboard/admin/audit.js` | 关联 client 维度过滤 | +50 |
| `scripts/broker/issue-client-cert.sh` | 加 `--days 90` 默认 | +20 |
| `docs/PLAN-secret-broker-v3.md` | 本文档持续更新 | - |
| `docs/04-secret-broker.md` | 引用新文档 | +20 |
| `README.md` | 双语重写，多场景 install | +300 |
| `RUNBOOK.md` | 加 v3.0 章节 | +200 |
| **小计** | **~1600 行新增** | |

### 7.3 独立仓库 (后续)

- `secret-broker-openclaw-skill/` (OpenClaw skill)
- `secret-broker-python-sdk/` (Python SDK)
- `secret-broker-node-sdk/` (Node SDK)
- `secret-broker-terraform/` (Terraform module)

---

## 8. 生态适配 / Ecosystem

### 8.1 三种用户画像

| 用户 | 安装方式 | 关键文件 |
|---|---|---|
| **DevOps / SRE** | Docker Compose + 反向代理 | `docker-compose.yml`, `docs/DEPLOY-devops.md` |
| **AI 开发者** | npm + OpenClaw skill / MCP | `@secret-broker/openclaw-skill`, `docs/AI-INTEGRATION.md` |
| **个人 / 小团队** | 1 行 curl | `curl -sSL install.52trz.com \| bash` |

### 8.2 DevOps 适配

**`docker-compose.yml`** (v3.0 新增):
```yaml
version: '3.8'
services:
  broker:
    build: .
    restart: unless-stopped
    ports:
      - "8443:8443"   # mTLS
      - "8080:8080"   # dashboard (behind nginx)
    volumes:
      - ./secrets:/app/secrets:ro      # SOPS 加密文件
      - ./pki:/app/pki:ro              # 证书
      - ./audit:/app/audit             # audit log
    environment:
      - SOPS_AGE_KEY_FILE=/run/secrets/age/key
      - BROKER_PORT=8443
    secrets:
      - age_key

secrets:
  age_key:
    file: ./age.key
```

**Ansible role** (后续): `ansible-galaxy install secret-broker.broker`

### 8.3 AI 开发者适配

**OpenClaw Skill 安装**:
```bash
openclaw skill add secret-broker
# 自动：
# 1. 拉 secret-broker-openclaw-skill
# 2. 提示用户填 broker URL
# 3. 引导生成 client cert 或 API Key
# 5 分钟跑通
```

**MCP Server 配置** (Claude Desktop `claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "secret-broker": {
      "command": "npx",
      "args": ["@secret-broker/mcp-server", "--broker", "https://broker.52trz.com", "--cert", "/path/to/client.mavis.crt", "--key", "/path/to/client.mavis.key", "--ca", "/path/to/ca.crt"]
    }
  }
}
```

**Python SDK**:
```python
from secret_broker import Broker
sb = Broker(url="...", cert=("client.crt", "client.key"), ca="ca.crt")
gh_repos = sb.call("github", method="GET", path="/user/repos")
# gh_repos 是 list of dict, 不是 token 字符串
```

### 8.4 个人/小团队适配

**一行安装**:
```bash
curl -sSL https://get.secret-broker.io | bash
# 1. 装 sops + age
# 2. 初始化 PKI
# 3. 随机生成 dashboard admin 密码
# 4. systemd 启动
# 5. 打印 dashboard URL + 临时密码
# 用户改密码 + 启 TOTP 完事
```

---

## 9. 测试策略 / Test Strategy

### 9.1 测试套件扩展 (6 → 12)

| # | 套件 | 覆盖 | 目标 |
|---|---|---|---|
| 1-6 | (现有) thorough/services/clients/audit/home/shortcuts | v2.0 全功能 | 196/196 PASS (回归) |
| 7 | `test-totp.js` | RFC 6238 合规、setup/verify/disable、恢复码 | 30+ cases |
| 8 | `test-api-keys.js` | CRUD、scope、TTL、auth、撤销 | 40+ cases |
| 9 | `test-me.js` | 改密码、rotate cert、me/audit | 30+ cases |
| 10 | `test-mcp-server.js` | list_secrets/describe_secret/call_service | 30+ cases |
| 11 | `test-healthcheck.js` | 凭据自检、证书到期、alerts | 30+ cases |
| 12 | `test-notifications.js` | SMS/Email 各 provider mock | 30+ cases |

**目标**: 12 套件 386/386 PASS (x 2 轮 = 772/772)

### 9.2 端到端测试 (E2E)

**新增 `tests/e2e/`**:
- `e2e-login-totp.spec.js` - 完整登录 → 启 TOTP → 重登 → 二次验证
- `e2e-ai-integration.spec.js` - 模拟 AI 调 broker → 拿到 GitHub 真实响应
- `e2e-credential-mismatch.spec.js` - 模拟 AK 看不到 ECS → 触发 alert

### 9.3 性能基准

- mTLS 握手 < 100ms
- TOTP 验证 < 10ms
- API Key 认证 < 5ms
- 单 secret 烟雾测试 < 5s (含 4 个上游)

---

## 10. 迁移路径与回滚 / Migration & Rollback

### 10.1 迁移策略 (零停机)

```
Day 0:  v2.0 在生产跑，所有数据兼容
Day 1:  scp v3.0 binary + scripts，**不重启 broker**
        broker in-process 检测到 broker.yaml 新字段，做 in-place upgrade
        （新字段 optional，老 client 自动用 default）
Day 2:  admin 在 dashboard 启用 TOTP（自己先试）
Day 3:  其他 client 收到邮件/通知，30 天内启 TOTP
Day 30: 强制 2FA（未启 TOTP 的 client 密码登录被拒，只能 mTLS）
Day 60: v2.0 测试全部跑通 v3.0 broker
```

### 10.2 迁移脚本

**`scripts/broker/migrate-v2-to-v3.js`** (新增):
- 启动时自动跑一次
- 检测老 client：自动加 `password_hash`、`password_set_at`
- 检测明文 `password` 字段：自动 hash 化
- 检测 cert 无 `cert_expires_at`：从 cert PEM 解析 + 写入
- 写 audit log: `action: 'migration', version: 'v2-to-v3'`

### 10.3 回滚

- v3.0 broker 检测 broker.yaml schema version = 3
- 回滚 v2.0：scp v2.0 binary，systemd restart
- v2.0 读 schema version 3 broker.yaml 会忽略新字段（已设计为 backward compatible）
- 数据零丢失

---

## 11. 风险与缓解 / Risks & Mitigations

| 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|
| **TOTP bug 锁住所有 client** | 中 | 高 | 1) 恢复码 10 个；2) admin 紧急解锁脚本；3) 部署者保留 SSH 入口 |
| **MCP spec 变化** | 中 | 中 | 锁定 spec version 2025-06-18；不激进追新 |
| **API Key 设计成低安全入口** | 中 | 中 | 默认不开；scope 强制；TTL 强制；rate limit；可 IP 白名单 |
| **大改破坏 v2.0 测试** | 中 | 中 | 旧测试 100% 保留；v3.0 加 6 套件；CI 强制 386/386 |
| **SMS provider 接入复杂** | 低 | 低 | v3.0 留 stub；console provider 作 default |
| **Docker Compose 镜像被黑** | 低 | 高 | 用 official node 22-slim 基础镜像；多阶段构建；不引第三方包；签 image |
| **OpenClaw skill 维护负担** | 中 | 低 | 独立仓库；社区可贡献；v3.0 核心是 MCP + mTLS，skill 是 nice-to-have |
| **凭据-资源检测误报** | 中 | 中 | 标记 status: `mismatch_suspect`，需要 admin 手动 ack 才会触发重试 |

---

## 12. 工作量估算与里程碑 / Estimate & Milestones

### 12.1 工作量

| 角色 | 工期 |
|---|---|
| 1 人全职 | 2-3 周 |
| 1 人兼职 | 4-5 周 |
| 2 人协作 | 1-1.5 周 |

### 12.2 里程碑

| 里程碑 | 内容 | 验收 | 工时 |
|---|---|---|---|
| **M0** (Week 0) | 设计评审 + 决策敲定 | 本文档评审通过 | 0.5d |
| **M1** (Week 1) | M1 自助管理 + M2 TOTP (无 SMS) | dashboard "我的资料" + 启 TOTP + 登录改流程；测试 7-9 套件 PASS | 3-4d |
| **M2** (Week 1.5) | M3 API Key | API Key CRUD + Bearer auth + 集成 dashboard；测试 7-10 套件 PASS | 2-3d |
| **M3** (Week 2) | M2 SMS 抽象 + M4 凭据自检 | SMS provider 4 选 1 接入 + cron 任务 + alerts 页；测试 7-12 套件 PASS | 3-4d |
| **M4** (Week 2.5) | M3 MCP Server + Docker | MCP 独立进程 + docker-compose + .env.example；测试 7-12 套件 PASS | 2-3d |
| **M5** (Week 3) | OpenClaw skill + 文档 | 独立仓库 + SKILL.md + 3 个使用场景指南 | 1-2d |
| **M6** (Week 3) | 公网部署 + 验收 | 浏览器走通所有 4 种登录方式 + 4 种 AI 接入方式 | 1d |

**总计**: 约 3 周（1 人）

### 12.3 关键依赖

- 阿里云短信 / 腾讯云短信：deploy 提供 AK + 模板 ID (可选)
- 域名 + LE 证书：deploy 提供 (通常已有)
- SMTP 服务器：deploy 自配 (可选)

---

## 13. 明确不做的事 / Out of Scope

为避免 scope creep，以下明确**不在 v3.0**：

- ❌ **WebAuthn / FIDO2** → v3.1 (v3.0 留接口)
- ❌ **SAML / OIDC 联邦登录** → v4.0
- ❌ **HA 多实例 / etcd 同步** → v4.0
- ❌ **HSM / KMS 集成** → v4.0
- ❌ **Webhook 通知 (Slack/飞书/钉钉)** → v3.1 (v3.0 留接口)
- ❌ **多租户** → v4.0
- ❌ **审计日志外部化 (SIEM)** → v3.1
- ❌ **证书自动 ACME (Let's Encrypt)** → 已支持，deploy 自己配
- ❌ **GUI 安装向导** → v3.1 (v3.0 提供 curl 一行安装)

---

## 14. 下一步 / Next Steps

### 14.1 立刻要做 (本周)

1. ✅ **用户评审本文档** — 重点关注 12.2 里程碑切分是否合理
2. ⏳ **M1 + M2 TOTP 启动** — 我开始写 `broker/totp.js` + `broker/api-me.js`
3. ⏳ **每日 17:00 同步进度** — 跑测试 + commit

### 14.2 我的工作方式

- 每个 phase 跑通 12 套件测试后再 commit
- 自然 commit message (不写 `feat:` 前缀)
- Author: 脱永军 <tyj1987@users.noreply.github.com>
- 公网部署由你 SSH 上去操作（不接触凭据）
- 凭据零接触 (你只在 ECS 终端上输入新值)
- 中英双语文档

### 14.3 决策待你拍板 (本评审前)

| 决策点 | 我的推荐 | 备选 |
|---|---|---|
| 2FA 强制级别 | 密码登录 + 强制 TOTP，mTLS 登录可选 TOTP | 全部可选 |
| TOTP 恢复码 | 10 个一次性 | 5 个 / 20 个 |
| API Key 默认 TTL | 24h | 1h / 7d / 不限 |
| 凭据自检频率 | 每日 04:00 | 每小时 / 每周 |
| MCP Server 协议版本 | 2025-06-18 stable | latest |
| OpenClaw skill 独立仓库 | 是 | 放主仓 |
| Docker 镜像 base | `node:22-slim` | `alpine` (有 musl 兼容问题) |
| 旧 client 强制 2FA 截止 | v3.0 发布 30 天后 | 立即 / 90 天 |

---

## 附录 A: 关键流程图 / Key Flow Diagrams

### A.1 完整登录流程 (密码 + TOTP)

```
┌─────────┐
│ Browser │
└────┬────┘
     │
     │ 1. POST /api/v1/login
     │    { client: "tyj", password: "..." }
     ▼
┌──────────────────────┐
│ Server               │
│  - 查 client         │
│  - 验 password hash   │
│  - 失败计数++        │
│  - 锁?               │
└────┬─────────────────┘
     │ ok
     ▼
┌──────────────────────┐
│ client.totp_enabled? │
└────┬────────┬────────┘
  No │        │ Yes
     │        │
     ▼        ▼
┌──────┐  ┌────────────────────┐
│ Session│  │ mfa_token (5min)  │
│ 返 ok │  │ { mfa_required:T  │
└──────┘  │   mfa_token:"..." }│
           └────┬───────────────┘
                │
                │ 2. POST /api/v1/login/mfa
                │    { mfa_token, totp_code: "123456" }
                ▼
           ┌──────────────────┐
           │ Server           │
           │  - 验 TOTP       │
           │  - 或验恢复码    │
           │  - 失败计数++    │
           └────┬─────────────┘
                │ ok
                ▼
           ┌────────┐
           │Session │
           │ 返 ok  │
           └────────┘
```

### A.2 AI 接入全图

```
┌──────────────┐
│ AI Agent     │
│ (Claude/Cline│
│  /Cursor/    │
│  OpenClaw)   │
└──────┬───────┘
       │ 接入方式
       ├─────────────┬──────────────┬─────────────┐
       │             │              │             │
       ▼             ▼              ▼             ▼
   ┌────────┐   ┌──────────┐   ┌──────────┐  ┌────────┐
   │ mTLS   │   │ API Key  │   │ MCP      │  │ 任何   │
   │ Cert   │   │ Bearer   │   │ Server   │  │ HTTP   │
   │ (90d)  │   │ (24h)    │   │ (stdio/  │  │ client │
   │        │   │          │   │  HTTP)   │  │ (SDK)  │
   └───┬────┘   └────┬─────┘   └────┬─────┘  └───┬────┘
       │             │              │             │
       └─────────────┴──────────────┴─────────────┘
                            │
                            ▼
                  ┌──────────────────────┐
                  │ Broker REST API      │
                  │  (mTLS always-on     │
                  │   内部 → 8000/8443)  │
                  └──────┬───────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
   ┌─────────┐    ┌──────────┐    ┌──────────┐
   │ resolve │    │ proxy    │    │ list     │
   │ secret  │    │ service  │    │ secrets  │
   └────┬────┘    └────┬─────┘    └────┬─────┘
        │              │               │
        ▼              ▼               ▼
   ┌─────────┐    ┌──────────┐    ┌──────────┐
   │ 密钥明文│    │ 上游 API │    │ 名字+type│
   │ (只返给 │    │ (代发)   │    │ (元信息) │
   │  调方)  │    │          │    │          │
   └─────────┘    └──────────┘    └──────────┘
        │              │               │
        └──────────────┴───────────────┘
                       │
                       ▼
              ┌──────────────┐
              │ audit log    │
              │ 100% 覆盖    │
              └──────────────┘
```

### A.3 凭据自检流程

```
04:00 cron
     │
     ▼
┌────────────────────────┐
│ healthcheck.runAll()   │
└────┬───────────────────┘
     │
     ├─→ 对每个 secret:
     │      type=github_pat → 调 GET /user
     │      type=aliyun_ak  → 调 DescribeRegions
     │      type=openai_key → 调 GET /v1/models
     │      type=ssh        → TCP connect host:port
     │      ...
     │
     ├─→ 对每个 service 上游域名:
     │      TCP connect
     │      (DNS 解析 + TLS 握手)
     │
     ├─→ 对每个 client cert:
     │      查 expires_at
     │      7/14/30 天内 → 加入告警列表
     │
     └─→ 特殊检测 (v3.0 新增):
            aliyun_ecs: 调 DescribeInstances
            TotalCount=0 + RequestId 正常 → 凭据-资源不匹配
            写 alert
                 │
                 ▼
         ┌───────────────────┐
         │ 告警分发           │
         │  - audit log      │
         │  - SSE 推到 admin │
         │  - (v3.1) email   │
         │  - (v3.1) sms     │
         │  - (v3.1) webhook │
         └───────────────────┘
```

---

## 附录 B: 已有 v3 计划文档的差异说明

之前 `docs/PLAN-secret-broker-v3.md` (20653 字节) 关注的是 **Dashboard CRUD**（让用户能在 Web 端增删改查 secrets/services/clients）。**本版 v3.0 文档** 范围扩大：

| 模块 | 旧 v3 | 新 v3.0 |
|---|---|---|
| Dashboard CRUD | ✅ | ✅ (沿用) |
| 2FA / TOTP | ❌ | ✅ (新增) |
| 自助管理 (改密码/启 TOTP) | ❌ | ✅ (新增) |
| API Key | ❌ | ✅ (新增) |
| MCP Server | ❌ | ✅ (新增) |
| OpenClaw skill | ❌ | ✅ (新增, 独立仓库) |
| 凭据自检 / 告警 | ❌ | ✅ (新增) |
| Docker Compose | 部分 | ✅ (完整) |
| 多场景文档 | ❌ | ✅ (DevOps/AI/小团队) |
| 测试 12 套件 | 6 套件 | ✅ (6+6=12) |
| WebAuthn | ❌ | 留 v3.1 |
| SMS 抽象 | ❌ | ✅ (新增) |
| Webhook 通知 | ❌ | 留 v3.1 |

**结论**: 本文档是 v3.0 全面架构设计，**取代**之前只关注 Dashboard 的旧 v3 计划。

---

## 附录 C: 文件结构总览 (v3.0)

```
secret-broker/
├── broker/
│   ├── server.js                       [改 +500 行]
│   ├── cert-issuer.js                  [改 +30 行]
│   ├── service-templates.js
│   ├── type-schemas.js
│   ├── totp.js                         [新增 120 行]
│   ├── auth-flow.js                    [新增 200 行]
│   ├── api-me.js                       [新增 200 行]
│   ├── api-keys.js                     [新增 300 行]
│   ├── api-alerts.js                   [新增 150 行]
│   ├── healthcheck.js                  [新增 250 行]
│   ├── cron-tasks.js                   [新增 100 行]
│   ├── mcp-server.js                   [新增 400 行]
│   ├── notifications/
│   │   ├── sms/
│   │   │   ├── index.js                [新增 80]
│   │   │   ├── aliyun.js               [新增 150]
│   │   │   ├── tencent.js              [新增 150]
│   │   │   ├── twilio.js               [新增 100]
│   │   │   ├── http-generic.js         [新增 80]
│   │   │   └── console.js              [新增 30]
│   │   └── email/
│   │       ├── index.js                [新增 50]
│   │       └── smtp.js                 [新增 120]
│   ├── dashboard/
│   │   ├── index.html                  [改 +80]
│   │   ├── app.js                      [改 +200]
│   │   ├── home.js
│   │   ├── style.css                   [改 +200]
│   │   ├── me.html                     [新增 250]
│   │   ├── me.js                       [新增 400]
│   │   ├── api-keys.html               [新增 200]
│   │   ├── api-keys.js                 [新增 300]
│   │   ├── alerts.html                 [新增 200]
│   │   ├── alerts.js                   [新增 350]
│   │   └── admin/
│   │       ├── audit.js                [改 +50]
│   │       ├── clients.js
│   │       ├── secrets.js
│   │       └── services.js
├── scripts/
│   └── broker/
│       ├── issue-client-cert.sh        [改 +20, --days 90]
│       ├── migrate-v2-to-v3.js         [新增 200]
│       └── ...
├── secrets/
│   ├── broker.yaml                     [schema 升级 + 新字段]
│   └── common.env
├── tests/                              [扩展 6 → 12 套件]
│   ├── test-thorough.js                (现有 196/196 PASS)
│   ├── test-services-crud.js
│   ├── test-clients-crud.js
│   ├── test-audit.js
│   ├── test-home.js
│   ├── test-shortcuts.js
│   ├── test-totp.js                    [新增]
│   ├── test-api-keys.js                [新增]
│   ├── test-me.js                      [新增]
│   ├── test-mcp-server.js              [新增]
│   ├── test-healthcheck.js             [新增]
│   └── test-notifications.js           [新增]
├── docs/
│   ├── AUTH.md                         [新增 中英 200]
│   ├── AI-INTEGRATION.md               [新增 中英 250]
│   ├── OPENAPI.yaml                    [新增 400]
│   ├── DEPLOY.md                       [新增 中英 300]
│   ├── PLAN-secret-broker-v3.md        [本文档]
│   └── 04-secret-broker.md             [改 +20]
├── docker-compose.yml                  [新增 80]
├── Dockerfile                          [新增 40]
├── .env.example                        [新增 30]
├── README.md                           [重写 +300]
└── RUNBOOK.md                          [改 +200]
```

**总计**:
- 新增文件: ~30 个, ~4980 行
- 改动文件: ~10 个, ~1600 行
- 测试套件: 6 → 12, 196 → 386+ cases
- 文档: 4 个新, 4 个改, 全部中英双语

---

**文档结束 / End of Document**

### 14.3 决策记录 (2026-08-16 评审后锁定)

> 用户授权「按我的理解选最优方案执行」。以下决定作为 v3.0 实现基线，
> 后续如有变更需走 v3.0.1 修订。

| 决策点 | 锁定值 | 备注 |
|---|---|---|
| 2FA 强制级别 | 密码登录 + 强制 TOTP；mTLS 登录可选 TOTP（risk score 决定） | 安全底线 |
| TOTP 恢复码 | 10 个一次性（8 字符字母数字） | 业界标准 |
| API Key 默认 TTL | 24h（创建时可调 1h / 24h / 7d / 永久） | 短而够用 |
| 凭据自检频率 | 每日 04:00（broker 内置 cron） | 避开业务高峰 |
| MCP Server 协议版本 | 2025-06-18 stable | 锁 spec，不追新 |
| OpenClaw skill 仓库 | 独立 `secret-broker-openclaw-skill` | 维护边界清晰 |
| Docker 镜像 base | `node:22-slim` | 官方维护，体积小 |
| 旧 client 强制 2FA 截止 | v3.0 公网发布后 30 天 | 留过渡期 |
| 仪表盘登录流程 | 密码 → 启 TOTP（强制） → session | 一次性跳转 |
| TOTP secret 存储 | broker.yaml 加密字段 `totp_secret`（base32 32 字符） | 与现有 secret 体系一致 |
| 恢复码存储 | broker.yaml 加密字段 `totp_recovery_codes_hash`（10 个 SHA-256 哈希） | 防明文泄露 |
| mTLS + TOTP 关系 | mTLS 已足够强，TOTP 可选；用户可主动配 | 灵活 |
| cert 默认有效期 | 90 天（从 365 天降下来，强制 rotation） | 安全基线 |
| 凭据自检告警通道 v3.0 | 仅 SSE（dashboard 实时） | email/sms/webhook 留 v3.1 |

---

> 下一步: 立即进入 M1 实现 (TOTP + 自助管理)。
> 完成标准: 12 套件 386/386 × 2 轮 = 772/772 全 PASS, 公网部署, browser 走通 4 种登录方式。
