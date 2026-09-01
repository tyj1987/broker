# Secret Broker V4 — AI-First Secret Management Platform

> **设计目标**:把"AI / 脚本 / 任何设备在开发过程中使用密钥"做到**绝对安全 + 绝对便捷**。
> **当前版本**:V4 设计阶段(在 v3.8.0 基础上扩展)
> **状态**:Master Plan,待评审
> **作者**:Mavis (AI 架构助手) + 脱永军 (项目所有者)
> **生效日期**:2026-09-01

---

## 目录 / Table of Contents

0. [为什么需要 V4](#0-为什么需要-v4--why-v4)
1. [设计哲学](#1-设计哲学--design-philosophy)
2. [核心目标](#2-核心目标--core-goals)
3. [目标用户与场景](#3-目标用户与场景--users--scenarios)
4. [四大支柱](#4-四大支柱--four-pillars)
5. [整体架构](#5-整体架构--architecture)
6. [V4 增量改造模块](#6-v4-增量改造模块--increments)
7. [标准化的密钥调用范式](#7-标准化的密钥调用范式--calling-paradigm)
8. [身份验证纵深防御](#8-身份验证纵深防御--identity-defense)
9. [服务商模板库设计](#9-服务商模板库设计--provider-templates)
10. [安全模型与零信任原则](#10-安全模型与零信任原则--zero-trust)
11. [数据流与生命周期](#11-数据流与生命周期--data-flow)
12. [开发体验(DevEx)设计](#12-开发体验devex设计)
13. [可观测性 / 告警 / 应急](#13-可观测性--告警--应急)
14. [实施路线图](#14-实施路线图--roadmap)
15. [风险与不做的事](#15-风险与不做的事--risks--out-of-scope)
16. [附录:术语表](#16-附录术语表--glossary)

---

## 0. 为什么需要 V4 / Why V4

### 0.1 项目位置(Secret Broker 现状)

`secret-broker` 自 v2.0 引入以来,经历了 v3.0 (M1-M4 强认证/AI接入/自检)、
v3.1 (M5 健康检查)、v3.2 (90天证书/IP白名单)、v3.3-3.8 (模块化/可观测/备份探针)
的迭代。截至 v3.8.0,系统已经具备:

- ✅ mTLS 双向认证 (客户端证书绑定设备)
- ✅ TOTP 二次验证 (RFC 6238) + 10 个一次性恢复码
- ✅ 密码登录 + 登录锁定(5 次失败锁 15 分钟)
- ✅ API Key 体系(master/child 关系、scope 限定、IP 白名单、TTL)
- ✅ MCP Server (AI 友好接入)
- ✅ 30+ secret type schemas (github_pat、openai_key、aliyun_ak...)
- ✅ 6 个内置 service templates (github/openai/aliyun_ecs/aliyun_ram/cloudflare/generic_https)
- ✅ 凭据自检引擎(5 维状态:ok/expired/unreachable/misconfigured/fail)
- ✅ JSON Lines 审计 + SSE 实时推送 + 备份 manifest + 探针

### 0.2 V4 解决的痛点

| # | 痛点 | V3 现状 | V4 目标 |
|---|---|---|---|
| **P1** | 主流服务商接入门槛高 | 6 个模板,需手动配 broker.yaml | **40+ 模板**,从官网拉最新调用格式,0 配置 |
| **P2** | 多设备/多场景登录不统一 | 需 mTLS 证书 + TOTP 二选一 | **6 种认证因子可叠加**(mTLS/Password/TOTP/WebAuthn/SMS/Recovery) |
| **P3** | AI 客户端接入方式少 | 4 种(CLI/API Key/MCP/Skill) | **8 种入口**(CLI/SDK/MCP/Skill/REST/WebSocket/SSH/Workload Identity) |
| **P4** | 缺凭据-资源不匹配检测 | 健康检查只检查"凭据对不对" | **资源归属检测**(AK 看到的资源 vs 预期资源) |
| **P5** | AI 接触敏感元数据 | metadata 偶尔泄露 | **100% 凭据零接触**(MCP 响应 0 个 value 字段) |
| **P6** | 凭据轮换流程脱节 | 手动改 secret + 手动 rotate AK | **全自动轮换** + Slack/Email 通知 + 一键 rollback |
| **P7** | 部署复杂 | 需手动配 nginx/SOPS/age/CA | **5 分钟一键** (`bootstrap.ps1 -Auto`) |
| **P8** | 跨云/混合云不通 | 阿里云 + 腾讯云 broker 主备 | **统一代理 + per-service 路由**(AWS/GCP/Azure/Oracle) |
| **P9** | 文档碎片化 | 8 个 PHASE-*.md + PLAN + RUNBOOK | **统一 V4 文档树** + 自动化 docs 同步 |
| **P10** | 开发体验不一致 | CLI/PowerShell 混用,Windows-only 部分 | **完全跨平台** + 单一 invoke 模型 |

### 0.3 V4 一句话定位

> **V4 = 零信任凭据代理 + 服务商模板中心 + 凭据生命周期自动化 + AI 友好调用范式**
>
> 让"AI 开发"在"用密钥这件事"上**和"不需用密钥"一样自然**。

---

## 1. 设计哲学 / Design Philosophy

按优先级排序,冲突时**前面的赢**:

| # | 原则 | 说明 |
|---|---|---|
| 1 | **AI 永远不接触明文** | 默认 proxy 模式;`exec`/`get` 模式审计 100% 覆盖;`describe_secret` 0 value 字段返回 |
| 2 | **身份是叠加的,不是二选一** | 1 种主认证(mTLS/Password/SSO)+ ≥1 种二验(TOTP/WebAuthn/SMS/Recovery) |
| 3 | **服务商即模板,模板即协议** | 每个 type 都有 schema;每个 schema 来自官网;模板升级 = 拉一次最新版 |
| 4 | **调用即范式,范式即 CLI** | `secret-broker` 一条命令覆盖 8 种使用场景,参数 `--help` 自解释 |
| 5 | **生命周期自动化** | 90 天证书轮换 / 凭据过期前 14 天告警 / 自动 rotate / Slack webhook |
| 6 | **可推敲 > 漂亮** | 代码可被开源社区审计;UI 用 Vanilla JS,无需 build 工具;不引入前端框架 |
| 7 | **一份配置,一份密钥,一份审计** | broker.yaml (SOPS) + secrets 详情 (SOPS) + audit/alert/rotation 三套 JSONL 全部对齐 |
| 8 | **零信任 by default** | 即使内网,也是 mTLS;即使 AI 跑在 broker 同主机,也是 HTTPS+签 token;never trust, always verify |

---

## 2. 核心目标 / Core Goals

### 2.1 量化指标(V4 验收)

| 维度 | 指标 | 测量方法 |
|---|---|---|
| **安全性** | AI 接触明文次数 = 0 | MCP 响应 diff + `proxy` 流量分析 |
| **安全性** | 凭据从创建到销毁 100% 审计 | audit JSONL grep |
| **安全性** | 凭据泄露检测时间 < 5 分钟 | healthcheck cron + alert SSE |
| **便捷性** | 5 分钟内 0 → 跑通一个完整调用 | `bootstrap.ps1 -Auto` + 单一命令 |
| **便捷性** | AI 接入新服务商 < 5 行 YAML | 模板数量 + diff 大小 |
| **标准化** | 8 种调用入口共享 100% API schema | OpenAPI 单一来源 |
| **可靠性** | broker uptime ≥ 99.9% | healthcheck + alert |
| **可观测** | 任何调用 1 秒内可追踪 | trace_id 全链路 |

### 2.2 非功能要求

- **性能**:proxy P95 < 300ms (本地) / < 800ms (跨云)
- **兼容性**:Node 20+ / PowerShell 7+ / Windows / Linux / macOS
- **可扩展**:水平扩展 = 加 broker 实例 + 共享 secrets 存储
- **可审计**:100% 关键操作 1 行 JSONL;admin 端可全量下载 + 过滤

---

## 3. 目标用户与场景 / Users & Scenarios

### 3.1 三类用户

| 用户类型 | 主要场景 | 关键痛点 | V4 解决方案 |
|---|---|---|---|
| **AI 开发者** (主流) | AI agent 调 GitHub/OpenAI/Cloud API | AI 看见 PAT → 风险 | proxy + 0 明文 |
| **DevOps/SRE** | CI/CD 推送镜像、跨云部署 | 长期 AK 风险大 | mTLS 短期 cert + 自动 rotate |
| **个人/小团队** | 家里笔记本 + 公司笔记本 + 手机 SSH | 凭据散落多设备 | 一处 SOPS,多处 mTLS |

### 3.2 8 种使用场景(对应 8 种调用入口)

| # | 场景 | 入口 | 命令/方式 |
|---|---|---|---|
| 1 | AI agent 调外部 API | **REST + proxy** | `POST /api/v1/proxy/:service` |
| 2 | AI 调 broker 通过 MCP | **MCP Server** | `mcp-server.js --master-key ...` |
| 3 | 本地脚本/工具调外部 API | **CLI proxy** | `secret-broker proxy github GET /user` |
| 4 | git push 注入凭据 | **CLI exec** | `secret-broker exec --env GH_TOKEN -- git push` |
| 5 | CI/CD 流水线 | **mTLS client cert** | 配置 `~/.broker/config.json` + cert |
| 6 | Web 应用后端 | **API Key (Bearer)** | `Authorization: Bearer mb_live_xxx` |
| 7 | Cloud workload (无 AK) | **Workload Identity / OIDC** | broker 调 STS/Metadata server |
| 8 | SSH 跳板(运维) | **SSH Proxy** | `ssh -J broker user@host` (V4 新增) |

---

## 4. 四大支柱 / Four Pillars

V4 围绕四个相互支撑的支柱:

```
┌────────────────────────────────────────────────────────────────────┐
│                       Pillar 1: 身份认证                           │
│            (mTLS + Password + TOTP + WebAuthn + SMS)               │
│              "证明你是谁" / Prove who you are                     │
└────────────────────────────────────────────────────────────────────┘
                                  ↓
┌────────────────────────────────────────────────────────────────────┐
│                       Pillar 2: 凭据存储                           │
│            (SOPS+age 静态 + 内存解密 + 类型 schema)                 │
│              "存放你的密钥" / Where secrets live                  │
└────────────────────────────────────────────────────────────────────┘
                                  ↓
┌────────────────────────────────────────────────────────────────────┐
│                       Pillar 3: 服务商模板                         │
│         (40+ provider templates, 官方 API 同步, 签名注入)            │
│            "用标准协议调外部" / Standardize external calls        │
└────────────────────────────────────────────────────────────────────┘
                                  ↓
┌────────────────────────────────────────────────────────────────────┐
│                       Pillar 4: 调用范式                           │
│       (CLI / SDK / MCP / REST / WebSocket / SSH / OIDC)            │
│             "任何场景都能接入" / Any scenario, any client         │
└────────────────────────────────────────────────────────────────────┘
```

详细设计见:
- 身份认证 → `docs/DESIGN-V4-IDENTITY-MFA.md`
- 凭据存储 → `docs/DESIGN-V4-PROVIDER-TEMPLATES.md` § A (type schemas)
- 服务商模板 → `docs/DESIGN-V4-PROVIDER-TEMPLATES.md`
- 调用范式 → `docs/DESIGN-V4-API-CALLING-STANDARDS.md`

---

## 5. 整体架构 / Architecture

### 5.1 系统全景图

```
┌──────────────────────────────────────────────────────────────────────┐
│                          AI / DevOps 客户端                          │
│                                                                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  │
│  │ VS Code  │  │ Cursor   │  │ OpenClaw │  │ Claude   │  │ Custom │  │
│  │ Copilot  │  │  + Cline │  │  Skill   │  │   SDK    │  │  Code  │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬───┘  │
│       │             │             │             │             │       │
│       └─────────────┴──────┬──────┴─────────────┴─────────────┘       │
│                            │                                          │
│                  ┌─────────▼──────────┐                               │
│                  │  8 个调用入口之一  │                               │
│                  │ CLI/SDK/MCP/REST  │                               │
│                  │ /WS/SSH/OIDC/Skill │                               │
│                  └─────────┬──────────┘                               │
└────────────────────────────┼──────────────────────────────────────────┘
                             │ mTLS 8443 (HTTPS)
                             │ Bearer 8443 (mTLS-free)
                             │ mcp+http 3001
                             │ SSH 7222
                             ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     Secret Broker (双云主备)                          │
│   Aliyun ECS 2C2G (主)    ←rsync→    Tencent CVM 2C2G (备)            │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │                  Front Layer: mTLS + Auth                     │    │
│  │   mTLS 验证 cert fingerprint → ctx.client                     │    │
│  │   + Bearer 验证 API Key → ctx.api_key                        │    │
│  │   + Password + TOTP → ctx.session                            │    │
│  │   + WebAuthn → ctx.webauthn_cred                             │    │
│  └──────────────────────────────┬───────────────────────────────┘    │
│                                  │                                    │
│  ┌───────────────────────────────▼──────────────────────────────┐    │
│  │               Middleware: Authz + Audit + Trace               │    │
│  │   ACL (allowed_proxy / allowed_secrets)                       │    │
│  │   Rate limit (per client/API key)                              │    │
│  │   Audit emit (JSONL append)                                   │    │
│  │   Trace (W3C traceparent + trace_id)                          │    │
│  └──────────────────────────────┬───────────────────────────────┘    │
│                                  │                                    │
│  ┌───────────────────────────────▼──────────────────────────────┐    │
│  │                  Core: Resolve + Proxy                        │    │
│  │   1. resolveSecret(name) → in-memory plain                    │    │
│  │   2. buildUpstreamRequest(svc, secret) → signed request       │    │
│  │   3. fetch(upstream) → response                               │    │
│  │   4. audit emit / metric observe / healthcheck cache          │    │
│  └──────────────────────────────┬───────────────────────────────┘    │
│                                  │                                    │
│  ┌───────────────────────────────▼──────────────────────────────┐    │
│  │                  Backend: SOPS + Storage                      │    │
│  │   SOPS 加密 broker.yaml + secrets-detail.json                 │    │
│  │   age 私钥(读 600,内存)                                      │    │
│  │   PKI ca/server/clients (OpenSSL 签发)                        │    │
│  │   audit/alert/rotation JSONL                                  │    │
│  └──────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘
                             │ HTTPS (out)
                             ▼
┌──────────────────────────────────────────────────────────────────────┐
│                        40+ 服务商 (上游)                              │
│  GitHub · GitLab · Gitee · Docker Hub · Quay                          │
│  OpenAI · Anthropic · Gemini · Mistral · Cohere · DeepSeek · Zhipu  │
│  阿里云 · 腾讯云 · AWS · GCP · Azure · Oracle                          │
│  Cloudflare · Stripe · 微信支付 · 钉钉 · Slack · Discord                │
│  SSH · PostgreSQL · MySQL · Redis · MongoDB · Sentry · Datadog       │
└──────────────────────────────────────────────────────────────────────┘
```

### 5.2 数据流(典型 AI 调用 GitHub)

```
1. AI: secret-broker proxy github GET /user
2. CLI: mTLSRequest → POST https://broker:8443/api/v1/proxy/github
3. broker:
   a. TLS handshake: 验证 client cert (fingerprint AB:CD:...)
   b. ACL: client.test 在 broker.yaml 允许 service=github
   c. Audit: emit { action: 'proxy', cn: 'client.test', ... }
   d. resolveSecret('github.pat') → SOPS 解密 → 'ghp_xxx' in memory
   e. buildUpstreamRequest:
      - URL: https://api.github.com/user
      - Headers:
        Authorization: Bearer ghp_xxx   ← 注入,只活在内存
        Accept: application/vnd.github+json
        X-GitHub-Api-Version: 2022-11-28
        User-Agent: secret-broker/4.0
   f. fetch upstream → 200 OK { login: 'tyj1987', ... }
   g. Metric: observeMs('proxy.github', latency)
   h. Healthcheck cache: 标记 github.pat ok
   i. 返回 JSON 给 CLI
4. CLI: process.stdout.write(response)
5. AI: 拿到 { login: 'tyj1987', ... },从未看到 ghp_xxx
```

**关键不变量**:
- `ghp_xxx` 在 `resolveSecret` 返回的同一行就被 fetch 消费
- `proxyRequest` 函数返回时,栈帧被 GC;`gcp.memory` 立即清零(buffer)
- 永远不在 audit log 中出现 secret 值(`redact` 强制)
- 永远不在 SSE 推送中出现 secret 值

### 5.3 模块边界

| 层 | 模块 | 职责 | 不做 |
|---|---|---|---|
| **Front** | `lib/session.js` `lib/tls.js` | 协议解析 | 不读业务数据 |
| **Middleware** | `lib/audit.js` `lib/rate-limit.js` `lib/trace.js` | 横切关注 | 不改业务流 |
| **Core** | `api-keys.js` `auth-flow.js` `totp.js` `webauthn.js` `mfa-policy.js` | 认证 + ACL | 不做协议 |
| **Resolve** | `lib/sops.js` `secrets-detail.js` | SOPS 解密 | 不做签名 |
| **Proxy** | `service-templates.js` `signing/*.js` (aliyun_v2, tencent_v3, aws_v4, gcp_jwt, github_basic) | 上游签名 | 不做认证 |
| **Adapter** | `routes/*.js` | URL 路由 | 不做业务 |
| **Client** | `cli/secret-broker.js` `mcp-server.js` | 调用方 | 不存密钥 |

详细设计见对应文档。

---

## 6. V4 增量改造模块 / Increments

V4 在 v3.8 基础上**新增 6 个模块**,**强化 4 个模块**:

### 6.1 新增模块(NEW)

| # | 模块 | 作用 | 优先级 |
|---|---|---|---|
| **M-N1** | **WebAuthn / Passkey** | FIDO2 硬件密钥 + 生物识别 (YubiKey / Touch ID / Windows Hello) | P0 |
| **M-N2** | **Workload Identity** | broker 替 ECS/ACI/GKE 取 STS/OIDC 临时凭证,下游应用 0 AK | P0 |
| **M-N3** | **SSH Proxy** | broker 替 SSH 跳板,密钥零接触 (V4 SSH 代理模式) | P1 |
| **M-N4** | **Provider SDK Sync** | 自动从官网拉最新 API 格式(curl + OpenAPI + docs) | P0 |
| **M-N5** | **Auto-Rotation Engine** | 凭据到期前 14 天触发 rotate,通知 webhook,1-click rollback | P1 |
| **M-N6** | **Cross-Cloud Route** | 一个 service 模板可跨多云(AWS+阿里云+Tencent),按 region 选最近 | P2 |

### 6.2 强化模块(ENHANCE)

| # | 模块 | v3 现状 | V4 增强 |
|---|---|---|---|
| **M-E1** | **Type Schemas** | 30+ 类型 | 50+ 类型,所有字段标注 "V4 官网最新格式" |
| **M-E2** | **Service Templates** | 6 个内置 | 40+ 内置,签名算法 v2/v3/v4 全覆盖 |
| **M-E3** | **MFA Policy** | TOTP only | 6 种因子,基于 risk score 动态要求 |
| **M-E4** | **Audit / Alert** | JSONL | JSONL + OpenTelemetry + Grafana dashboard JSON |

### 6.3 不动的核心(UNCHANGED)

> 不会重写 v3.8 已经稳定的部分。只补不强拆。

- `lib/sops.js` (SOPS 解密)
- `lib/tls.js` (mTLS 配置)
- `healthcheck.js` (5 维状态引擎)
- `lib/audit.js` (JSONL emitter)
- `broker/server.js` 的核心路由(只在末尾追加新路由)

---

## 7. 标准化的密钥调用范式 / Calling Paradigm

V4 定义**统一的调用协议**:任何客户端 → broker → 上游,都走 `proxy` 接口,只是包装形式不同。

### 7.1 核心协议:`POST /api/v1/proxy/:service`

```http
POST /api/v1/proxy/github
Authorization: Bearer mb_live_xxx       ← 或 mTLS client cert
Content-Type: application/json
Traceparent: 00-{trace_id}-{span_id}-01
X-Broker-Client: client.tyj-laptop       ← 可选
X-Idempotency-Key: <uuid>                ← 可选(防重放)

{
  "method": "GET" | "POST" | "PUT" | "DELETE" | "PATCH",
  "path": "/repos/tyj1987/sops-age-template",
  "query": { "per_page": "5" },
  "headers": { "X-Custom": "value" },     ← 可选,合并到 inject_headers
  "body": { "key": "value" } | "string",  ← 可选
  "timeout_ms": 30000,                     ← 可选
  "stream": false                          ← 可选,流式响应
}
```

返回:
```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Broker-Trace-Id: abc123
X-Broker-Provider: github
X-Broker-Latency-Ms: 234
X-Broker-Upstream-Status: 200

{ "login": "tyj1987", ... }               ← 上游原样返回
```

### 7.2 8 种入口的统一语义

| 入口 | 用户调用 | 内部等价于 |
|---|---|---|
| **CLI** | `secret-broker proxy github GET /user` | `POST /api/v1/proxy/github {method, path}` |
| **REST** | `curl -X POST .../api/v1/proxy/github ...` | (直接) |
| **MCP** | `tool: call_service(service='github', method='GET', path='/user')` | mcp-server 内部调 `POST /api/v1/proxy/github` |
| **SDK (Node)** | `await broker.proxy('github', { method: 'GET', path: '/user' })` | 同上,带 mTLS 客户端 |
| **SDK (Python)** | `broker.proxy('github', method='GET', path='/user')` | 同上 |
| **WebSocket** | ws.send(JSON.stringify({action:'proxy', ...})) | broker 升级 ws 路由 |
| **SSH Proxy** | `ssh -J broker user@host` | broker SSH 服务器模式,执行命令时按需 resolve secret |
| **Workload Identity** | ECS instance role 调 metadata server | broker 调 STS,临时凭证注入调用 |

### 7.3 三种调用模式

| 模式 | 命令 | 何时用 | AI 接触明文? |
|---|---|---|---|
| **Proxy** (推荐,80%) | `secret-broker proxy github GET /user` | AI 调外部 API | ❌ 完全不接触 |
| **Exec** (10%) | `secret-broker exec --env GH_TOKEN -- git push` | 注入子进程 | ❌ 子进程结束即丢 |
| **Resolve** (10%,审计严格) | `secret-broker get github.pat` | 真需要明文(罕见) | ⚠️ 显式审计 + 限额 |

### 7.4 错误码标准

```json
// 400-499 客户端错误
{ "error": "bad_request", "detail": "Missing {path}" }
{ "error": "unauthorized", "detail": "mTLS cert required" }
{ "error": "forbidden", "detail": "service 'github' not in allowed_proxy" }
{ "error": "rate_limited", "retry_after_ms": 5000 }
{ "error": "mfa_required", "mfa_token": "...", "method": "totp" }
{ "error": "mfa_invalid", "detail": "Bad TOTP code" }

// 500-599 服务端错误
{ "error": "secret_not_found", "detail": "no secret 'github.pat'" }
{ "error": "secret_expired", "detail": "github.pat status=expired, rotate first" }
{ "error": "upstream_error", "upstream_status": 503, "detail": "..." }
{ "error": "signing_error", "detail": "missing access_key_id" }
{ "error": "internal", "request_id": "abc-123" }
```

详细规范见 `docs/DESIGN-V4-API-CALLING-STANDARDS.md`。

---

## 8. 身份验证纵深防御 / Identity Defense

V4 引入**6 种认证因子**,根据**风险评分**动态选择。

### 8.1 6 种认证因子

| 因子 | 强度 | 用户体验 | 部署成本 | V4 支持 |
|---|---|---|---|---|
| **mTLS 客户端证书** | 强 (设备绑定) | 无感(已签发) | 一次性 | ✅ v3 已有 |
| **Password (scrypt)** | 中 | 需输入 | 0 | ✅ v3 已有 |
| **TOTP (RFC 6238)** | 强 (时间窗) | 输 6 位码 | 装 Authenticator | ✅ v3 已有 |
| **WebAuthn / Passkey** | 强 (防钓鱼) | 指纹/USB Key | 0(浏览器支持) | 🆕 V4 |
| **SMS 验证码** | 中(易劫持) | 收短信 | 部署 SMS 网关 | 🆕 V4 |
| **Recovery Code** | 弱(一次性) | 输 8 位 | 0 | ✅ v3 已有 |

### 8.2 登录状态机

```
                    ┌─────────────────────┐
                    │   START (无凭据)    │
                    └──────────┬──────────┘
                               │
                ┌──────────────┴──────────────┐
                │                             │
        mTLS 客户端证书                  Password (body)
                │                             │
                ▼                             ▼
        ┌───────────────┐            ┌───────────────┐
        │  Cert 验证    │            │  密码验证     │
        │  + 锁定检测   │            │  + 锁定检测   │
        └───────┬───────┘            └───────┬───────┘
                │                             │
                └──────────────┬──────────────┘
                               │
                ┌──────────────▼──────────────┐
                │      已通过主认证            │
                │      role: developer/admin  │
                └──────────────┬──────────────┘
                               │
                ┌──────────────▼──────────────┐
                │   risk_score 计算            │
                │   1) 来源 IP 不在白名单     │
                │   2) 不常用设备              │
                │   3) 敏感操作                │
                │   4) 时间异常                │
                └──────────────┬──────────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
   low (≤20)              mid (20-60)           high (>60)
        │                      │                      │
        ▼                      ▼                      ▼
  无需 MFA          必须 TOTP 或 WebAuthn   TOTP + WebAuthn (两因子)
```

### 8.3 V4 风险评分算法

```js
function calcRiskScore(ctx) {
  let score = 0;
  if (ctx.source_ip && !isInIpWhitelist(ctx.source_ip, ctx.client)) score += 30;
  if (ctx.last_login_at && (Date.now() - ctx.last_login_at) > 30 * 86400_000) score += 20;
  if (ctx.sensitive_action) score += 25;  // rotate-cert, delete-secret
  if (ctx.request_hour < 6 || ctx.request_hour > 22) score += 10;
  if (ctx.user_agent_changed) score += 15;
  return score;
}
```

详细设计见 `docs/DESIGN-V4-IDENTITY-MFA.md`。

---

## 9. 服务商模板库设计 / Provider Templates

### 9.1 模板分类

V4 内置 **40+ 服务商模板**,分 8 类:

| 类别 | 数量 | 示例 |
|---|---|---|
| **代码平台** | 4 | GitHub, GitLab, Gitee, Bitbucket |
| **AI 服务** | 8 | OpenAI, Anthropic, Gemini, Mistral, Cohere, DeepSeek, Zhipu, Moonshot |
| **云厂商 - 中国** | 6 | 阿里云 (ECS, RAM, OSS, ACR), 腾讯云 (CVM, COS, TCR) |
| **云厂商 - 国际** | 5 | AWS, GCP, Azure, Oracle, DigitalOcean |
| **容器/镜像** | 4 | Docker Hub, GHCR, Quay, Harbor |
| **CDN/DNS** | 3 | Cloudflare, Akamai, 阿里云 DNS |
| **支付** | 2 | Stripe, 微信支付 |
| **通信** | 6 | Slack, Discord, 飞书, 钉钉, Telegram, SendGrid |
| **数据库** | 4 | PostgreSQL, MySQL, Redis, MongoDB |
| **监控** | 3 | Sentry, Datadog, New Relic |
| **SSH** | 1 | SSH Proxy (V4 新增) |

### 9.2 模板元数据 schema

每个模板包含:
- `id` (kebab-case)
- `provider` (公司名,如 "GitHub, Inc.")
- `display_name` ("GitHub API")
- `category` (分类)
- `icon` (emoji)
- `auth_type` ("bearer" | "basic" | "header" | "aliyun_v2" | "tencent_v3" | "aws_sigv4" | "gcp_jwt" | "ssh_proxy" | ...)
- `upstream` (官方 base URL)
- `default_secret_field` (e.g. "token" for github_pat)
- `inject_headers` (固定头)
- `signature_algorithm` (签名算法 ID,对应 `signing/*.js`)
- `default_actions` (Dashboard quick actions)
- `official_docs_url` (引用)
- `last_synced_at` (V4 SDK Sync 拉取时间)
- `version` (模板版本,如 "2025-Q3")

### 9.3 V4 SDK Sync — 自动从官网同步

```bash
# broker 内置,定时拉最新格式
secret-broker sync-templates
# → 拉 docs.github.com / openai.com / aliyun.com 等
# → 解析 OpenAPI / curl 示例 / 官方 changelog
# → diff 当前模板 → 新模板
# → PR 创建
```

详见 `docs/DESIGN-V4-PROVIDER-TEMPLATES.md`。

---

## 10. 安全模型与零信任原则 / Zero-Trust

### 10.1 零信任清单(必须满足)

| 原则 | 实施 |
|---|---|
| **never trust, always verify** | 所有请求都需 mTLS 或 Bearer,无内网例外 |
| **least privilege** | 每个 client 显式 allowed_proxy/allowed_resolve |
| **assume breach** | broker 日志全量;一旦发现异常,自动 revoke cert + rotate secret |
| **defense in depth** | TLS + Cert fingerprint + ACL + Rate limit + Audit + Alert |
| **short-lived credentials** | API Key 默认 24h;Child Key 1h;Master Key 30d |
| **encrypt at rest + in transit** | SOPS+age (静态) + TLS 1.3 (传输) |
| **凭据零接触** | proxy/exec 不返回明文;MCP 响应 redact value 字段 |
| **auditable** | 100% 操作 1 行 JSONL,append-only,7 年保留 |

### 10.2 攻击面分析

| 攻击面 | 缓解 |
|---|---|
| **broker 服务器被攻陷** | SOPS 加密 + age 私钥只读;CA 私钥 600;docker read_only rootfs |
| **client cert 丢失** | CRL 立即吊销,broker 拒绝;revoke-cert.ps1 一键 |
| **API Key 泄露** | revokeApiKey 立即失效;audit 找到泄露源;rotate secret |
| **AI prompt injection** | 凭据不进入 prompt 上下文(只在 broker 内存);AI 永远见不到 value |
| **MCP 工具调用越权** | master/child scope 限定;child 默认 `secrets:resolve` + `services:proxy`,无 admin |
| **DDoS** | mTLS 是天然屏障(伪造 cert 失败);rate limit 兜底;Cloudflare WAF |
| **replay** | mTLS 双向 + trace_id + 可选 `X-Idempotency-Key` |
| **insider (admin)** | audit 全量;admin 操作也审计;secrets 永远 SOPS,admin 也需 age key |

### 10.3 凭据生命周期

```
         创建                  使用                   轮换
    ┌─────────────┐      ┌─────────────┐       ┌─────────────┐
    │ Dashboard   │      │ proxy/exec  │       │ 到期前14d   │
    │ SOPS 加密   │ ──▶  │ 注入调用    │ ──▶  │ 告警 →     │
    │ 写 broker   │      │ 100% 审计   │       │ rotate     │
    │ yaml+detail │      │             │       │ → 新 SOPS  │
    └─────────────┘      └─────────────┘       └──────┬──────┘
                                                       │
                                                       ▼
                                                ┌─────────────┐
                                                │ 销毁        │
                                                │ 旧 value    │
                                                │ 立即从内存  │
                                                │ 删除        │
                                                │ audit 标记  │
                                                │ `rotated`   │
                                                └─────────────┘
```

详细安全模型见 `docs/DESIGN-V4-SECURITY-MODEL.md`。

---

## 11. 数据流与生命周期 / Data Flow

### 11.1 启动流程

```
1. docker compose up -d broker
2. broker: sopsDecrypt('secrets/broker.yaml')  →  in-memory config
3. broker: sopsDecrypt('secrets/secrets-detail.json')  →  in-memory secrets
4. broker: loadCA + loadServerCert + loadClientsCert  →  TLS ready
5. broker: listen 0.0.0.0:8443 (mTLS)
6. broker: cron healthcheck 04:00 daily
7. broker: ready
```

### 11.2 首次使用流程(AI 开发者)

```
Day 0:  一次环境搭建
  1. 安装: scoop install age sops git nodejs gitleaks direnv
  2. 克隆: git clone https://github.com/tyj1987/broker.git
  3. 引导: pwsh -File bootstrap.ps1 -Auto
  4. 启动 broker: docker compose up -d broker
  5. 客户端: ./scripts/broker/issue-client-cert.ps1 -CN client.laptop

Day 1+: 日常使用
  1. AI 调外部 API: secret-broker proxy github GET /user
  2. AI 调 broker 本身: 自动用 mTLS
  3. 健康检查: secret-broker health
  4. 审计: secret-broker audit --since "1d"
```

### 11.3 数据流图(完整)

```
   GitHub PAT (ghp_xxx)                      Dashboard 登录
   ┌──────────────┐                          ┌──────────────┐
   │  Admin 输入  │                          │ Browser 输  │
   │  Dashboard   │                          │ 入密码+TOTP │
   └──────┬───────┘                          └──────┬───────┘
          │ SOPS 加密                              │ HTTPS+mTLS
          ▼                                        ▼
   ┌─────────────────────┐                ┌─────────────────┐
   │ secrets-detail.json │                │   /login        │
   │  (SOPS encrypted)   │                │  + /login/mfa   │
   └──────────┬──────────┘                └────────┬────────┘
              │                                     │
              │ sopsDecrypt()              ctx.client
              │                             ctx.session
              │                                     │
              │     ┌───────────────────────────────┘
              │     │
              ▼     ▼
   ┌──────────────────────────────────────┐
   │        Secret Broker Core           │
   │                                      │
   │  ctx.client + ctx.session            │
   │           ↓                          │
   │  canProxy(service, ctx, method)      │
   │           ↓                          │
   │  resolveSecret(token_secret)         │
   │           ↓ (in-memory)              │
   │  buildUpstreamRequest(svc, secret)   │
   │           ↓                          │
   │  fetch(upstream)                     │
   │           ↓                          │
   │  audit emit / metric observe         │
   │           ↓                          │
   │  return response                     │
   └─────────────────┬────────────────────┘
                     │ HTTPS
                     ▼
   ┌──────────────────────────────────────┐
   │  上游 API (GitHub / OpenAI / 阿里云) │
   │  Authorization: Bearer ghp_xxx (in  │
   │  request, never in response)         │
   └──────────────────────────────────────┘
```

---

## 12. 开发体验(DevEx)设计

### 12.1 一行命令跑通

```powershell
# 0 准备(单次)
scoop install age sops git nodejs gitleaks direnv
git clone https://github.com/tyj1987/broker.git
cd broker

# 1 引导(单次)
pwsh -File bootstrap.ps1 -Auto

# 2 跑 broker(本地)
docker compose up -d broker

# 3 客户端(每天)
secret-broker health
secret-broker proxy github GET /user
```

### 12.2 CLI 帮助系统

```bash
secret-broker --help
# 输出分层:概念 / 命令 / 场景示例 / 链接到 docs

secret-broker proxy --help
# 输出:用法 / 所有参数 / 5 个真实示例

secret-broker pki issue-client --help
# 输出:用法 / -CN / -Role / -Register / -Days / cert 生命周期
```

### 12.3 错误信息

```bash
# 不好的错误
$ secret-broker proxy github GET /user
ERROR: 500

# 好的错误 (V4)
$ secret-broker proxy github GET /user
ERROR [secret_not_found]: secret 'github.pat' not configured
  → Action: Add via Dashboard at https://broker.52trz.com/admin/secrets/new?type=github_pat
  → Or CLI: secret-broker admin secret create --type github_pat --name github.pat
  → Docs: docs/DESIGN-V4-PROVIDER-TEMPLATES.md#github_pat
  → Trace ID: abc-123 (show to support)
```

### 12.4 调试工具

```bash
# 1. 完整 trace 一条调用
secret-broker --trace proxy github GET /user
# → 输出: 客户端 cert fp, mTLS handshake, 路由, ACL, resolveSecret, buildUpstream, fetch, audit

# 2. 模拟调用(不发到上游)
secret-broker --dry-run proxy github GET /user
# → 输出: 注入的 headers, signed request 预览, 不发

# 3. 验证模板
secret-broker validate-template github
# → 输出: 模板 schema, 字段, 必填, 默认 action

# 4. 验证 broker.yaml
secret-broker validate-config
# → 输出: services 列表, clients 列表, ACL conflict 检测
```

### 12.5 跨平台

| 平台 | 支持 | 实现 |
|---|---|---|
| **Windows 10+** | ✅ | PowerShell 5.1+ / pwsh 7+ / Node 20+ |
| **Linux** | ✅ | bash + Node 20+ |
| **macOS** | ✅ | zsh + Node 20+ |

CLI 用 Node 写,无 shell 特定语法;bootstrap 用 PowerShell(Windows 优先)+ bash(可选)。

---

## 13. 可观测性 / 告警 / 应急

### 13.1 三大类指标

| 类别 | 指标 | 导出 |
|---|---|---|
| **流量** | `proxy.{service}.count` `proxy.{service}.latency_ms.p95` | Prometheus `/metrics` |
| **凭据** | `secret.{name}.status` (ok/expired/unreachable/...) | JSONL + SSE |
| **安全** | `auth.fail` `cert.expired` `rate_limited` `mfa.fail` | JSONL + alert webhook |

### 13.2 告警渠道(可插拔)

```yaml
# broker.yaml
alerting:
  channels:
    - type: slack_webhook
      url: '{{secret.slack_alerts.url}}'
      events: [secret.expired, cert.expiring, mfa.fail_threshold]
    - type: email
      smtp: '{{secret.smtp_alerts}}'
      events: [secret.expired, auth.brute_force]
    - type: feishu_webhook
      url: '{{secret.feishu_alerts.url}}'
      events: [upstream.error_5xx]
```

### 13.3 应急流程

| 事件 | 检测 | 响应 | 工具 |
|---|---|---|---|
| **client cert 丢失** | 用户报告 / 设备失窃 | `revoke-cert.ps1` → CRL 更新 | 5 秒 |
| **API Key 泄露** | audit 日志异常 / 用户报告 | `POST /api/v1/api-keys/:id` DELETE | 立即 |
| **secret value 泄露** | healthcheck 失败 / 用户报告 | rotate secret + invalidate sessions | 30 秒 |
| **broker 服务器被攻陷** | 监控告警 | revoke 所有 cert + rotate age key + 重新 bootstrap | 30 分钟 |
| **MCP 工具越权** | audit 检测 | 立即 revoke master + child + 调查 | 立即 |

---

## 14. 实施路线图 / Roadmap

### 14.1 三阶段交付(预计 6 个月)

| 阶段 | 周期 | 重点 | 交付 |
|---|---|---|---|
| **P1 (V4.0)** | 1-2 月 | **核心强化** | 40+ 模板 / MFA 策略 / SDK Sync / Auto-Rotate / WebAuthn / 文档统一 |
| **P2 (V4.1)** | 3-4 月 | **跨场景** | Workload Identity / SSH Proxy / WebSocket 通道 / Python SDK / VS Code Extension |
| **P3 (V4.2)** | 5-6 月 | **生态** | Cloud 1-click (AWS/GCP/Azure Marketplace) / Helm chart / Terraform module / Grafana dashboard JSON |

### 14.2 P1 详细任务

| # | 任务 | 工作量 | 优先级 |
|---|---|---|---|
| 1 | WebAuthn 注册/认证端点 | 1 周 | P0 |
| 2 | MFA Policy 引擎(risk score) | 1 周 | P0 |
| 3 | SDK Sync 工具(从 OpenAPI 拉模板) | 1 周 | P0 |
| 4 | 模板扩充 30 → 40+ | 2 周 | P0 |
| 5 | Auto-Rotate 引擎(cron + webhook) | 1 周 | P1 |
| 6 | Master/Child API Key 增强(IP/CIDR + 限额细化) | 3 天 | P1 |
| 7 | 统一 OpenAPI 3.1 schema | 1 周 | P0 |
| 8 | 统一 V4 文档(7 个子文档) | 1 周 | P0 |
| 9 | 跨平台 CI (Windows + Linux + macOS) | 1 周 | P0 |
| 10 | 测试扩充(从 18 → 30+ 测试) | 1 周 | P0 |

---

## 15. 风险与不做的事 / Risks & Out-of-Scope

### 15.1 风险

| 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|
| **SOPS + age 私钥丢失** | 低 | 极高 | 双钥匙 (key A + key B);USB 备份;rotate 流程 |
| **OpenAI/Anthropic 等 API 格式变更** | 中 | 中 | SDK Sync 自动检测;模板版本化;留 1-2 季度兼容 |
| **broker 单点故障** | 低 | 高 | 双云主备;rsync 同步;DNS failover |
| **AI 越权调用** | 低 | 中 | ACL + rate limit + audit;MCP 工具粒度化 |
| **凭据零接触破窗** | 低 | 极高 | 强制 audit redact 字段;Prometheus 监控异常 value leak |
| **合规要求(等保/SOC2)** | 中 | 中 | 保留 7 年 audit;支持 KMS 集成;SOC2 控制项可勾选 |

### 15.2 明确不做

- ❌ **不**做完整 IAM/PAM 替代(用 SOPS+age+AK 体系已够)
- ❌ **不**做 KMS 同步(用户自管,broker 只读)
- ❌ **不**做 Web UI 框架升级(vanilla JS 已够)
- ❌ **不**做 secret 自动发现(用 healthcheck 主动验证)
- ❌ **不**做跨 broker 实例的 secret 共享(各自 SOPS,各自 mTLS)
- ❌ **不**做 broker→broker 联邦(复杂度过高)

---

## 16. 附录:术语表 / Glossary

| 术语 | 含义 |
|---|---|
| **mTLS** | Mutual TLS,客户端和服务端互相验证证书 |
| **SOPS** | Mozilla SOPS,文件级加密工具(支持 age / KMS / PGP) |
| **age** | 现代加密工具(替代 GPG),用于对称/非对称加密 |
| **TOTP** | Time-based One-Time Password (RFC 6238) |
| **WebAuthn / Passkey** | FIDO2/WebAuthn 协议,基于公钥的无密码认证 |
| **MFA** | Multi-Factor Authentication,多因素认证 |
| **OIDC** | OpenID Connect,身份联合协议 |
| **STS** | Security Token Service,临时凭证服务(阿里云/AWS) |
| **ACL** | Access Control List,访问控制列表 |
| **ACL** | (V4 用 `allowed_proxy` / `allowed_resolve` 显式) |
| **CRL** | Certificate Revocation List,证书吊销列表 |
| **AK / SK** | AccessKey / SecretKey(云厂商术语) |
| **PAT** | Personal Access Token(GitHub 等) |
| **KMS** | Key Management Service(云厂商密钥管理) |
| **Proxy mode** | AI 调外部 API,broker 替注入凭证,AI 看不见明文 |
| **Resolve mode** | AI 显式取明文,严格审计 |
| **Exec mode** | 注入子进程环境变量,子进程结束即丢 |
| **Service Template** | 服务商模板(预定义 upstream + 签名 + 默认 actions) |
| **Type Schema** | Secret 类型定义(github_pat / openai_key / aliyun_ak 等) |
| **Healthcheck** | 凭据自检,5 维状态:ok/expired/unreachable/misconfigured/fail |
| **Audit JSONL** | 每行一条 JSON 事件,append-only |
| **Workload Identity** | broker 替 ECS/AKS/GKE 取 STS/OIDC 临时凭证 |

---

## 相关文档 / Related Docs

| 文档 | 作用 |
|---|---|
| [docs/DESIGN-V4-IDENTITY-MFA.md](./DESIGN-V4-IDENTITY-MFA.md) | 身份认证 + MFA 详细设计 |
| [docs/DESIGN-V4-PROVIDER-TEMPLATES.md](./DESIGN-V4-PROVIDER-TEMPLATES.md) | 40+ 服务商模板详细设计 |
| [docs/DESIGN-V4-API-CALLING-STANDARDS.md](./DESIGN-V4-API-CALLING-STANDARDS.md) | 8 种调用入口 + OpenAPI 规范 |
| [docs/DESIGN-V4-SECURITY-MODEL.md](./DESIGN-V4-SECURITY-MODEL.md) | 零信任 + 攻击面 + 应急 |
| [docs/DESIGN-V4-ROADMAP.md](./DESIGN-V4-ROADMAP.md) | 实施路线图(详细) |
| [docs/PLAN-secret-broker-v3.md](./PLAN-secret-broker-v3.md) | V3 设计(本设计的前置) |
| [RUNBOOK.md](../RUNBOOK.md) | 运维手册 |
| [README.md](../README.md) | 项目入口 |

---

**作者**:Mavis (AI 架构助手) + 脱永军 (项目所有者)
**最后更新**:2026-09-01
**版本**:V4.0-MASTER
