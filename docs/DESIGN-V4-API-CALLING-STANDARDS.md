# Secret Broker V4 — API Calling Standards

> **本文档**:V4 API 调用标准化设计
> **基础**:v3.0 路由 + v3.5 MCP server + v3.8 session/cookie
> **目标**:**8 种调用入口,1 套核心协议,100% OpenAPI schema**
> **覆盖**:CLI / SDK / MCP / REST / WebSocket / SSH / OIDC / Skill

---

## 目录

1. [设计目标](#1-设计目标)
2. [核心协议 `POST /api/v1/proxy/:service`](#2-核心协议-post-apiv1proxyservice)
3. [8 种调用入口](#3-8-种调用入口)
4. [OpenAPI 3.1 Schema](#4-openapi-31-schema)
5. [错误码规范](#5-错误码规范)
6. [SDK 设计](#6-sdk-设计)
7. [CLI 设计](#7-cli-设计)
8. [MCP Server 设计](#8-mcp-server-设计)
9. [WebSocket 实时通道](#9-websocket-实时通道)
10. [SSH Proxy 模式](#10-ssh-proxy-模式)
11. [Workload Identity](#11-workload-identity)
12. [OpenClaw / Claude / Cursor Skill](#12-openclaw--claude--cursor-skill)
13. [可观测性集成](#13-可观测性集成)
14. [测试矩阵](#14-测试矩阵)

---

## 1. 设计目标

### 1.1 必须满足

| 目标 | 验收 |
|---|---|
| **1 套核心协议** | 所有入口最终都调 `POST /api/v1/proxy/:service` |
| **OpenAPI 3.1 schema** | 100% 端点用 OpenAPI 描述,生成 SDK |
| **8 种入口** | CLI / SDK (Node+Python+Go) / MCP / REST / WebSocket / SSH / OIDC / Skill |
| **错误码统一** | JSON 格式,所有入口一致 |
| **可观测性** | 每个请求带 trace_id,跨入口可追踪 |
| **幂等性** | 可选 `X-Idempotency-Key` 防重放 |
| **流式响应** | proxy 支持 SSE / chunked |
| **离线缓存** | GET 可选 `Cache-Control: max-age=N` |

### 1.2 与 v3 差异

| 项 | v3.8 | V4 |
|---|---|---|
| 调用入口 | 4 (CLI / MCP / REST / Skill) | **8** |
| OpenAPI | 分散 | **100% schema 单一来源** |
| SDK | 无 | **Node + Python + Go** |
| WebSocket | 无 | **新增** |
| SSH Proxy | 占位 | **完整实现** |
| Workload Identity | 无 | **新增** (OIDC) |
| 错误码 | 部分 | **统一规范** |
| 流式 | 无 | **proxy 支持 SSE** |
| 幂等 | 无 | **可选 X-Idempotency-Key** |

---

## 2. 核心协议 `POST /api/v1/proxy/:service`

### 2.1 请求

```http
POST /api/v1/proxy/github
Host: broker.52trz.com:8443
Authorization: Bearer mb_live_xxxxxxxxxxxxxxxxxxxx     ← 任一认证
Traceparent: 00-{trace_id}-{span_id}-01
X-Broker-Client: client.tyj-laptop
X-Idempotency-Key: 9f4d8b3a-...                         ← 可选
Content-Type: application/json

{
  "method": "GET" | "POST" | "PUT" | "DELETE" | "PATCH",
  "path": "/repos/tyj1987/broker",
  "query": { "per_page": "5" },
  "headers": { "X-Custom-Header": "value" },
  "body": { "key": "value" } | "string" | null,
  "timeout_ms": 30000,
  "stream": false
}
```

### 2.2 响应(成功)

```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Broker-Trace-Id: abc-123-def
X-Broker-Provider: github
X-Broker-Latency-Ms: 234
X-Broker-Upstream-Status: 200
X-Broker-Idempotent-Replay: false

{ "login": "tyj1987", "id": 12345, ... }
```

### 2.3 响应(失败)

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json
X-Broker-Trace-Id: abc-123-def

{
  "error": "unauthorized",
  "detail": "mTLS cert required or Bearer token",
  "request_id": "abc-123-def",
  "docs": "https://docs.52trz.com/broker/auth"
}
```

### 2.4 流式响应(SSE)

```http
POST /api/v1/proxy/openai
{ "method": "POST", "path": "/v1/chat/completions", "stream": true, "body": {...} }

→ HTTP/1.1 200 OK
  Content-Type: text/event-stream
  X-Broker-Provider: openai

  data: {"id":"chatcmpl-1","choices":[{"delta":{"content":"Hello"}}]}

  data: {"id":"chatcmpl-1","choices":[{"delta":{"content":" world"}}]}

  data: [DONE]
```

### 2.5 字段约束

| 字段 | 必填 | 约束 |
|---|---|---|
| `method` | ✅ | 枚举 GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS |
| `path` | ✅ | 以 `/` 开头,长度 ≤ 2048,匹配 ACL `allow_paths` |
| `query` | ❌ | object,key=value string |
| `headers` | ❌ | object,key=value string;不可覆盖 `Authorization`/`Host` |
| `body` | ❌ | object / string / null,大小 ≤ 10MB |
| `timeout_ms` | ❌ | 1000-60000,默认 30000 |
| `stream` | ❌ | bool,默认 false |

---

## 3. 8 种调用入口

### 3.1 入口矩阵

| 入口 | 谁用 | 协议 | 鉴权 | 何时用 |
|---|---|---|---|---|
| **CLI** | 开发者本地 | HTTPS + mTLS | cert | 终端命令 |
| **SDK Node** | Node 应用 | HTTPS + mTLS | cert | 后端服务 |
| **SDK Python** | Python 应用 | HTTPS + mTLS | cert | 后端服务 |
| **SDK Go** | Go 应用 | HTTPS + mTLS | cert | 后端服务 |
| **MCP Server** | AI agent | HTTP + JSON-RPC | master/child key | AI 调外部 API |
| **REST (curl)** | 任何 | HTTPS | mTLS / Bearer | 调试 / 一次性 |
| **WebSocket** | 实时场景 | WSS + mTLS | cert | 订阅事件 / 双向流 |
| **SSH Proxy** | 运维 | SSH 协议 | cert + 二验 | ssh 跳板 / 远程执行 |
| **OIDC (Workload Identity)** | 容器 | HTTPS + JWT | OIDC token | K8s Pod / ECS 任务 |
| **Skill** | IDE / 助手 | 调用 CLI / SDK | mTLS | OpenClaw / Claude Code / Cursor |

### 3.2 入口决策树

```
我想用 broker
    │
    ├─ 我是 AI agent
    │   └─ 用 MCP Server 或 Skill
    │
    ├─ 我是 Node/Python/Go 后端
    │   └─ 用 SDK(mTLS 长连接 / Bearer 短期)
    │
    ├─ 我是终端用户
    │   └─ 用 CLI
    │
    ├─ 我是 CI/CD
    │   └─ 用 CLI 或 REST(mTLS cert)
    │
    ├─ 我是浏览器
    │   └─ 用 REST(Bearer 短期 key)
    │
    ├─ 我是 K8s/ECS Pod
    │   └─ 用 OIDC(无 AK,broker 取 STS)
    │
    ├─ 我是 SSH 客户端
    │   └─ 用 SSH Proxy(ssh -J broker)
    │
    └─ 我想订阅事件
        └─ 用 WebSocket(SSE 也行)
```

---

## 4. OpenAPI 3.1 Schema

### 4.1 端点分类

| 类别 | 端点数 | 用途 |
|---|---|---|
| **公开** | 5 | health / ready / metrics / static / login |
| **认证** | 8 | login / login/mfa / login/sms / login/recovery / logout / totp / webauthn |
| **Me** | 12 | /me + /me/totp/* + /me/webauthn/* + /me/phone/* + /me/recovery-codes/* + /me/audit + /me/change-password + /me/rotate-cert |
| **Secrets** | 4 | list / resolve / create / delete (admin 后 2) |
| **Services** | 3 | list / describe / use proxy |
| **Proxy** | 1 | POST /api/v1/proxy/:service |
| **API Keys** | 6 | list / create / revoke / master / issue-child / use |
| **Admin** | 15 | secrets / services / clients / types / templates / audit / alert / reload / recover |
| **Health** | 3 | status / run / stream |
| **MCP** | 1 | JSON-RPC over HTTP |
| **WebSocket** | 1 | /ws |
| **总** | **~60** | 端点 |

### 4.2 完整 OpenAPI 文档

```yaml
# docs/openapi.yaml
openapi: 3.1.0
info:
  title: Secret Broker API
  version: 4.0.0
  description: |
    mTLS Secret Broker for AI clients. 让 AI 不接触明文密钥。
  contact:
    name: 脱永军
    url: https://github.com/tyj1987/broker
  license:
    name: MIT

servers:
  - url: https://broker.52trz.com:8443
    description: Production (Aliyun)
  - url: https://broker-bk.52trz.com:8443
    description: Production (Tencent, fallback)
  - url: http://localhost:8443
    description: Local dev

security:
  - mtls: []
  - bearerAuth: []
  - sessionCookie: []

paths:
  /health:
    get:
      summary: 健康检查
      security: []  # 公开
      responses:
        '200': { $ref: '#/components/responses/HealthOk' }
        '503': { $ref: '#/components/responses/HealthFail' }

  /api/v1/proxy/{service}:
    post:
      summary: 代理调用外部服务
      description: |
        主流入口。broker 解密 secret,自动签名/注入,转发到上游。
        AI 永远不接触明文。
      parameters:
        - in: path
          name: service
          required: true
          schema: { type: string }
          description: 服务名(如 'github', 'openai', 'aliyun_ecs')
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: '#/components/schemas/ProxyRequest' }
      responses:
        '200':
          description: 成功(上游响应)
          content:
            application/json:
              schema: { $ref: '#/components/schemas/ProxyResponse' }
            text/event-stream:
              schema: { type: string }
        '400': { $ref: '#/components/responses/BadRequest' }
        '401': { $ref: '#/components/responses/Unauthorized' }
        '403': { $ref: '#/components/responses/Forbidden' }
        '404': { $ref: '#/components/responses/NotFound' }
        '429': { $ref: '#/components/responses/RateLimited' }
        '502': { $ref: '#/components/responses/UpstreamError' }
        '503': { $ref: '#/components/responses/ServiceUnavailable' }

  /api/v1/login:
    post:
      summary: 密码登录(或 mTLS 隐式登录)
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [password]
              properties:
                client: { type: string }
                password: { type: string, format: password }
      responses:
        '200':
          description: 登录成功,返回 session token
          headers:
            Set-Cookie:
              schema: { type: string }
          content:
            application/json:
              schema: { $ref: '#/components/schemas/LoginResponse' }
        '401': { $ref: '#/components/responses/Unauthorized' }
        '429': { $ref: '#/components/responses/RateLimited' }

components:
  securitySchemes:
    mtls:
      type: mutualTLS
      description: mTLS 客户端证书
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: API Key (mb_live_xxx)
    sessionCookie:
      type: apiKey
      in: cookie
      name: broker_session

  schemas:
    ProxyRequest:
      type: object
      required: [method, path]
      properties:
        method:
          type: string
          enum: [GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS]
        path:
          type: string
          pattern: '^/'
          maxLength: 2048
        query:
          type: object
          additionalProperties: { type: string }
        headers:
          type: object
          additionalProperties: { type: string }
        body:
          oneOf:
            - type: object
            - type: string
            - type: 'null'
        timeout_ms:
          type: integer
          minimum: 1000
          maximum: 60000
          default: 30000
        stream:
          type: boolean
          default: false

    ProxyResponse:
      oneOf:
        - type: object
        - type: string
        - type: 'null'

    LoginResponse:
      type: object
      properties:
        token: { type: string, description: 'session token' }
        expires_at: { type: string, format: date-time }
        cn: { type: string }
        role: { type: string, enum: [developer, admin, ci] }
        mfa_methods: { type: array, items: { type: string } }
        mfa_required:
          type: boolean
          description: '需要二验,字段同 LoginMfaResponse'
        mfa_token:
          type: string
          description: 'mfa_token 需 POST /login/mfa'

    Error:
      type: object
      required: [error, request_id]
      properties:
        error:
          type: string
          enum:
            - bad_request
            - unauthorized
            - forbidden
            - not_found
            - rate_limited
            - mfa_required
            - mfa_invalid
            - secret_not_found
            - secret_expired
            - secret_unreachable
            - secret_misconfigured
            - upstream_error
            - signing_error
            - internal
        detail: { type: string }
        request_id: { type: string, description: 'trace_id for support' }
        retry_after_ms: { type: integer }
        docs: { type: string, description: 'docs URL' }

  responses:
    BadRequest:
      description: 客户端错误
      content:
        application/json:
          schema: { $ref: '#/components/schemas/Error' }
    Unauthorized:
      description: 未认证
      content:
        application/json:
          schema:
            allOf:
              - $ref: '#/components/schemas/Error'
              - example:
                  error: unauthorized
                  detail: mTLS cert required
    Forbidden:
      description: 权限不足
      content:
        application/json:
          schema: { $ref: '#/components/schemas/Error' }
    NotFound:
      description: 资源不存在
      content:
        application/json:
          schema: { $ref: '#/components/schemas/Error' }
    RateLimited:
      description: 触发限流
      headers:
        Retry-After:
          schema: { type: integer, description: '秒' }
      content:
        application/json:
          schema: { $ref: '#/components/schemas/Error' }
    UpstreamError:
      description: 上游错误
      content:
        application/json:
          schema: { $ref: '#/components/schemas/Error' }
    ServiceUnavailable:
      description: 服务不可用(凭据过期等)
      content:
        application/json:
          schema: { $ref: '#/components/schemas/Error' }
    HealthOk:
      description: 健康
      content:
        application/json:
          schema:
            type: object
            properties:
              status: { type: string, enum: [ok] }
              version: { type: string }
              uptime: { type: number }
    HealthFail:
      description: 不健康
      content:
        application/json:
          schema:
            type: object
            properties:
              status: { type: string, enum: [degraded, down] }
              checks: { type: object }
```

### 4.3 OpenAPI 自动生成

```bash
# 从 broker 代码生成 OpenAPI
secret-broker openapi generate > docs/openapi.yaml

# 客户端 SDK 生成
secret-broker openapi sdk --lang node --out sdk/node/
secret-broker openapi sdk --lang python --out sdk/python/
secret-broker openapi sdk --lang go --out sdk/go/

# Postman 集合
secret-broker openapi postman > docs/postman.json

# HTML 文档
secret-broker openapi docs > docs/api.html
```

---

## 5. 错误码规范

### 5.1 错误分类

| HTTP | error code | 含义 | 客户端行动 |
|---|---|---|---|
| 400 | `bad_request` | 请求格式错 | 改请求 |
| 401 | `unauthorized` | 未认证 | 重新登录 / 换 cert |
| 403 | `forbidden` | 权限不足 | 检查 ACL / 申请权限 |
| 404 | `not_found` | 资源不存在 | 改名 / 创建 |
| 429 | `rate_limited` | 限流 | 等 Retry-After 秒 |
| 401 | `mfa_required` | 需要二验 | 调 /login/mfa |
| 401 | `mfa_invalid` | 二验失败 | 重输 |
| 503 | `secret_not_found` | secret 不存在 | 创建 secret |
| 503 | `secret_expired` | secret 过期 | rotate secret |
| 503 | `secret_unreachable` | 上游不可达 | 检查网络/防火墙 |
| 503 | `secret_misconfigured` | secret 配置错 | 改 broker.yaml |
| 502 | `upstream_error` | 上游 4xx/5xx | 看 detail |
| 500 | `signing_error` | 签名失败 | 改 secret 字段 |
| 500 | `internal` | 内部错误 | 联系 admin,带 request_id |

### 5.2 错误响应格式

```json
{
  "error": "rate_limited",
  "detail": "client.test exceeded 100/hour",
  "request_id": "abc-123-def-456",
  "retry_after_ms": 5000,
  "docs": "https://docs.52trz.com/broker/errors#rate_limited"
}
```

### 5.3 关键设计:零明文

```javascript
// broker 端:任何错误响应都不返回 secret value
function jsonError(res, status, error, detail, extras = {}) {
  const body = {
    error,
    detail: redactSecrets(detail),  // 过滤 AK/PAT/secret
    request_id: getRequestId(),
    ...extras,
  };
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(body));
}
```

---

## 6. SDK 设计

### 6.1 Node.js SDK

```typescript
// sdk/node/src/client.ts
import { SecretBroker } from '@broker/sdk';

const client = new SecretBroker({
  endpoint: 'https://broker.52trz.com:8443',
  clientCert: '~/.broker/client.crt',
  clientKey: '~/.broker/client.key',
  caCert: '~/.broker/ca.crt',
});

// 主流:proxy 调用
const user = await client.proxy('github', {
  method: 'GET',
  path: '/user',
});
console.log(user.login);  // 'tyj1987'

// 其他 service
const instances = await client.proxy('aliyun_ecs', {
  method: 'GET',
  path: '/?Action=DescribeInstances&RegionId=cn-hangzhou',
});

// 列表 secrets
const secrets = await client.listSecrets();
// [{ name: 'github.pat', type: 'github_pat' }]

// 解析 secret(强审计,需 allow_resolve)
const pat = await client.resolveSecret('github.pat');
console.log(pat);  // 'ghp_xxx'(慎用)

// 错误处理
try {
  await client.proxy('github', { method: 'GET', path: '/user' });
} catch (e) {
  if (e.code === 'rate_limited') {
    await sleep(e.retryAfterMs);
  }
}

// 高级:Workload Identity(OIDC)
const client2 = new SecretBroker({
  endpoint: 'https://broker.52trz.com:8443',
  workloadIdentity: {
    oidcTokenFile: '/var/run/secrets/tokens/oidc',
    roleArn: 'arn:broker:role/tyj-developer',
  },
});
```

### 6.2 Python SDK

```python
from broker_sdk import SecretBroker

client = SecretBroker(
    endpoint="https://broker.52trz.com:8443",
    client_cert="~/.broker/client.crt",
    client_key="~/.broker/client.key",
    ca_cert="~/.broker/ca.crt",
)

# 主流
user = client.proxy("github", method="GET", path="/user")
print(user["login"])

# 流式
for chunk in client.proxy("openai", method="POST", path="/v1/chat/completions", stream=True):
    print(chunk)
```

### 6.3 Go SDK

```go
import brokersdk "github.com/tyj1987/broker-sdk-go"

client, _ := brokersdk.New(brokersdk.Config{
    Endpoint: "https://broker.52trz.com:8443",
    ClientCert: "~/.broker/client.crt",
    ClientKey: "~/.broker/client.key",
    CACert: "~/.broker/ca.crt",
})

ctx := context.Background()
resp, err := client.Proxy(ctx, "github", brokersdk.ProxyRequest{
    Method: "GET",
    Path: "/user",
})
```

### 6.4 SDK 设计原则

- **零依赖** — 必要时引入最少的依赖
- **强类型** — TypeScript / Python type hints / Go strong typing
- **错误友好** — 抛业务异常,带 `code/retryAfterMs/requestId`
- **自动 retry** — 429 自动按 Retry-After 重试
- **可观察** — 透传 trace_id,可注入到 log/OTel
- **同步 + 异步** — Node 异步/Python 同步-Go context

---

## 7. CLI 设计

### 7.1 完整命令

```bash
secret-broker <command> [args]
secret-broker <command> --help

# === 通用 ===
secret-broker health                    # 健康检查
secret-broker identity                  # 当前身份(cert/session/api_key)
secret-broker version                   # broker 版本
secret-broker openapi                   # 输出 OpenAPI schema
secret-broker openapi sdk --lang node   # 生成 SDK
secret-broker help                      # 详细帮助
secret-broker docs                      # 打开浏览器到 docs

# === Proxy 模式 (主) ===
secret-broker proxy <service> <METHOD> <path> \
  [--body '<json>'] \
  [--query k=v]... \
  [--header K:V]... \
  [--timeout 30000] \
  [--stream]

# 示例
secret-broker proxy github GET /user
secret-broker proxy openai POST /v1/chat/completions --body '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
secret-broker proxy aliyun_ecs GET "/?Action=DescribeInstances&RegionId=cn-hangzhou"

# === Resolve 模式 (强审计) ===
secret-broker get <secret-name>         # 输出明文,需 allowed_resolve

# === Exec 模式 (子进程注入) ===
secret-broker exec --env "VAR1,VAR2" -- <cmd> [args]
# 例:
secret-broker exec --env "GH_TOKEN" -- git push origin main
secret-broker exec --env "AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY,AWS_SESSION_TOKEN" -- terraform apply

# === Login (Web 登录,无 mTLS 时) ===
secret-broker login                     # 交互式
secret-broker login --user tyj --password-stdin --totp-stdin
secret-broker login --webauthn
secret-broker login --sms
secret-broker login --recovery
secret-broker logout

# === Secrets 管理 (admin) ===
secret-broker secrets list
secret-broker secrets describe <name>
secret-broker secrets create --type <type> --name <name> [--data <k=v>]...
secret-broker secrets update <name> --data <k=v>...
secret-broker secrets delete <name>
secret-broker secrets rotate <name>     # 触发 rotate

# === Services 管理 (admin) ===
secret-broker services list
secret-broker services describe <service>
secret-broker services add --from-template github
secret-broker services enable/disable <service>

# === Clients 管理 (admin) ===
secret-broker clients list
secret-broker clients create --name <name> --role <role>
secret-broker clients update <name> --add-allow-proxy github
secret-broker clients delete <name>

# === API Keys ===
secret-broker keys list
secret-broker keys create --name <name> [--scopes secrets:resolve,services:proxy] [--ttl 86400]
secret-broker keys create-master --name <name>  # 30d master
secret-broker keys revoke <id>
secret-broker keys usage <id>

# === TOTP / WebAuthn / SMS ===
secret-broker totp setup
secret-broker totp verify <code>
secret-broker totp disable
secret-broker webauthn register
secret-broker webauthn list
secret-broker webauthn delete <id>
secret-broker phone set +8613800000000
secret-broker phone verify <code>

# === PKI ===
secret-broker pki issue-client --cn <name> [--role developer] [--register]
secret-broker pki revoke --fingerprint <sha256>
secret-broker pki list
secret-broker pki show-ca

# === Audit ===
secret-broker audit list --since 1d --action proxy --cn client.test
secret-broker audit stream                # SSE 实时
secret-broker audit export --since 1d    # 下载 jsonl

# === Healthcheck ===
secret-broker healthcheck status
secret-broker healthcheck run
secret-broker healthcheck stream          # SSE

# === Template / Sync ===
secret-broker template list
secret-broker template describe github
secret-broker template generate --from-openapi <url>
secret-broker template upgrade github
secret-broker template smoke github openai ...

# === Validate / Debug ===
secret-broker validate-config
secret-broker validate-template github
secret-broker --trace proxy github GET /user
secret-broker --dry-run proxy github GET /user

# === Admin ===
secret-broker admin reload
secret-broker admin backup
secret-broker admin emergency-recover --user tyj
```

### 7.2 输出格式

```bash
# 默认 JSON(脚本友好)
secret-broker health
{"status":"ok","version":"4.0.0","uptime":12345}

# 人类友好(TTY 自动启用)
secret-broker services list
🐙 github            GitHub API              healthcheck: ok
🤖 openai            OpenAI API              healthcheck: ok
☁️  aliyun_ecs       阿里云 ECS              healthcheck: degraded
   └─ secret: aliyun.access_key         status: expired
   └─ action: rotate immediately

# 错误:可读 + 结构化
secret-broker proxy github GET /user
ERROR [unauthorized]: mTLS cert required or Bearer token
  → Run: secret-broker login
  → Docs: https://docs.52trz.com/broker/auth
  → Trace ID: abc-123 (show to support)
```

### 7.3 跨平台实现

- **Node 20+**(主)
- 同一份代码 Windows / Linux / macOS
- 路径处理用 `path.join`,UTF-8 编码
- PowerShell 5.1 / pwsh 7+ 双兼容(`bootstrap.ps1`)
- bash 可选(辅助脚本)

---

## 8. MCP Server 设计

### 8.1 完整工具列表

```typescript
// broker/mcp-server.js
const TOOLS = [
  // === Secrets ===
  {
    name: 'list_secrets',
    description: '列出当前 client 可访问的 secret 名字(不返回值)。',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'describe_secret',
    description: '查看 secret 元信息(name/type/desc/last_used),不返回 value。',
    inputSchema: {
      type: 'object',
      properties: { name: { type: 'string' } },
      required: ['name'],
    },
  },

  // === Proxy (主) ===
  {
    name: 'call_service',
    description: '调外部服务(e.g. GitHub)。Agent 拿到响应,不是密钥。',
    inputSchema: {
      type: 'object',
      properties: {
        service: { type: 'string', description: 'github, openai, aliyun_ecs...' },
        method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] },
        path: { type: 'string' },
        query: { type: 'object', additionalProperties: { type: 'string' } },
        body: { type: 'object' },
      },
      required: ['service', 'method', 'path'],
    },
  },

  // === Health / Audit ===
  {
    name: 'get_health',
    description: 'broker 健康度 + uptime。',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'get_audit',
    description: '查询 broker audit log(默认 50 条)。',
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'number', default: 50 },
        since: { type: 'string' },
      },
    },
  },

  // === Healthcheck ===
  {
    name: 'check_credential',
    description: '验单个 secret 凭据是否仍有效。返回 status/detail/latency,不返 value。',
    inputSchema: {
      type: 'object',
      properties: { name: { type: 'string' } },
      required: ['name'],
    },
  },
  {
    name: 'run_healthcheck',
    description: '跑全部 secret 凭据自检。',
    inputSchema: { type: 'object', properties: {} },
  },

  // === Identity (V4 新增) ===
  {
    name: 'list_mfa_factors',
    description: '列出当前 client 的可用 MFA 因子。',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'enroll_webauthn',
    description: '为当前 client 启用 WebAuthn 二验(返回 challenge)。',
    inputSchema: {
      type: 'object',
      properties: { display_name: { type: 'string' } },
    },
  },

  // === Templates (V4 新增) ===
  {
    name: 'list_provider_templates',
    description: '列出 broker 内置的服务商模板。',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'describe_provider_template',
    description: '查看某个模板的详细 schema。',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string' } },
      required: ['id'],
    },
  },
];
```

### 8.2 凭据零接触保证

```javascript
// toolDescribeSecret: 显式 redact 所有可能的 value 字段
async function toolDescribeSecret(args) {
  const r = await callBroker('/api/v1/secrets/resolve', {
    method: 'POST',
    body: JSON.stringify({ name: args.name }),
  });
  if (r.status === 404 || r.status === 403) return { found: false, name: args.name };
  const item = r.json || {};
  return {
    found: true,
    name: item.name,
    type: item.type,
    description: item.description,
    has_value: !!(item.value || (item.fields && Object.keys(item.fields).length > 0)),
    // ⚠️ 不返 value / fields / token / api_key 等任何密钥字段
  };
}
```

### 8.3 MCP 自动注册

```bash
# OpenClaw / Claude Code / Cursor 集成
# 在 ~/.openclaw/skills/ 或 ~/.claude/skills/ 创建

# 1. CLI 形式
claude mcp add broker node /path/to/secret-broker/cli/mcp-server.js \
  --broker https://broker.52trz.com:8443 \
  --master-key-file ~/.broker/master.key

# 2. SSE 形式(远程)
claude mcp add broker-sse https://broker.52trz.com:8443/mcp \
  --header "Authorization: Bearer mb_live_xxx"
```

---

## 9. WebSocket 实时通道

### 9.1 协议

```javascript
// 客户端
const ws = new WebSocket('wss://broker.52trz.com:8443/ws', {
  // mTLS 在 Node 用 https.WebSocket 实现
  cert: fs.readFileSync('client.crt'),
  key: fs.readFileSync('client.key'),
  ca: fs.readFileSync('ca.crt'),
});

ws.on('open', () => {
  // 订阅事件
  ws.send(JSON.stringify({
    action: 'subscribe',
    events: ['audit', 'healthcheck', 'alerts'],
    filter: { cn: 'client.test' },
  }));
});

ws.on('message', (data) => {
  const evt = JSON.parse(data);
  console.log(evt);  // { type: 'audit', ts: '...', data: {...} }
});
```

### 9.2 事件类型

| type | 含义 | 频率 |
|---|---|---|
| `audit` | 新审计事件 | 高(每请求 1) |
| `healthcheck` | 凭据状态变化 | 低(每天) |
| `alert` | 告警(凭据过期/异常) | 低 |
| `secret_rotated` | secret 已轮换 | 低 |
| `mfa_enrolled` | 客户端启用新因子 | 极低 |
| `config_reloaded` | broker.yaml 已 reload | 极低 |

### 9.3 SSE 等价接口

```
GET /api/v1/admin/audit/stream
Accept: text/event-stream

data: {"ts":"2026-09-01T07:06:35Z","action":"proxy","cn":"client.test",...}

data: {"ts":"2026-09-01T07:06:36Z","action":"proxy","cn":"client.test",...}
```

---

## 10. SSH Proxy 模式

### 10.1 设计目标

让 AI / 运维通过 broker 跳板,broker 注入 SSH 凭据,**AI 永远不接触私钥**。

### 10.2 协议

```
用户 → ssh -J broker:7222 user@target-host

1. 用户连 broker:7222(SSH 协议)
2. broker 验证用户身份(mTLS cert)
3. broker 解析 jump target
4. broker 用 ssh_connection secret 自动连 target-host:22
5. broker 中转流量(透明)
6. 目标主机看到 broker IP,不是用户 IP
```

### 10.3 实现

```javascript
// broker/ssh-proxy.js
import { createServer as createSshServer } from 'node:net';
import { Client as SshClient } from 'ssh2';

const server = createSshServer(async (clientSock) => {
  // 1. 接收 SSH 握手
  const ctx = await acceptMtlsContext(clientSock);
  if (!ctx?.client) {
    clientSock.end();
    return;
  }

  // 2. 解析目标(jump_to)
  // 用户 ssh 命令: ssh -J broker user@host
  // → broker 收到 "user@host" 作为 jump target

  // 3. 取 ssh_connection secret
  const secret = await resolveSecret(ctx.client, 'ssh.<target>');
  if (!secret) {
    clientSock.end('Permission denied (no ssh secret)\r\n');
    return;
  }

  // 4. 用 secret 私钥连目标
  const dst = new SshClient();
  dst.on('ready', () => {
    // 5. 中转
    clientSock.pipe(dst).pipe(clientSock);
  });
  dst.connect({
    host: secret.host,
    port: secret.port || 22,
    username: secret.username,
    privateKey: secret.private_key,
    passphrase: secret.passphrase,
  });

  // 6. 审计
  audit({ action: 'ssh_proxy', cn: ctx.cn, target: `${secret.username}@${secret.host}`, status: 'ok' });
});
```

### 10.4 命令代理(高级)

```bash
# AI 想在远程执行命令
secret-broker ssh-exec --target my-server --command "systemctl status nginx"
# broker:
#  1. 解析 target → ssh_connection secret
#  2. SSH 连目标
#  3. exec command
#  4. 返回 stdout
#  5. audit
# AI 看不到 ssh key,只看到结果
```

---

## 11. Workload Identity

### 11.1 场景

K8s / ECS 容器内的应用需要调云 API,无 AK,broker 替取临时凭证。

### 11.2 OIDC 流程

```
Pod                                broker                         云 API
 │                                   │                              │
 │ 1. OIDC token (from K8s SA)       │                              │
 ├──────────────────────────────────>│                              │
 │                                   │ 2. 验证 OIDC token           │
 │                                   │ 3. 调 STS AssumeRole         │
 │                                   ├─────────────────────────────>│
 │                                   │ 4. 临时凭证(1h TTL)         │
 │                                   │<─────────────────────────────┤
 │ 5. broker 缓存 + 转发            │                              │
 │<──────────────────────────────────┤                              │
 │                                   │                              │
 │ 6. 应用调 broker /api/v1/proxy/aws                                │
 ├──────────────────────────────────>│                              │
 │                                   │ 7. 用 STS 临时凭证签名        │
 │                                   ├─────────────────────────────>│
 │                                   │ 8. 转发响应                  │
 │<──────────────────────────────────┤<─────────────────────────────┤
```

### 11.3 配置

```yaml
# broker.yaml
workload_identity:
  providers:
    aliyun:
      type: oidc
      oidc_provider_arn: 'acs:ram::1234:oidc-provider/tyj-cluster'
      role_arns:
        - 'acs:ram::1234:role/tyj-app-role'
      audience: 'broker.52trz.com'

    aws:
      type: oidc
      cluster_oidc_issuer: 'https://oidc.eks.us-east-1.amazonaws.com/id/xxx'
      role_arns:
        - 'arn:aws:iam::1234:role/tyj-app-role'

    gcp:
      type: workload_identity
      project_number: '1234567890'
      pool_id: 'tyj-pool'
      service_account_email: 'tyj-app@tyj-proj.iam.gserviceaccount.com'
```

### 11.4 SDK 使用

```typescript
// 在 Pod 内,无需任何 env var
const broker = new SecretBroker({
  endpoint: 'https://broker.52trz.com:8443',
  workloadIdentity: {
    type: 'k8s',
    serviceAccountTokenPath: '/var/run/secrets/tokens/broker-oidc',
  },
});

// broker 自动:
//  1. 读 SA token
//  2. 调 broker /workload-identity/assume
//  3. broker 验证 + 调 STS 换云临时凭证
//  4. 注入到后续 proxy 调用

await broker.proxy('aws_s3', { method: 'GET', path: '/my-bucket/key' });
// 实际由 broker 用 STS 签名,Pod 0 AK
```

---

## 12. OpenClaw / Claude / Cursor Skill

### 12.1 通用 Skill 模板

```yaml
# skill.yaml (供 OpenClaw 等 AI agent 加载)
name: secret-broker
description: |
  通过 Secret Broker 调外部 API,AI 不接触明文密钥。
  适用:任何需要 GitHub/OpenAI/云 API 调用的场景。
version: 4.0.0

# 默认入口
entry: mcp
mcp:
  command: node
  args: ["/path/to/broker/cli/mcp-server.js"]
  env:
    BROKER_URL: "https://broker.52trz.com:8443"
    MCP_MASTER_KEY_FILE: "~/.broker/master.key"

# 也支持 cli / sdk 入口
cli:
  command: secret-broker

# 提供的工具
tools:
  - list_secrets
  - describe_secret
  - call_service
  - get_health
  - get_audit
  - check_credential
  - run_healthcheck

# 系统提示词(注入到 AI 上下文)
system_prompt: |
  当需要调外部 API(GitHub/OpenAI/阿里云等)时,使用 call_service 工具。
  永远不要尝试用环境变量或 .env 读密钥;用 broker。
  ...
```

### 12.2 Claude Code Skill

```bash
# 安装
claude mcp add broker-sse https://broker.52trz.com:8443/mcp \
  --header "Authorization: Bearer mb_live_xxx"

# 或本地
claude mcp add broker node /path/to/mcp-server.js \
  --env BROKER_URL=https://broker.52trz.com:8443 \
  --env-file ~/.broker/master.key
```

### 12.3 OpenClaw Skill

```bash
# 放 ~/.openclaw/skills/broker/
# → 自动加载
```

### 12.4 Cursor Extension

```bash
# 在 VS Code / Cursor marketplace 上架
# 安装即用,自动检测 ~/.broker/config.json
```

---

## 13. 可观测性集成

### 13.1 Prometheus 指标

```promql
# 请求量
proxy_requests_total{service="github",method="GET",status="200"} 1234

# 延迟
proxy_request_duration_seconds{service="github",quantile="0.5"} 0.123
proxy_request_duration_seconds{service="github",quantile="0.95"} 0.456
proxy_request_duration_seconds{service="github",quantile="0.99"} 0.789

# 凭据状态
secret_healthcheck_status{name="github.pat",status="ok"} 1
secret_healthcheck_status{name="github.pat",status="expired"} 0

# 认证
auth_login_total{role="developer",mfa="totp",status="ok"} 50
auth_login_total{role="developer",mfa="totp",status="denied"} 3

# 限流
rate_limit_exceeded_total{client="client.test",endpoint="/api/v1/proxy/github"} 5

# 错误
proxy_errors_total{service="github",error="upstream_503"} 2
```

### 13.2 OpenTelemetry Trace

```yaml
# broker.yaml
tracing:
  exporter: otlp
  endpoint: 'http://otel-collector:4318/v1/traces'
  service_name: secret-broker
  sample_rate: 0.1  # 10% 采样
```

每个请求的 trace 自动包含:
- broker receive
- auth check
- ACL check
- resolveSecret
- buildUpstreamRequest
- HTTP fetch
- response write

### 13.3 Structured Logging

```json
{
  "ts": "2026-09-01T07:06:35.123Z",
  "level": "info",
  "msg": "proxy request",
  "service": "github",
  "method": "GET",
  "path": "/user",
  "cn": "client.test",
  "fp": "AB:CD:...",
  "upstream_status": 200,
  "latency_ms": 234,
  "trace_id": "abc-123-def"
}
```

### 13.4 Grafana Dashboard JSON

```bash
secret-broker grafana-dashboard > dashboards/broker.json
# → 导入到 Grafana
# → 自动看到 7 个 panel:
#   1. proxy requests/s by service
#   2. latency p50/p95/p99
#   3. error rate
#   4. login success/fail
#   5. secret health
#   6. rate limit hits
#   7. mfa factor usage
```

---

## 14. 测试矩阵

### 14.1 必测

| # | 类别 | 测试 |
|---|---|---|
| 1 | 协议 | OpenAPI schema 验证(每个端点) |
| 2 | 协议 | proxy 8 种 service 都跑通 smoke |
| 3 | 协议 | 错误码符合规范(每类 1+ case) |
| 4 | SDK | Node SDK 100% 端点覆盖 |
| 5 | SDK | Python SDK 100% 端点覆盖 |
| 6 | SDK | Go SDK 100% 端点覆盖 |
| 7 | CLI | 每个 command 跑通 |
| 8 | CLI | --help 正确 |
| 9 | CLI | 错误信息友好 |
| 10 | MCP | 所有 tool 跑通 |
| 11 | MCP | 凭据零接触(redact 100%) |
| 12 | WebSocket | 订阅 + 接收事件 |
| 13 | WebSocket | mTLS 双向认证 |
| 14 | SSH Proxy | 跳板连接 + 命令执行 |
| 15 | SSH Proxy | 私钥零接触 |
| 16 | OIDC | K8s token 验 + STS 换 |
| 17 | OIDC | AWS STS AssumeRole |
| 18 | OIDC | GCP WIF |
| 19 | 幂等 | X-Idempotency-Key 重放返回同一结果 |
| 20 | 流式 | SSE 流式响应正确 |
| 21 | 跨平台 | Windows + Linux + macOS 全过 |
| 22 | 性能 | P95 < 300ms 本地 |
| 23 | 安全 | OWASP Top 10 防护 |
| 24 | 兼容 | v3 client 仍可用 |

### 14.2 性能基准

| 操作 | 目标 |
|---|---|
| proxy (本地,小响应) | P95 < 50ms |
| proxy (跨云,大响应) | P95 < 800ms |
| resolve secret | P95 < 5ms |
| TLS handshake | P95 < 100ms |
| WebSocket 事件延迟 | P95 < 200ms |
| MCP 工具调用 | P95 < 100ms |

---

## 附录 A:curl 完整示例

```bash
# 1. Health
curl -sk https://broker:8443/health

# 2. Identity (mTLS)
curl --cert client.crt --key client.key --cacert ca.crt \
  https://broker:8443/api/v1/identity

# 3. Login (password + TOTP)
curl -sk -c cookies.txt -X POST https://broker:8443/api/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"client":"tyj","password":"mypass"}'
# → 200 { mfa_required: true, mfa_token: "..." }
curl -sk -b cookies.txt -X POST https://broker:8443/api/v1/login/mfa \
  -H 'Content-Type: application/json' \
  -d '{"mfa_token":"...","code":"123456"}'
# → 200 { token: "..." } + Set-Cookie

# 4. Proxy (用 cookie)
curl -sk -b cookies.txt -X POST https://broker:8443/api/v1/proxy/github \
  -H 'Content-Type: application/json' \
  -d '{"method":"GET","path":"/user"}'

# 5. Proxy (用 Bearer)
curl -sk -X POST https://broker:8443/api/v1/proxy/github \
  -H 'Authorization: Bearer mb_live_xxxx' \
  -H 'Content-Type: application/json' \
  -d '{"method":"GET","path":"/user"}'

# 6. Stream (SSE)
curl -sk -N -X POST https://broker:8443/api/v1/proxy/openai \
  -H 'Authorization: Bearer mb_live_xxxx' \
  -H 'Content-Type: application/json' \
  -d '{"method":"POST","path":"/v1/chat/completions","stream":true,"body":{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"hi"}]}}'

# 7. Idempotency
curl -sk -X POST https://broker:8443/api/v1/proxy/github \
  -H 'Authorization: Bearer mb_live_xxxx' \
  -H 'X-Idempotency-Key: abc-123' \
  -H 'Content-Type: application/json' \
  -d '{"method":"POST","path":"/repos","body":{"name":"new-repo","private":true}}'
# 第二次同 key → 返回 cached result
```

---

## 附录 B:Trace 上下文传递

```javascript
// Client 发起
fetch('/api/v1/proxy/github', {
  headers: {
    'Traceparent': '00-{trace_id}-{span_id}-01',
    'X-Broker-Request-Id': 'unique-id',
  },
});

// broker 内部
const traceparent = req.headers['traceparent'];
// 1. 解析 trace_id
// 2. 创建子 span
// 3. 写 audit
// 4. 转发到上游(可选)
fetch(upstream, {
  headers: {
    'Traceparent': outboundTraceparent(traceparent),  // 加 1 跳
  },
});

// AI 拿到响应后,trace_id 仍可关联(在 X-Broker-Trace-Id)
```

---

**作者**:Mavis (AI 架构助手) + 脱永军 (项目所有者)
**最后更新**:2026-09-01
**版本**:V4.0-API-CALLING-STANDARDS
