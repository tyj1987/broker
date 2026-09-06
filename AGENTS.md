# Secret Broker — AI Agent Onboarding

> **TL;DR**: Secret Broker 是一个 mTLS 反代,把所有外部 API 的凭据 (GitHub PAT / Cloudflare token / 阿里云 AK / SSH 密码) 集中存放在一台受控的 broker 服务上。你 (AI agent) 不应该直接拿到明文凭据,应该调 broker 的 HTTP API,broker 在服务端自动注入凭据并转发请求。明文凭据永远不离开 broker 的内存。

---

## 1. Broker 是什么, 你的角色

**Broker** (`broker.52trz.com`) 是一个 mTLS 双向认证的 HTTPS 服务 (Node.js), 跑在用户的 Aliyun ECS 上 (47.94.225.76:8443, 走 nginx + Cloudflare CDN)。

**你的角色**: 你是一台 AI agent (例如 Mavis、Claude、CI runner), 想替用户调用外部 API (GitHub、Cloudflare、阿里云 ECS / DNS、OpenAI 等)。但你**不应该**直接拿到 PAT / token / access key 这些明文凭据 — 泄露风险太高。

**正确姿势**:
- 你只调 broker 的两个 HTTP endpoint
- broker 在服务端自动注入凭据, 转发到上游 API, 把响应 (不含明文凭据) 返给你
- 凭据 (secrets) 永远只在 broker 内存中, **不出现在你的 context**

---

## 2. Broker 端点 — 你只需要知道 2 个

### 2.1 `POST /api/v1/secrets/resolve` — 拿明文 (admin only, 不推荐)

```bash
curl --cert client.crt --key client.key https://broker.52trz.com:8443/api/v1/secrets/resolve \
  -X POST -H 'Content-Type: application/json' \
  -d '{"name":"GITHUB_PAT","field":"token"}'
```

**响应** (admin 才允许):
```json
{"name":"GITHUB_PAT","field":"token","value":"ghp_REPLACE_WITH_REAL_PAT","type":"github_pat"}
```

⚠️ **这条路径会把明文返给你** — 审计日志会记录每一次调用, 任何把 secret 写进对话/日志/截图的行为都是 leak。仅在调试时使用, 生产请走下面 2.2 的 proxy。

### 2.2 `POST /api/v1/proxy/:service` — **推荐, 这是你 99% 时间该用的**

```bash
curl --cert client.crt --key client.key https://broker.52trz.com:8443/api/v1/proxy/github \
  -X POST -H 'Content-Type: application/json' \
  -d '{"method":"GET","path":"/user/repos","query":{"visibility":"all"},"headers":{}}'
```

**broker 自动**:
1. 查 `:service` 的 config, 找到 `token_secret` 字段
2. 拿 secret 内存里**明文**值 (不返你)
3. 注入对应 Authorization header (Bearer / GitHub-Token-Generic / aliyun v2 signature)
4. 转发到 upstream URL
5. 把上游响应**直接**返你 (HTML / JSON / 文本)

**你看到的是**: 上游 API 的响应, 像你**直接**调上游一样。但你**从未看到** PAT / token / access key 的明文。

**调用规范**:
- `method`: GET / POST / PUT / PATCH / DELETE
- `path`: URL path 部分, 会拼到 service 的 `upstream` URL 后面
- `query` (可选): URL query params (object)
- `headers` (可选): 额外 HTTP header (object)
- `body` (可选): request body (string, 不会自动 stringify)

---

## 3. 认证 — 你怎么 "证明" 你能用 broker

broker 支持 2 种 auth, 你用哪种取决于 client 端:

### 3.1 mTLS client cert (推荐 for AI agents / CLI / scripts)

broker 端在 `/opt/secret-broker/pki/clients/<client-name>.{crt,key}` 有 client certs。你的 client 名 + cert 是一对一, broker 知道每个 cert 对应哪个 client 配置 (role, allowed_resolve, allowed_proxy 白名单)。

**怎么 import cert**:
```bash
# 在 broker 端 (admin): 生成新 client + cert
ssh root@52trz.com
bash /opt/secret-broker/scripts/issue-client-cert.sh client.my-ai-agent
# 产物 (写到 /opt/secret-broker/pki/clients/):
#   client.my-ai-agent.crt
#   client.my-ai-agent.key  (SECRET, 不要发到 chat)
#   client.my-ai-agent.fp   (fingerprint, 写到 broker.yaml)
```

把 .crt + .key 拿到你的设备 (scp / secure file transfer)。然后:
```bash
# curl
curl --cert client.crt --key client.key https://broker.52trz.com:8443/api/v1/me

# Python requests
import requests
requests.get(url, cert=('client.crt', 'client.key'), verify='ca.crt')

# Node.js undici
import { Agent, fetch } from 'undici'
fetch(url, { dispatcher: new Agent({ cert, key, ca }) })
```

### 3.2 password + 2FA (for 浏览器 / dashboard UI)

仅 dashboard 用。AI agent 不应该用这个 (脚本里 mTLS 更稳)。

```
URL:      https://broker.52trz.com/  (走 Cloudflare, 不需要 :8443)
Client:   client.dashboard-admin (admin role, full access)
Password: [REMOVED — suspected exposed credential; rotate before any production use]
2FA:      Authenticator App 6 位 TOTP (或 10 个恢复码)
```

---

## 4. 你能调哪些 service

broker 当前配了 **4 个 service** (broker.yaml 的 `services:` 块):

| Service name | Type | 上游 | 凭据 |
|---|---|---|---|
| `github` | `github_token` | `https://api.github.com` | `GITHUB_PAT` (类型 github_pat) |
| `cloudflare` | `bearer` | `https://api.cloudflare.com/client/v4` | `cloudflare` (类型 cloudflare_token) |
| `aliyun_ecs` | `aliyun_v2` | `https://ecs.aliyuncs.com` | `ALIYUN_ACCESS_KEY` (类型 aliyun_ak) |
| `alidns` | `aliyun_v2` | `https://alidns.aliyuncs.com` | `ALIYUN_ACCESS_KEY` (类型 aliyun_ak) |

要加新 service (例如 openai), admin 在 dashboard 走 "服务管理" tab, 或 curl 调 admin API。

---

## 5. 完整工作流示例

### 5.1 列出你 GitHub 仓库 (走 broker)

```bash
# user 给你: client.crt + client.key
# 你要做: 列 user 自己的 repos
curl --cert client.crt --key client.key https://broker.52trz.com:8443/api/v1/proxy/github \
  -X POST -H 'Content-Type: application/json' \
  -d '{"method":"GET","path":"/user/repos","query":{"per_page":30}}'
```

broker 自动加 `Authorization: token ghp_xxx` header, 转发到 `https://api.github.com/user/repos`, 返你 JSON。

### 5.2 查阿里云 ECS 实例

```bash
curl --cert client.crt --key client.key https://broker.52trz.com:8443/api/v1/proxy/aliyun_ecs \
  -X POST -H 'Content-Type: application/json' \
  -d '{"method":"GET","path":"/","query":{"Action":"DescribeInstances","Version":"2014-05-26","RegionId":"cn-hangzhou"}}'
```

broker 自动用 ALIYUN_ACCESS_KEY 算 v2 signature, 转发到 ECS API, 返响应。

### 5.3 拿明文 secret (调试时, 谨慎)

```bash
curl --cert client.crt --key client.key https://broker.52trz.com:8443/api/v1/secrets/resolve \
  -X POST -H 'Content-Type: application/json' \
  -d '{"name":"IBMC","field":"host"}'
# 返: {"name":"IBMC","field":"host","value":"192.168.2.100","type":"ssh_connection"}
```

⚠️ 响应里有明文 — 截图 / 写日志 = 泄露。

---

## 6. 你的 client 配置 (role + 白名单)

broker.yaml 的 `clients.<name>` 决定你能做什么:

```yaml
clients:
  client.my-ai-agent:
    role: developer          # admin / developer / readonly
    allow_password_login: false   # 强制 mTLS only (推荐 for AI agents)
    allowed_resolve:         # 哪些 secret 你能 resolve (admin 例外)
      - GITHUB_PAT
    allowed_proxy:           # 哪些 service 你能 proxy
      - service: github
        paths: ["^/.*"]      # regex, 哪些 URL path 允许
        methods: [GET, POST]
    rate_limit: 1000/hour    # admin 无限制
```

如果 broker 返 `403 Service github not allowed for your client` 或 `403 Path not allowed`, 那是你 client 没在 `allowed_proxy` 白名单里。需要 admin 改 broker.yaml。

---

## 7. ⚠️ 关键 invariant (做之前先读)

1. **明文凭据永远不离开 broker** — 截图 broker 响应、log broker 响应、写 broker 响应到 chat = **泄露 secrets**。broker 自己的代码也是 redact 过的 (lib/redact.js), 但 agent 不会自动 redact。
2. **使用 broker 不要绕过** — 即使你可以调 2.1 `resolve` 拿明文, 也**永远**优先用 2.2 `proxy` 模式。proxy 模式 broker 自动注入, 你 context 永远只有响应, 没有凭据。
3. **审计**: 你每次调 broker 都写 audit log, 包括 client name + 调用 endpoint + 响应大小。User 随时能查谁什么时候调了什么。
4. **rate limit**: 非 admin client 有 rate limit (e.g. 1000/hour), 超过返 429。要重任务请 admin 调高。
5. **不要 chmod 600 mTLS key 然后粘贴到 chat** — 这是 secret, 用 secure file transfer 拿。
6. **client cert 跟 CN 匹配** — 你 cert 的 CN (`X509 subject CN=`) 必须 = broker.yaml 的 client name (`<CN>.crt` 文件名前缀), 否则 broker 401。

---

## 8. 失败模式 / 故障排查

| 错 | 原因 | 修法 |
|---|---|---|
| `curl: (58) SSL cert problem` | 系统 trust store 不认 broker server cert | 加 `--cacert ca.crt` 或 `-k` skip server verify (你 verify 的是 client cert, 不是 server cert) |
| `mTLS handshake: certificate verify failed (unauthorized)` | broker 不认你的 client cert | 1) cert 跟 broker.yaml 里 `cert_fingerprint_sha256` 不匹配; 2) cert 过期; 3) cert 由陌生 CA 签发。让 admin `issue-client-cert.sh` 重发 |
| `403 Service github not allowed` | 你的 client `allowed_proxy` 没列 github | 让 admin 改 broker.yaml 加白名单 |
| `401 Bad password` | password 错 (5 次失败锁 15 分钟) | 等解锁, 或用 mTLS |
| `400 Missing {password}` (login) | TOTP 启了后 password 登录拿 mfa_required | 输 6 位 TOTP 走 mfa 流程 |
| `500 Internal error` (proxy) | broker 调上游失败 (aliyun v2 signature 错、cloudflare token 过期、github 401) | broker 返的 error 里有 `upstream_status`, 看那个 |
| `502 Bad Gateway` (proxy) | broker 连不上上游 (network / DNS) | check upstream URL, 是不是 CF 改过路径 |
| `503 secret expired` (proxy) | secret health check 失败 (V3 时代 placeholder, real token 过期) | 让 admin dashboard rotate secret |

---

## 9. 你的 onboarding checklist (从零开始)

当 user 跟你说 "用 broker 调 XXX API" 时, 确认你手上有:

- [ ] **broker URL**: `https://broker.52trz.com:8443` (mTLS 直连) 或 `https://broker.52trz.com` (走 CF, 不支持 mTLS)
- [ ] **client cert + key** (`.crt` + `.key` 文件, mTLS 路径下)
- [ ] **CA cert** (`ca.crt`, 用于 verify broker server cert)
- [ ] **你的 client name** (cert 的 CN, e.g. `client.mavis`)
- [ ] **broker.yaml 里你的 client 配置** (role + allowed_resolve + allowed_proxy)
- [ ] **(可选) Secret 名字** 你能 resolve (e.g. `GITHUB_PAT`, `IBMC`, `cloudflare`, `ALIYUN_ACCESS_KEY`)
- [ ] **(可选) Service 名字** 你能 proxy (e.g. `github`, `openai`, `cloudflare`, `aliyun_ecs`, `alidns`)

如果 user 没给齐, 直接问, 不要假设。**永远不要**让 user 把 mTLS key 贴到 chat, 让他用 scp / secure file transfer。

---

## 10. 一页 cheat sheet (复制保存)

```bash
# 你能调: 列你的 client 资料 (verify cert + role + fp)
curl --cert client.crt --key client.key https://broker.52trz.com:8443/api/v1/me

# 你能调: 走 broker 调上游 API (推荐, secrets 不外泄)
curl --cert client.crt --key client.key https://broker.52trz.com:8443/api/v1/proxy/<service> \
  -X POST -H 'Content-Type: application/json' \
  -d '{"method":"<METHOD>","path":"<PATH>","query":{...},"headers":{...},"body":"..."}'

# 你能调: 拿明文 secret (admin only, 慎用)
curl --cert client.crt --key client.key https://broker.52trz.com:8443/api/v1/secrets/resolve \
  -X POST -H 'Content-Type: application/json' \
  -d '{"name":"<SECRET_NAME>","field":"<FIELD>"}'
```

**记住**:
- 你**永远不**直接拿 secret 明文
- 你**永远不**绕过 broker 调上游 (那样你得自己 manage secret, 失去 broker 价值)
- 任何凭据请求, 第一反应: "走 broker"
- broker 出问题: 报 user, **不**让 user 把 secret paste 出来

---

## 11. 设备 / Client 模型 — 什么时候需要新设备, 新设备长什么样

### 11.1 什么情况下需要新设备 (新 client)

`broker.yaml` 的 `clients.<name>` 一行 = 一个 broker 视角的 "设备" (client)。在以下场景需要新增:

| 场景 | 原因 |
|---|---|
| 引入一台新的 AI agent / CLI tool | 隔离身份 + 审计独立 |
| 一台物理机/VM 上跑多个独立 agent (e.g. Mavis + Claude + CI runner) | 每 agent 独立 cert, 一方泄露不影响其他 |
| agent 切角色 (e.g. developer → admin) | 角色提升需要新 client + 显式 allow_password_login |
| 老的 cert 泄露 / 设备报废 | revoke 旧 client + 重新 issue, 不影响其他 client |
| 不同网络段 / IP allowlist | broker 支持 per-client IP allowlist |
| 不同业务场景 (read-only vs developer vs admin) | 最小权限原则, 不同 client 配不同 allowed_proxy |

反例 (不需要新设备):
- 同一 agent 多次重启 → 复用同一 cert (broker 看 fingerprint + role, 跟 session 无关)
- 同一 agent 在 2 台物理机跑 → **需要** 2 个 cert (PKI 原则: 1 cert = 1 身份, 不跨设备)
- 只改 password → 改 `password` 字段, 不用新建 client

### 11.2 新设备的典型存在形式

broker 的 "client" 是**逻辑身份**, 不是物理设备。一张 cert 可以装在多种介质上:

| 存在形式 | 典型场景 | 怎么装 |
|---|---|---|
| **云端 agent 容器** | mavis 跑在 Windows host 调 broker | 装到系统 trust store (Windows: certlm.msc) 或 app trust dir |
| **CI runner** | GitHub Actions self-hosted runner 调 broker | 装到 runner host + 环境变量指向 cert 路径 |
| **本地 CLI 工具** | 用户本地 Python 脚本 / Node CLI | 装到项目 `.secrets/` dir (加 gitignore) |
| **浏览器 (PKCS#12)** | 用户通过 dashboard 操作 | Chrome: Settings → Manage certificates → Import |
| **嵌入式 / 边缘设备** | 路由器、IoT 设备、CI 工控机 | 装到设备 trust store, 走 system 服务 |
| **临时 / ephemeral** | AWS Lambda / Cloudflare Worker 一次性执行 | cert 存 KMS / Secrets Manager, runtime 拉 |

每种形式**底层都是同一张 .crt + .key**,只是**装载方式**不同。

### 11.3 与"实体设备"的关系 (重要!)

**broker client ≠ 物理机**。常见混淆:

| 误解 | 真相 |
|---|---|
| "1 台物理机 = 1 个 client" | **错**。1 台物理机可以跑 N 个 agent, 每个 agent 应该有独立 client (最小权限) |
| "1 个 client = 1 台物理机" | **错**。1 个 client cert 可以装在 N 台物理机 (只要都信这个身份) |
| "agent 重启了需要新 client" | **错**。cert 是身份, 不是 session; 重启不换 cert |
| "物理机换了需要新 client" | **看情况**。同一 agent 换物理机 → 复用 cert (拷过去)。新 agent 上物理机 → 新 cert |

**最佳实践**:
- **1 agent 进程 = 1 cert** (隔离)
- **1 物理机可以跑 N 个 agent** (N 张 cert)
- **cert 跟着 agent 走, 不跟着物理机走** (物理机是介质, cert 是身份)
- **agent 报废 → 立即 revoke 它的 cert** (不要让旧 cert 漂在物理机磁盘上)

### 11.4 cert 能不能复用到其他 AI?

**绝对不能**。原因:

1. **PKI 设计原则**: 1 cert = 1 身份。多个 AI 用同一 cert = 多个 AI 共享同一身份, 审计 log 没法区分谁干的, 撤销也只能一锅端。
2. **安全**: 任何 AI 拿到 cert 就能伪装其他 AI 调 broker。cert 泄露 = 所有用同一 cert 的 AI 全被冒充。
3. **broker 设计**: broker.yaml `clients.<name>.cert_fingerprint_sha256` 是 1:1 配对, 多个 AI 用同一 cert 只能配一个 client name, 后面要分开就乱。

**cert 是身份, 不能 share, 跟 SSH key 一样**。

但 **client config 模板** 可以共享:

| 字段 | 能复用? | 说明 |
|---|---|---|
| `cert_fingerprint_sha256` | ❌ 绝对不能 | 1 cert = 1 fingerprint |
| `password` (mTLS 不需要) | ❌ | 每个 client 独立 hash |
| `role` | ✅ 模板 | "所有 dev agent 都用 developer role" 可以批量复制 |
| `allowed_resolve` | ✅ 模板 | "所有 dev agent 都能 resolve GITHUB_PAT" 模板 |
| `allowed_proxy` | ✅ 模板 | 同上 |
| `rate_limit` | ✅ 模板 | "所有 dev agent 1000/hour" 模板 |
| `description` | ✅ | 描述 agent 用途 |
| `allow_password_login` | ✅ 模板 | "AI agent 全 false, dashboard admin true" |

**复用模板 = 共享 client config (role / 权限 / rate limit) 但生成独立 cert + fingerprint**。

### 11.5 cert 生命周期

```
[Admin: bash issue-client-cert.sh client.X]
  ↓ 生成 2048-bit RSA keypair, sign with broker CA, 365d validity
  ↓ 写 pki/clients/client.X.{crt,key,fp}, 更新 broker.yaml fingerprint
  ↓ reload broker (or restart)
[Cert 装到 AI 设备 (out-of-band, scp / secure file transfer)]
  ↓ AI 用 cert 调 broker /api/v1/proxy/:service /api/v1/secrets/resolve
[Cert 过期 / 设备报废 / 泄露]
  ↓ Admin: rotate (POST /admin/clients/X/rotate 或 scripts/issue-client-cert.sh X --rotate)
  ↓ 新 cert 装到 AI 设备, 旧 cert revoke (broker.yaml fingerprint 替换)
[Cert 永久报废]
  ↓ Admin: delete client (POST /admin/clients/X DELETE) → 删 pki 文件 + broker.yaml entry
```

### 11.6 6 条原则

1. **1 agent = 1 cert** (永远)
2. **cert 跟 agent 走, 不跟物理机走** (迁移 agent 拷 cert, 换物理机 agent 不要重发 cert)
3. **template 共享, cert 独立** (role / allowed_* 复制, fingerprint 每个 client 唯一)
4. **泄露立即 revoke** (broker.yaml 删 fingerprint + 重 issue, 旧 cert 5 分钟内失效)
5. **物理机 0 → 1 + cert 跟着搬运** (而不是 cert 跟物理机共存亡)
6. **永远不用 chat / email / git 传 cert** (用 scp / secret manager / 加密 USB)
