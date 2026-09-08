# Secret Broker · 安全代理

> **AI 优先的 mTLS 凭据代理,实现零凭据泄漏。**

一个自托管的密钥管理与凭据代理,专为 AI Agent、Kubernetes 工作负载和开发者工作站设计。
凭据用 SOPS 加密存储,通过 mTLS 提供服务,绝不向 AI 暴露原始密钥——只暴露元数据或脱敏占位符。

[![Version](https://img.shields.io/badge/version-v4.1.1-blue)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()
[![Node](https://img.shields.io/badge/node-%E2%89%A520-brightgreen)]()
[![Tests](https://img.shields.io/badge/tests-1100%2B%20passing-brightgreen)]()

> English version: [README.md](README.md)

---

## 问题

AI Agent(LLM、IDE、MCP 客户端)需要 API token、数据库密码、SSH 密钥才能工作——但你不
能信任它们不会把凭据泄漏到日志、对话历史或模型训练数据里。

## 解决方案

**Secret Broker** 就是答案:

* **仅 mTLS** —— 每个请求都用客户端证书认证。绝不允许匿名访问。
* **静态加密** (SOPS) —— 凭据存在 `secrets/broker.yaml` 里,用 age 或 PGP 密钥加密。
* **零凭据泄漏** —— broker、SDK 和审计日志都自动脱敏已知密钥模式(GitHub PAT、OpenAI
  `sk-`、AWS `AKIA`、JWT 等)。每次 commit 都有测试断言这一点。
* **审计日志** —— 仅追加的 JSONL,带防篡改的哈希链。每次 resolve、proxy 和管理操作都被记录。
* **三种使用模式** —— 选最合适的:
  - **Proxy 模式** (推荐给 AI) —— broker 把密钥注入上游请求,AI 永远看不到原始值。
  - **API key** —— 给 AI 客户端的短期 Bearer token;自动撤销。
  - **Resolve 模式** —— 只返回名字,值永远不离开 broker。
* **三个官方 SDK** —— Python、Go、VSCode 扩展。
* **Workload identity** —— K8s/ECS/GKE Pod 用 OIDC 换短期 STS 凭据;磁盘上无长期密钥。

---

## 快速开始

5 分钟跑起你的第一个 broker。

### 1. 安装

```bash
# 克隆
git clone https://github.com/tyj1987/broker.git
cd broker

# 一次性: 初始化 SOPS + age key + PKI
iex (Get-Content .\bootstrap.ps1 -Raw)   # Windows
# 或
./bootstrap.sh                            # Linux/macOS
```

### 2. 启动

```bash
cd broker
node server.js
# 监听 https://127.0.0.1:8443
```

### 3. 签发客户端证书

```powershell
# Windows
.\scripts\broker\issue-client-cert.ps1 -CN client.mylaptop -Role developer
```

```bash
# Linux/macOS
./scripts/broker/issue-client-cert.sh client.mylaptop developer
```

证书由你的本地 CA 签名,打印到 stdout(请保存!)。

### 4. 发起第一次调用

```bash
# mTLS 直连 (最安全)
curl --cert client.mylaptop.crt --key client.mylaptop.key \
     --cacert pki/ca/ca.crt \
     https://127.0.0.1:8443/api/v1/identity
```

完成。完整步骤见 [`docs/QUICKSTART.md`](docs/QUICKSTART.md)。

---

## 架构

```
┌─────────────┐  mTLS   ┌─────────────┐  HTTPS   ┌─────────────┐
│ AI / CLI /  │ ──────▶ │   Nginx     │ ───────▶ │   Broker    │
│ K8s / ECS   │         │  (edge)     │          │ (Node.js)   │
└─────────────┘         └─────────────┘          └──────┬──────┘
                                                        │
                                              ┌─────────┴──────────┐
                                              ▼                    ▼
                                       ┌─────────────┐    ┌────────────────┐
                                       │ SOPS+age    │    │ Upstream APIs  │
                                       │ secrets/    │    │ GitHub/Cloud/  │
                                       │ broker.yaml │    │ SSH/etc        │
                                       └─────────────┘    └────────────────┘
```

* **Broker** (Node.js,单进程) 把密钥放在内存里,从不以明文写磁盘。
  监听 `127.0.0.1:8443`;nginx 在前面做公网 TLS。
* **Nginx** 终结公网 HTTPS,应用 `ssl_verify_client optional`,
  把客户端证书(如果有)作为 `X-SSL-Client-*` header 转给 broker。
* **SOPS** 用 age(或 KMS)在静态加密 `secrets/broker.yaml`。

详见 [`ARCHITECTURE.md`](ARCHITECTURE.md) 深入了解。

---

## 仓库结构

```
.
├── broker/                  # 服务端源码 (Node.js, ES modules)
│   ├── server.js            # 入口 (~3300 行, 100+ 路由)
│   ├── lib/                 # 抽离的 helpers (sops, audit, mtls, …)
│   ├── routes/              # 按资源的 HTTP handlers
│   ├── signing/             # Provider 请求签名器 (Aliyun, AWS, …)
│   ├── dashboard/           # 静态管理 UI
│   └── …
├── sdk/                     # 官方客户端 SDK
│   ├── python/              # Python (零依赖,只用 stdlib)
│   ├── go/                  # Go (只用 stdlib)
│   └── vscode/              # VSCode 扩展 (TypeScript)
├── broker-test/             # 服务端集成测试 (43 个文件, 1100+ 测试)
├── docs/                    # 长篇文档
│   ├── index.md             # MkDocs 着陆页
│   ├── QUICKSTART.md        # 5 分钟教程
│   ├── EXTENDING.md         # 添加新的密钥类型 / 服务模板
│   ├── FAQ.md               # 常见问题
│   ├── SDK-REFERENCE.md     # 3 个 SDK 速查
│   ├── THREAT-MODEL.md      # 安全模型
│   ├── SSH-PROXY.md         # SSH 代理功能
│   ├── WEBSOCKET.md         # WebSocket 事件功能
│   └── WORKLOAD-IDENTITY.md # K8s/ECS/GKE OIDC → STS
├── scripts/                 # 安装 / 部署 / 维护脚本
│   └── broker/              # 核心运维脚本
├── deploy/                  # 部署资源 (helm, terraform, 等)
├── infra/                   # Terraform 模块 (Aliyun + Tencent)
├── pki/                     # PKI 根 CA (仅公钥证书;私钥被 .gitignore 排除)
│   └── ca/ca.crt            # 本地 CA 证书 (提交到 git 方便开发)
├── audit/                   # 运行时审计日志 (JSONL, gitignore)
├── secrets/                 # 运行时密钥 (除 broker.yaml 外都 gitignore)
├── age/                     # age 密钥 (gitignore)
├── .github/                 # GitHub 配置: workflows, issue/PR 模板
├── Dockerfile               # 容器镜像
└── docker-compose.yml       # 本地开发栈
```

---

## API 速览

所有路径都要求 mTLS(或 Bearer API key 给 AI 客户端)。

| Method | Path | 用途 |
|---|---|---|
| GET    | `/health` | 存活检查(无需认证) |
| GET    | `/api/v1/identity` | "我是谁,什么角色" |
| GET    | `/api/v1/services` | 可用的上游服务 |
| GET    | `/api/v1/secrets` | 仅密钥名(永不返回值) |
| POST   | `/api/v1/secrets/resolve` | 获取一个密钥值(admin/有权限者) |
| POST   | `/api/v1/proxy/<service>` | 作为该服务发起上游 API 调用 |
| GET    | `/api/v1/admin/clients` | 列出客户端(admin) |
| POST   | `/api/v1/admin/secrets` | CRUD 密钥(admin) |
| GET    | `/api/v1/admin/audit/verify` | 验证审计日志哈希链 |
| GET    | `/api/v1/healthcheck/status` | 最近一次凭据健康检查 |
| WS     | `/api/v1/ws` | 实时事件流 |

完整参考: [`docs/SDK-REFERENCE.md`](docs/SDK-REFERENCE.md)。

---

## SDKs

```python
# Python (零依赖)
from secret_broker import Client
c = Client.from_env()
me = c.identity()
print(me.role, me.client_name)
```

```go
// Go (零依赖)
import "github.com/tyj1987/broker/sdk/go/broker"
c, _ := broker.NewFromEnv()
me, _ := c.Identity()
fmt.Println(me.Role, me.ClientName)
```

```typescript
// VSCode 扩展
import { SecretBroker } from '@tyj1987/broker-vscode';
const client = SecretBroker.fromEnv();
const me = await client.identity();
```

三者都是**零依赖**(只用 stdlib),不会引入有漏洞的传递依赖。

---

## 安全

* **仅 mTLS** —— 匿名请求在 TLS 层就被 401 拒绝。
* **原始密钥不离开 broker** —— proxy 模式返回带注入凭据的上游响应。
* **审计哈希链** —— 每个事件通过 SHA-256 链接到前一个;篡改可检测。
* **自动脱敏** —— 已知 token 模式(GitHub PAT、OpenAI `sk-`、AWS `AKIA` 等)
  在到达审计日志、错误响应或 dashboard 之前被替换为 `ghp_***` 等。
* **TOTP + 恢复码** 供人工管理员使用。
* **漏洞赏金**: 见 [`SECURITY.md`](SECURITY.md) —— 关键漏洞 $5,000 美元。

威胁模型: [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md)。

---

## 开发

```bash
# 安装
cd broker && npm install

# 运行所有测试 (server + 3 个 SDK 共 1100+)
cd broker && npm run test:verify-all

# 格式化
cd broker && npm run format
cd broker && npm run format:check

# Lint
cd broker && npm run lint
```

详见 [`CONTRIBUTING.md`](CONTRIBUTING.md)。

---

## 部署

* **Docker** — `docker build -t secret-broker . && docker run -p 8443:8443 ...`
* **Docker Compose** — `docker-compose up`
* **Aliyun / Tencent** — 见 `infra/` (Terraform 模块)
* **Helm** — 见 `deploy/helm/broker/`
* **Grafana** — 见 `deploy/grafana/`

完整指南: [`RUNBOOK.md`](RUNBOOK.md) 和 [`deploy/`](deploy/) 下的部署资源
(Helm、Terraform、Grafana)。

---

## 许可证

MIT. 见仓库根目录。

## 支持

* **Issues** —— Bug 报告、功能请求: [GitHub Issues](../../issues)
* **Discussions** —— 问题、想法: [GitHub Discussions](../../discussions)
* **Security** —— 见 [`SECURITY.md`](SECURITY.md)

---

## 致谢

由 Secret Broker 维护者和贡献者精心构建。SOPS+age 栈、nginx mTLS 模式
和零凭据泄漏原则的灵感来自 HashiCorp Vault、BoringSSL 和 Mozilla SOPS 项目。
