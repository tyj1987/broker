# sops-age-template / SOPS+age 密钥模板

> **v4 设计完成(2026-09-01)**：把 v3.8 (mTLS + TOTP + SOPS) 升级为 **AI-First 凭据管理平台**。
> 6 种认证因子 / 40+ 服务商模板 / 8 种调用入口 / 100% OpenAPI / 零信任 + 自动 rotate。
>
> 📘 **V4 设计文档树**:
> - [Master Plan](docs/DESIGN-V4-MASTER-PLAN.md) · [Quickstart](docs/QUICKSTART.md) (5 分钟)
> - [身份认证 + MFA](docs/DESIGN-V4-IDENTITY-MFA.md) · [服务商模板](docs/DESIGN-V4-PROVIDER-TEMPLATES.md)
> - [API 调用规范](docs/DESIGN-V4-API-CALLING-STANDARDS.md) · [安全模型](docs/DESIGN-V4-SECURITY-MODEL.md)
> - [实施路线图](docs/DESIGN-V4-ROADMAP.md) (6 个月,3 阶段)

> **v2.0 起 Secret Broker**：把"AI 安全使用密钥"变成"AI 不接触密钥"。
> AI 客户端通过 mTLS HTTPS 调用 broker，让 broker 替它调 GitHub / 阿里云 / 腾讯云 / SSH，
> 明文密钥永远只在 broker 内存里。

> **System docs / 系统文档**: `C:\home\dev-system\README.md`
> **架构详解 / Architecture deep-dive**: [`docs/04-secret-broker.md`](../dev-system/04-secret-broker.md)

A production-grade template that combines **SOPS+age secret management** with a
**Secret Broker** (mTLS HTTPS credential proxy). Deploy to **Aliyun + Tencent**,
push to **dual container registries**, ship via **GitHub Actions**.

生产级模板：把 **SOPS+age 静态密钥管理** 升级为 **Secret Broker 动态凭据代理**。
双云（阿里云 + 腾讯云）部署、双 registry 推送、GitHub Actions 全自动。

---

## ✨ What you get / 能力清单

### 核心：Secret Broker（v2.0）

- **mTLS 双向认证** — 每台设备一张客户端证书，丢失可秒吊销
- **代理模式（AI 推荐）** — AI 调外部 API 时，明文密钥永远不离开 broker 内存
- **SOPS 加密存储** — 复用上一代 SOPS+age 体系，不引入新依赖
- **全量审计** — JSON Lines 日志记录每个 resolve/proxy/rotate 调用
- **策略引擎** — 客户端按 cert fingerprint 细粒度白名单
- **轻量 Dashboard** — 浏览可见密钥、查审计、触发 rotate

### 三种使用模式

| 模式 | 命令 | AI 接触明文? |
|---|---|---|
| **Proxy**（推荐） | `secret-broker proxy github GET /repos/x/y` | ❌ |
| **Exec** | `secret-broker exec --env "GH_TOKEN" -- git push` | ❌ |
| **Get** | `secret-broker get github.pat` | ⚠️ 白名单 |

### 基础设施（沿用 v1.x）

- **多云** — Aliyun ECS + Tencent CVM 镜像双活（broker 主备）
- **零明文** — GitHub Secrets 全部通过 OIDC 临时令牌
- **多钥匙冗余** — 主 age key + 备份 key，SOPS 双重加密
- **本地一键** — `bootstrap.ps1` idempotent 引导
- **完整 CI** — gitleaks 扫密 + Node test + Terraform validate + Docker build

---

## 🚀 Quick start / 快速上手

### 1. 在 broker 服务器（云端）引导

```powershell
# 一次性：克隆仓库
git clone https://github.com/tyj1987/sops-age-template.git C:\home\broker-server
cd C:\home\broker-server

# 引导 SOPS+age
iex (Get-Content .\bootstrap.ps1 -Raw)

# 初始化 PKI
.\scripts\broker\init-ca.ps1
.\scripts\broker\issue-server-cert.ps1 -Domain broker.yourdomain.com -AltNames "localhost,127.0.0.1"
.\scripts\broker\issue-client-cert.ps1 -CN client.tyj-laptop -Role developer -RegisterToConfig

# 准备 SOPS 加密的密钥
notepad .\secrets\common.env        # 写明文
sops --encrypt --in-place .\secrets\common.env
Copy-Item .\secrets\broker.yaml.example .\secrets\broker.yaml
notepad .\secrets\broker.yaml        # 配置 services 和 clients
sops --encrypt --in-place .\secrets\broker.yaml

# 启动
docker compose up -d broker
```

### 2. 在 AI 客户端（你的笔记本）使用

```powershell
# 把客户端证书从 broker 服务器 scp 过来
scp broker:~/pki/clients/client.laptop.{crt,key} C:\Users\User\.broker\
scp broker:~/pki/ca/ca.crt C:\Users\User\.broker\

# 写客户端配置
@"
{
  "endpoint": "https://broker.yourdomain.com:8443",
  "client_cert": "C:\\Users\\User\\.broker\\client.laptop.crt",
  "client_key":  "C:\\Users\\User\\.broker\\client.laptop.key",
  "ca_cert":     "C:\\Users\\User\\.broker\\ca.crt"
}
"@ | Out-File C:\Users\User\.broker\config.json -Encoding UTF8

# 健康检查
node C:\path\to\cli\secret-broker.js health
# { "status": "ok", "sops_loaded": true, ... }

# AI 调用 GitHub（AI 看不到 PAT）
node secret-broker.js proxy github GET /repos/tyj1987/sops-age-template

# AI 执行 git push（密钥注入子进程，子进程结束即丢）
node secret-broker.js exec --env "GH_TOKEN" -- git push origin main
```

### 3. Dashboard

浏览器打开 `https://broker.yourdomain.com:8443/`（同样需要 mTLS 客户端证书）。
在浏览器里把 `client.laptop.crt` 导入浏览器证书库即可。

---

## 🏗️ Architecture / 架构

```
┌─────────────────────────────────────────────────────┐
│ Aliyun ECS / Tencent CVM (2C2G, ¥50/月)            │
│                                                     │
│  ┌──────────────────────────────────────────┐      │
│  │ Docker                                    │      │
│  │  ┌─────────────────────────────────────┐ │      │
│  │  │ secret-broker (Node 20, mTLS HTTPS) │ │      │
│  │  │  :8443                               │ │      │
│  │  │                                     │ │      │
│  │  │  /health, /api/v1/identity          │ │      │
│  │  │  /api/v1/secrets (list+resolve)     │ │      │
│  │  │  /api/v1/proxy/:service  🛡️         │ │      │
│  │  │  /api/v1/audit, /api/v1/rotate      │ │      │
│  │  │  /  (static dashboard)              │ │      │
│  │  └─────────────────────────────────────┘ │      │
│  │                                            │      │
│  │  /opt/broker/data/                         │      │
│  │    ├── secrets/  (SOPS encrypted)          │      │
│  │    ├── pki/      (CA + server + clients)   │      │
│  │    ├── age/      (age private key)          │      │
│  │    └── audit/    (JSON Lines)              │      │
│  └──────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────┘
         ▲
         │  mTLS (client cert + key)
         │
   ┌─────┴──────┬──────────┬──────────┐
   │            │          │          │
你的笔记本    家里台式机   CI runner   手机 SSH

# 数据流 / Data flow:
# AI 客户端 → POST /api/v1/proxy/github → broker 解密 PAT
# → 注入 Authorization 头 → 转发 api.github.com
# → 返回响应 → 写 audit.jsonl → AI 收到响应（无 PAT）
```

详细架构、API 协议、策略引擎、PKI 设计见 [`docs/04-secret-broker.md`](../dev-system/04-secret-broker.md)。

---

## 📂 Repository layout / 仓库结构

```
sops-age-template/
├── broker/                          # 🆕 Secret Broker 服务端
│   ├── server.js                    # mTLS HTTPS + 路由 + 代理
│   ├── package.json
│   ├── Dockerfile
│   └── dashboard/                   # 静态 Dashboard
│       ├── index.html
│       ├── app.js
│       └── style.css
├── cli/                             # 🆕 客户端 CLI
│   ├── secret-broker.js             # proxy / exec / get / pki
│   └── package.json
├── pki/                             # 🆕 PKI（CA + 证书，gitignore）
│   ├── ca/  server/  clients/
├── age/                             # 🆕 age 私钥（gitignore）
├── audit/                           # 🆕 审计日志（gitignore）
├── secrets/
│   ├── common.env                   # SOPS 加密的明文密钥
│   ├── common.env.example
│   ├── broker.yaml.example          # 🆕 broker 配置模板
│   └── common.yaml.example
├── scripts/
│   ├── check-tools.ps1
│   ├── backup-keys.ps1
│   ├── rotate-keys.ps1
│   ├── install-direnv-hook.ps1
│   └── broker/                      # 🆕 PKI 工具
│       ├── init-ca.ps1
│       ├── issue-server-cert.ps1
│       ├── issue-client-cert.ps1
│       └── revoke-cert.ps1
├── app/                             # 上一代 demo app
│   ├── index.js
│   └── package.json
├── infra/
│   ├── aliyun/
│   │   ├── main.tf                  # demo app (ACK)
│   │   ├── broker.tf                # 🆕 broker ECS
│   │   ├── broker-variables.tf
│   │   ├── cloud-init.sh
│   │   └── app.yaml
│   └── tencent/
│       ├── main.tf                  # demo app (TKE)
│       ├── broker.tf                # 🆕 broker CVM
│       ├── broker-variables.tf
│       └── app.yaml
├── monitoring/
│   ├── prometheus.yml
│   └── uptime-kuma.yml
├── .github/workflows/
│   ├── ci.yml                       # 🆕 broker-test + image-build
│   └── deploy.yml                   # 🆕 推送双云 + 双 Terraform apply
├── docker-compose.yml               # 🆕 broker 主 + 可选 app
├── Dockerfile                       # demo app
├── bootstrap.ps1
├── .sops.yaml
├── .envrc
└── README.md (本文件)
```

---

## 🛠️ Development / 开发

### 本地跑 broker（端到端测试）

```powershell
# 1. 准备 PKI（一次性）
.\scripts\broker\init-ca.ps1
.\scripts\broker\issue-server-cert.ps1 -Domain localhost -AltNames "localhost,127.0.0.1"
.\scripts\broker\issue-client-cert.ps1 -CN client.test -Role developer

# 2. 准备密钥
$env:SOPS_AGE_KEY_FILE = "C:\Users\User\.config\sops\age\key.txt"
"test-secret-123" | sops --encrypt --input-type plaintext --output-type dotenv /dev/stdin | Out-File secrets\test.env
# 或用现有 common.env

# 3. 写 broker.yaml
@"
services:
  github:
    type: github_token
    token_secret: github.pat
    upstream: https://api.github.com
clients:
  client.test:
    cert_fingerprint_sha256: "<填 issue-client-cert.ps1 输出的指纹>"
    role: developer
    allowed_proxy:
      - service: github
        paths: [".*"]
"@ | Out-File secrets\broker.yaml -Encoding UTF8
sops --encrypt --in-place secrets\broker.yaml

# 4. 启动
docker compose up -d broker

# 5. 测试
node cli\secret-broker.js health
node cli\secret-broker.js proxy github GET /
```

### Taskfile 任务

```powershell
task --list
# 上一代 app:
#   task dev          - 解密 secrets + 启动 docker compose
#   task decrypt      - sops 解密到 .env
#   task encrypt      - sops 加密 .env -> secrets/
#   task backup-keys  - 备份 age 私钥到加密 zip
#   task rotate-keys  - 轮转 age 私钥并重加密所有 secrets
# broker 相关:
#   task broker:init-ca           - 初始化根 CA
#   task broker:issue-server      - 签发服务端证书
#   task broker:issue-client CN=x - 签发客户端证书
#   task broker:revoke FP=xx      - 吊销证书
#   task broker:up                - docker compose up broker
#   task broker:logs              - 看 broker 日志
#   task broker:audit             - 看审计日志
```

---

## 🚢 Deploy / 部署

### 双云（阿里云主 + 腾讯云备）

```bash
# 1. 配置 GitHub repo secrets
#    ALIYUN_OIDC_PROVIDER_ARN, ALIYUN_OIDC_ROLE_ARN
#    ALIYUN_ACR_USERNAME, ALIYUN_ACR_PASSWORD
#    TENCENTCLOUD_SECRET_ID, TENCENTCLOUD_SECRET_KEY
#    TENCENT_TCR_USERNAME, TENCENT_TCR_PASSWORD

# 2. 推 tag 触发自动部署
git tag v2.0.0
git push origin v2.0.0

# 3. GitHub Actions 自动：
#    - build broker 镜像
#    - push 到 registry.cn-hangzhou.aliyuncs.com/tyj1987/sops-age-template-broker
#    - push 到 ccr.ccs.tencentyun.com/tyj1987/sops-age-template-broker
#    - terraform apply aliyun/broker.tf  (主 broker)
#    - terraform apply tencent/broker.tf (备 broker)
```

### Failover

阿里云 broker 挂时：
```powershell
# 在腾讯云 ECS 上
ssh ubuntu@<tencent-broker-ip>
cd /opt/secret-broker
# 同步主 broker 的状态
rsync -avz root@<aliyun-broker>:/opt/secret-broker/{secrets,pki,age,audit} ./
docker compose up -d broker

# DNS 切换: broker.yourdomain.com -> <tencent-broker-ip>
```

---

## 🔒 Security model / 安全模型

**绝对不能违反的规则** / Hard rules:

1. **AI 永远不接触明文密钥** — 默认 proxy 模式，exec 模式密钥只活子进程内
2. **客户端证书是设备绑定的** — 丢失笔记本立刻 `secret-broker pki revoke`
3. **CA 私钥不出 broker 服务器** — `pki/ca/ca.key` 严禁 scp
4. **age 私钥不能进 git** — 已加 `.gitignore`，如发现泄漏立即 rotate
5. **每个客户端有显式 ACL** — 不在 `clients:` 段里的 cert 全部 403

### 审计

```powershell
# 看最近 100 条审计
node cli\secret-broker.js health
# 直接看 broker 的 audit 目录（在服务器上）
Get-Content audit\audit-2026-08-12.jsonl | Select-Object -Last 20
```

每条事件格式：
```json
{
  "ts": "2026-08-12T13:45:23.123Z",
  "id": "uuid",
  "action": "proxy",
  "cn": "client.tyj-laptop",
  "fp": "AB:CD:...",
  "service": "github",
  "method": "GET",
  "path": "/repos/tyj1987/x",
  "upstream_status": 200,
  "latency_ms": 234,
  "status": "ok"
}
```

---

## 📚 Docs / 文档

- [系统方案 README](../dev-system/README.md) - 全套设计文档索引
- [01-secret-management.md](../dev-system/01-secret-management.md) - SOPS+age 详解
- [02-full-architecture.md](../dev-system/02-full-architecture.md) - 完整架构
- [03-implementation-roadmap.md](../dev-system/03-implementation-roadmap.md) - 实施路线图
- [04-secret-broker.md](../dev-system/04-secret-broker.md) - 🆕 Secret Broker 架构详解
- [RUNBOOK.md](./RUNBOOK.md) - 运维手册

---

## 📝 License

MIT
