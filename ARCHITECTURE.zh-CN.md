# Secret Broker · 架构

> 一页式 V4.1.1 架构总览。深入细节见 `docs/THREAT-MODEL.md` 及相关 spec 文档。
> 运行时运维见 `RUNBOOK.md`。
>
> English version: [ARCHITECTURE.md](ARCHITECTURE.md)

## 鸟瞰图

```
                ┌──────────────────────────────────────────────────────────┐
                │                       AI 客户端                           │
                │  (Claude / Cursor / VS Code / CLI / mcp-server)         │
                │                                                           │
                │   • 使用 proxy 模式   → 永远看不到密钥值                │
                │   • 使用 mTLS         → 证明身份                          │
                │   • 接收 WebAuthn     → 无密码存储                       │
                └─────────────────┬────────────────────────────────────────┘
                                  │ mTLS (TLS 1.2+)
                                  ▼
   ┌──────────────────────────────────────────────────────────────────────┐
   │                          Secret Broker (Node 20)                    │
   │                                                                      │
   │   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
   │   │ REST API │  │ WebSocket│  │  MCP stdio│  │   SSH    │            │
   │   │ /api/v1/ │  │   /ws    │  │  /mcp    │  │  /api/v1/│            │
   │   │          │  │ events   │  │   tools  │  │   ssh/*  │            │
   │   └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘            │
   │        │             │              │              │                │
   │   ┌────┴─────────────┴──────────────┴──────────────┴─────────────┐  │
   │   │ 8 个调用面: get/list/resolve / proxy / exec / ssh  │  │
   │   │ / workload-identity / login / health / audit / ws subscribe│  │
   │   └─────────────────────────┬──────────────────────────────────┘  │
   │                              │                                  │
   │            ┌─────────────────┴───────────────┐                  │
   │            │            Policy Engine         │                  │
   │            │  (per-client 白名单, scope 检查)  │                  │
   │            └─────────┬────────────────────────┘                  │
   │                      │                                          │
   │   ┌──────────────────┴──────────────────────────────┐           │
   │   │              Audit + Redact Layer               │           │
   │   │  • JSONL 追加,带 SHA-256 哈希链                │           │
   │   │  • 12+ 已知密钥模式自动脱敏                 │           │
   │   └──────────────────┬──────────────────────────────┘           │
   │                      │                                          │
   │   ┌──────────────────┴──────────────────────────────┐           │
   │   │              签名 + 注入层                       │           │
   │   │  (Aliyun v2 / AWS sigv4 / Azure AD / GCP /     │           │
   │   │   Cloudflare / Docker registry / 微信支付)     │           │
   │   └──────────────────┬──────────────────────────────┘           │
   │                      │                                          │
   │   ┌──────────────────┴──────────────────────────────┐           │
   │   │  SOPS 解密 secrets/broker.yaml (at-rest)       │           │
   │   └──────────────────┬──────────────────────────────┘           │
   │                      │                                          │
   │   ┌──────────────────┴──────────────────────────────┐           │
   │   │   Nginx (edge, 443, public TLS terminator)     │           │
   │   │   mTLS 验证, X-SSL-Client-* 头转发给 broker   │           │
   │   └────────────────────────────────────────────────┘           │
   │                                                                     │
   └─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
                       ┌─────────────────────┐
                       │  Upstream APIs      │
                       │  GitHub/Cloud/SSH/  │
                       │  K8s/ECS/GKE       │
                       └─────────────────────┘
```

## 8 个调用面

| 调用面 | 端点 | 谁能用 |
|---|---|---|
| `get/list/resolve` | `GET/POST /api/v1/secrets[/*]` | admin 或有 `allowed_resolve` 的人 |
| `proxy` | `POST /api/v1/proxy/:service` | admin 或有 `allowed_proxy` 的人 |
| `exec` (SSH) | `POST /api/v1/ssh/exec` | admin 或有 `allowed_proxy` 的人 |
| `workload-identity` | `POST /api/v1/wli/token` | 容器/Pod 用 OIDC |
| `login` | `POST /api/v1/login` + `/mfa` | 人类管理员 |
| `health` | `GET /health`, `/api/v1/healthcheck/status` | 任何人(只读元数据) |
| `audit` | `GET /api/v1/admin/audit[/*]` | admin only |
| `ws subscribe` | `WS /api/v1/ws` | admin only |

## 6 个认证因素

| 因素 | 谁能用 | 强度 |
|---|---|---|
| **mTLS 客户端证书** | 每台设备 | 强 (加密身份) |
| **TOTP** (RFC 6238) | 人类管理员 | 中 (Phishing-resistant) |
| **WebAuthn / Passkey** (FIDO2) | 人类管理员 | 强 (硬件密钥) |
| **API Key** (Bearer) | AI 客户端 / CI | 中 (短期, 限速) |
| **Workload Identity** (OIDC) | K8s/ECS/GKE Pods | 强 (自动轮转) |
| **Password** (scrypt) | 人类管理员 | 弱 (推荐 MFA) |

## 4 个 SDK

- **Node** (`sdk/node/`) — `npm install @tyj1987/broker-sdk`
- **Python** (`sdk/python/`) — `pip install secret-broker` (零硬依赖)
- **Go** (`sdk/go/`) — `go get github.com/tyj1987/broker-sdk-go` (零硬依赖)
- **VS Code / Cursor** (`sdk/vscode/`) — 从 releases 装 `.vsix`

## 4 个部署面

| 面 | 适用 | 路径 |
|---|---|---|
| **Docker / Compose** | 本地开发、小团队 | `Dockerfile`, `docker-compose.yml` |
| **Aliyun / Tencent Terraform** | 自托管云 | `infra/aliyun/`, `infra/tencent/` |
| **Helm** | K8s | `deploy/helm/broker/` |
| **Grafana + Prometheus** | 监控 | `deploy/grafana/` |

## 设计原则

1. **零信任 mTLS 优先**: 每条连接都被验证。Bearer API key 是一种**次要**便利,不是默认。
2. **静态加密 + 内存使用**: 凭据用 SOPS 加密在磁盘上,broker 进程启动时解密到内存。**凭据永远不写日志或错误响应**。
3. **拒绝客户端隐藏**: AI Agent 不能从日志、错误消息、监控指标里"探测"出密钥。broker **主动** 用 `redact.js` 过滤所有输出。
4. **三道防御层**:
   - `policy` 决定谁可以调什么
   - `redact` 决定什么会被泄漏
   - `audit` 决定谁干了什么
5. **可移植**: 单一 Node 进程,无外部服务依赖(除 SOPS+age 加密存储),Docker 镜像 ~150MB,启动 <2 秒。

## 阅读顺序

如果是第一次接触这个项目,按这个顺序读:

1. **[README.md](README.md)** —— 它是什么
2. **[QUICKSTART.md](docs/QUICKSTART.md)** —— 5 分钟教程
3. **[ARCHITECTURE.md](ARCHITECTURE.md)** (本文件) —— 高层总览
4. **[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)** —— 威胁模型
5. **[RUNBOOK.md](RUNBOOK.md)** —— 运行时运维
6. **源码** —— 从 `broker/server.js` + `broker/lib/redact.js` 开始
