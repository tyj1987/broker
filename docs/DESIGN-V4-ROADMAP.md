# Secret Broker V4 — Implementation Roadmap

> **本文档**:V4 实施的详细路线图(6 个月,3 个阶段)
> **配套**:`DESIGN-V4-MASTER-PLAN.md` 等 5 个设计文档
> **状态**:草案,待评审
> **更新**:2026-09-01

---

## 目录

1. [总览](#1-总览)
2. [P1 (V4.0) — 核心强化(1-2 月)](#2-p1-v40--核心强化1-2-月)
3. [P2 (V4.1) — 跨场景(3-4 月)](#3-p2-v41--跨场景3-4-月)
4. [P3 (V4.2) — 生态(5-6 月)](#4-p3-v42--生态5-6-月)
5. [资源与团队](#5-资源与团队)
6. [成功度量](#6-成功度量)
7. [风险与应对](#7-风险与应对)
8. [每周交付计划](#8-每周交付计划)

---

## 1. 总览

### 1.1 三阶段目标

| 阶段 | 周期 | 目标 | 关键指标 |
|---|---|---|---|
| **P1 (V4.0)** | 1-2 月 | **核心强化** | 40+ 模板 / WebAuthn / MFA Policy / SDK Sync / Auto-Rotate |
| **P2 (V4.1)** | 3-4 月 | **跨场景** | Workload Identity / SSH Proxy / WebSocket / Python SDK / IDE |
| **P3 (V4.2)** | 5-6 月 | **生态** | 1-click Cloud / Helm / Terraform / Grafana / Bug Bounty |

### 1.2 6 个月后达到的状态

- **40+ 服务商** 模板(从 6 → 40+)
- **6 种** 认证因子(从 2 → 6)
- **8 种** 调用入口(从 4 → 8)
- **3 个** SDK(从 0 → 3)
- **100%** OpenAPI schema 化
- **自动** 凭据 rotate
- **0** 凭据明文(强制)

### 1.3 不在 V4 范围(明确不做)

- ❌ 完整 IAM/PAM 替代
- ❌ KMS 同步(用户自管,broker 只读)
- ❌ 跨 broker 实例的 secret 共享
- ❌ broker→broker 联邦

---

## 2. P1 (V4.0) — 核心强化(1-2 月)

### 2.1 总体目标

把 v3.8 升级到 V4.0:**40+ 模板 + 6 因子 + SDK Sync + Auto-Rotate**。

### 2.2 任务清单(10 大任务)

#### 任务 1: WebAuthn 注册/认证端点(1 周)

**目标**:实现 FIDO2 / Passkey 全流程

**交付物**:
- `broker/webauthn.js` — challenge 生成/验证/credential 存储
- `broker/routes/auth.js` — 新增 4 个端点:
  - `POST /api/v1/me/webauthn/register/begin`
  - `POST /api/v1/me/webauthn/register/finish`
  - `POST /api/v1/login/webauthn/begin`
  - `POST /api/v1/login/webauthn/finish`
- 依赖:`@simplewebauthn/server`(仅此一个 npm 依赖)
- 测试:5 个 (register / authenticate / duplicate / revoke / U2F fallback)

**文件**:
- 新增:`broker/webauthn.js`, `broker-test/test-webauthn.js`
- 修改:`broker/routes/auth.js`, `broker/server.js`, `broker/package.json`

**验收**:
- [ ] YubiKey 5C NFC 注册成功
- [ ] Touch ID 登录成功
- [ ] Windows Hello 登录成功
- [ ] 重复注册检测
- [ ] Credential 列出 / 删除

#### 任务 2: MFA Policy 引擎 + Risk Score(1 周)

**目标**:6 因子 + 5 维风险评分

**交付物**:
- `broker/lib/risk-score.js` — 5 维评分函数
- `broker/lib/mfa-policy.js` — 决策函数
- `broker/auth-flow.js` 增强:
  - 支持 `factors_required` 数组
  - 多因子分步提交
  - `factors_verified` 状态机
- `secrets/broker.yaml` 新增 `mfa_policy` 配置段
- 测试:10 个 (各种 risk score 场景 + 多因子)

**文件**:
- 新增:`broker/lib/risk-score.js`, `broker/lib/mfa-policy.js`, `broker-test/test-mfa-policy.js`
- 修改:`broker/auth-flow.js`, `broker/lib/session.js`, `secrets/broker.yaml.example`

**验收**:
- [ ] score ≤ 20 不需要二验
- [ ] score 21-60 需要 1 因子
- [ ] score > 60 需要 2 因子
- [ ] admin 永远 ≥ 1 因子
- [ ] 敏感操作(rotate-cert/delete-secret)强制二验

#### 任务 3: SDK Sync 工具(1 周)

**目标**:从官网拉最新 OpenAPI,自动生成模板

**交付物**:
- `broker/bin/sync-templates.js` — 同步工具
- `broker/lib/template-parser.js` — 解析器(OpenAPI / curl / SDK)
- `broker/templates/sources.yaml` — 30+ 数据源列表
- `docs/TEMPLATES-SYNC-<date>.md` — 同步报告模板
- 同步流程:每月 1 号跑 + 邮件 PR 通知

**文件**:
- 新增:`broker/bin/sync-templates.js`, `broker/lib/template-parser.js`
- 修改:`broker/service-templates.js`(改用同步数据)

**验收**:
- [ ] 能从 OpenAPI 3.x 解析
- [ ] 能从 docs 页 curl 例子提取
- [ ] 生成 PR(github CLI)
- [ ] 检测 stale 模板(>90d)

#### 任务 4: 模板扩充(30 → 40+)(2 周)

**目标**:补齐 6 大类模板

**任务细分**:
| 类别 | 数量 | 模板 |
|---|---|---|
| AI 服务 | +5 | mistral / cohere / deepseek / zhipu / moonshot / qwen |
| 云厂商 - 中国 | +4 | aliyun_oss / tencent_cos / tencent_tcr / aliyun_dns |
| 云厂商 - 国际 | +3 | gcp / azure / digitalocean |
| 容器镜像 | +2 | ghcr / quay |
| 支付 | +1 | alipay_key |
| 通信 | +1 | feishu_app |
| 监控 | +1 | new_relic |
| SSH | +1 | ssh_proxy |
| 杂项 | +2 | npm_token / pypi_token |

**文件**:
- 修改:`broker/service-templates.js`(+ 20 模板)
- 修改:`broker/type-schemas.js`(+ 20 type)
- 新增:`broker/signing/*.js`(AWS SigV4 / Tencent V3 / GCP JWT 等)
- 测试:每模板 1 个 smoke test,共 + 20 测试

**验收**:
- [ ] 40+ 模板就绪
- [ ] 50+ type schema
- [ ] 每模板 smoke 通过
- [ ] dashboard 列出全部

#### 任务 5: Auto-Rotate 引擎(1 周)

**目标**:凭据到期前 14 天触发 rotate

**交付物**:
- `broker/auto-rotate.js` — 旋转引擎
- `broker/cron-tasks.js` 增强 — 加 rotation cron
- 通知:Slack/Email webhook
- Rollback:1-click 回滚
- 监控:Prometheus `secret_rotation_count_total`

**文件**:
- 新增:`broker/auto-rotate.js`
- 修改:`broker/cron-tasks.js`, `broker/healthcheck.js`, `broker/lib/alerting.js`(新)

**验收**:
- [ ] 到期前 14/7/1 天发告警
- [ ] 自动 rotate(支持的 provider)
- [ ] 手动 rotate 命令
- [ ] Rollback 命令
- [ ] Audit 记录

#### 任务 6: Master/Child API Key 增强(3 天)

**目标**:IP 白名单 + 限额细化

**交付物**:
- `broker/api-keys.js` 增强:
  - `ip_whitelist` 字段(v3 已有,加强)
  - 限额细化为 `rate_limit_per_minute` / `rate_limit_per_hour` / `rate_limit_per_day`
  - `expires_at` 强制(没有就是 24h)
- 测试:5 个

**验收**:
- [ ] IP 白名单 CIDR 支持
- [ ] 多维度限额
- [ ] 强制 TTL

#### 任务 7: 统一 OpenAPI 3.1 schema(1 周)

**目标**:100% 端点 OpenAPI 化

**交付物**:
- `docs/openapi.yaml` — 完整 OpenAPI 3.1
- `broker/bin/openapi-generate.js` — 从代码生成
- SDK 生成:Node / Python / Go
- Postman collection
- HTML 文档

**文件**:
- 新增:`docs/openapi.yaml`, `broker/bin/openapi-generate.js`
- 修改:每个 route 文件,加 OpenAPI 注释

**验收**:
- [ ] OpenAPI 校验通过
- [ ] SDK 生成可用
- [ ] Postman 导入可用
- [ ] HTML 文档美观

#### 任务 8: 统一 V4 文档(1 周)

**目标**:整合 5 个设计文档 + Quickstart

**交付物**:
- `docs/DESIGN-V4-MASTER-PLAN.md` (本路线图所属)
- `docs/DESIGN-V4-IDENTITY-MFA.md`
- `docs/DESIGN-V4-PROVIDER-TEMPLATES.md`
- `docs/DESIGN-V4-API-CALLING-STANDARDS.md`
- `docs/DESIGN-V4-SECURITY-MODEL.md`
- `docs/QUICKSTART.md` — 5 分钟上手

**验收**:
- [ ] 所有文档内部链接通
- [ ] Quickstart 真能 5 分钟跑通
- [ ] 设计决策有理有据

#### 任务 9: 跨平台 CI(1 周)

**目标**:Windows / Linux / macOS 三平台 CI

**交付物**:
- `.github/workflows/ci.yml` 增强:
  - 矩阵:windows-latest / ubuntu-latest / macos-latest
  - 全部 6 阶段(test:lib / test:ip / test:routes / test:obs / test:trace / test:ops / test:backup)
  - 模板 smoke(用 secrets)
- Docker 多平台:`linux/amd64,linux/arm64`

**验收**:
- [ ] 3 平台 CI 全绿
- [ ] Docker manifest 列表

#### 任务 10: 测试扩充(18 → 30+)(1 周)

**目标**:覆盖率 ≥ 80%

**任务细分**:
- WebAuthn:5
- MFA Policy:5
- Auto-Rotate:3
- SDK Sync:2
- 新模板 smoke:20
- 跨平台:2

**验收**:
- [ ] 30+ 测试
- [ ] 覆盖率 ≥ 80%
- [ ] CI 全绿

### 2.3 P1 交付清单(2 月末)

| 类型 | 数量 | 内容 |
|---|---|---|
| 新代码 | ~3000 行 | webauthn, mfa-policy, auto-rotate, signing, sync-templates, openapi |
| 新文档 | ~5000 行 | 5 个 DESIGN-V4 + QUICKSTART |
| 新测试 | 12 个 | test-webauthn, test-mfa-policy, test-auto-rotate, ... |
| 新模板 | 34 个 | 6 → 40 |
| 新 type | 20 个 | 30+ → 50+ |
| 新依赖 | 1 个 | @simplewebauthn/server |

### 2.4 P1 验收标准

- [ ] 所有 6 因子都可用
- [ ] 40+ 模板就绪 + smoke 通过
- [ ] 凭据自动 rotate 演示
- [ ] SDK 生成 + 调用通过
- [ ] 3 平台 CI 全绿
- [ ] 文档结构清晰
- [ ] v3.8 client 仍兼容(无破坏性变更)

---

## 3. P2 (V4.1) — 跨场景(3-4 月)

### 3.1 总体目标

扩展 broker 接入场景:**Workload Identity / SSH Proxy / WebSocket / Python SDK / IDE**。

### 3.2 任务清单

#### 任务 11: Workload Identity / OIDC(2 周)

**目标**:K8s / ECS Pod 0 AK,broker 取 STS

**交付物**:
- `broker/workload-identity.js` — OIDC 验证 + STS assume
- `broker/routes/workload-identity.js` — 4 个端点
- 配置:`workload_identity.providers.{aliyun,aws,gcp}`
- SDK:`SecretBroker.workloadIdentity` 选项
- 测试:6 个(每个云 + token 过期处理)

**验收**:
- [ ] K8s Pod 0 AK 调 AWS
- [ ] ECS 任务 0 AK 调阿里云
- [ ] GKE 0 AK 调 GCP
- [ ] 临时凭证自动刷新

#### 任务 12: SSH Proxy 模式(1 周)

**目标**:让 SSH 跳板经 broker,AI 永远不接触私钥

**交付物**:
- `broker/ssh-proxy.js` — SSH 服务器
- `broker/ssh-exec.js` — 命令执行
- 配置:`ssh_proxy.{listen_port, allowed_targets}`
- CLI:`secret-broker ssh-exec`
- MCP 工具:`ssh_exec`
- 测试:5 个(连接 / 命令 / 私钥零接触 / 审计)

**验收**:
- [ ] SSH 跳板可用
- [ ] 私钥只在 broker 内存
- [ ] 命令审计
- [ ] 私钥泄露检测(mTLS 验证后)

#### 任务 13: WebSocket 通道(1 周)

**目标**:实时事件流(SSE 等价但双向)

**交付物**:
- `broker/ws.js` — WebSocket 服务器
- `broker/routes/ws.js` — 升级路由
- 事件类型:`audit / healthcheck / alerts / secret_rotated / mfa_enrolled`
- 测试:5 个

**验收**:
- [ ] mTLS 双向认证
- [ ] 订阅 / 取消订阅
- [ ] 过滤
- [ ] 心跳

#### 任务 14: Python SDK(1 周)

**目标**:Python 应用可调 broker

**交付物**:
- `sdk/python/broker/` — Python 包
- `pyproject.toml`, `setup.py`
- 主要类:`SecretBroker`, `ProxyRequest`, `ProxyResponse`
- 类型提示(.pyi)
- 文档 + 示例
- 测试:10 个

**验收**:
- [ ] pip install 装得上
- [ ] 100% 端点覆盖
- [ ] 类型完整
- [ ] 示例可跑

#### 任务 15: Go SDK(1 周)

**目标**:Go 应用可调 broker

**交付物**:
- `sdk/go/` — Go module
- 主要类型:`Client`, `ProxyRequest`, `ProxyResponse`
- context 支持
- 文档 + 示例
- 测试:8 个

**验收**:
- [ ] go get 装得上
- [ ] context 超时
- [ ] 类型完整
- [ ] 示例可跑

#### 任务 16: VS Code / Cursor Extension(1 周)

**目标**:IDE 内调用 broker

**交付物**:
- `ide/extension/` — VS Code extension(用 Cursor 兼容)
- Tree view:secrets / services / health
- 命令面板:proxy / resolve / exec
- 测试:5 个

**验收**:
- [ ] VS Code marketplace 上架
- [ ] Cursor 兼容
- [ ] 命令面板可用
- [ ] 凭据零接触

#### 任务 17: P2 文档(3 天)

- WORKLOAD-IDENTITY.md
- SSH-PROXY.md
- WEBSOCKET.md
- SDK-REFERENCE.md

### 3.3 P2 交付清单

| 类型 | 数量 |
|---|---|
| 新代码 | ~2000 行 |
| 新 SDK | 2 个(Python + Go) |
| 新 IDE Extension | 1 个 |
| 新协议 | 2 个(WS + SSH) |
| 新测试 | 35 个 |
| 新文档 | 4 个 |

---

## 4. P3 (V4.2) — 生态(5-6 月)

### 4.1 任务清单

#### 任务 18: 一键部署到云(2 周)

**交付物**:
- AWS Marketplace AMI
- Azure Marketplace VM image
- GCP Marketplace image
- 阿里云 / 腾讯云 ROS 模板
- Terraform module(`modules/broker/`)
- Helm chart(`charts/secret-broker/`)

#### 任务 19: Grafana 仪表板(3 天)

- `dashboards/broker.json`(8 panel)
- 关键 SLI/SLO
- Alert 规则

#### 任务 20: 文档站点(1 周)

- 静态文档站(mkdocs)
- 包括设计 + Quickstart + Runbook + Reference
- 部署到 docs.52trz.com(可选)

#### 任务 21: Bug Bounty 计划(2 周)

- 公开安全邮箱
- 漏洞披露政策
- 奖励规则
- Hall of Fame

#### 任务 22: 审计(2 周)

- SOC 2 Type II(可选)
- 等保 2.0 三级
- 渗透测试

#### 任务 23: V4.x 后续(2 周)

- 性能优化(P95 < 200ms)
- 国际化(en-US 文档)
- 社区建设(Discord / GitHub Discussions)

### 4.2 P3 交付清单

| 类型 | 数量 |
|---|---|
| Marketplace | 4 个云 |
| Terraform | 1 module |
| Helm | 1 chart |
| Grafana | 8 panel |
| 文档站 | 1 site |
| 认证 | 1-2 个 |

---

## 5. 资源与团队

### 5.1 角色

| 角色 | 工作量 | 职责 |
|---|---|---|
| **架构师** | 全程 | 总体设计 + 评审 |
| **后端 (Node)** | 80% | broker 核心 + SDK |
| **前端 (Vanilla JS)** | 20% | dashboard |
| **DevOps** | 20% | CI/CD + 双云部署 |
| **安全** | 10% | 安全审计 + IR |
| **文档** | 20% | 设计 + 用户文档 |

### 5.2 假设

- 1 个全栈(主)+ AI 助手(Mavis)协作
- 每月 1-2 个 commit 周期
- 所有 PR 必 review
- v3.8 稳定,不破坏性变更

---

## 6. 成功度量

### 6.1 量化指标

| 阶段 | 指标 | 目标 |
|---|---|---|
| **P1 (2 月)** | 模板数 | 40+ |
| | 认证因子 | 6 |
| | 测试数 | 30+ |
| | 文档完整 | 6 文档 |
| **P2 (4 月)** | SDK | 3 (Node/Python/Go) |
| | 接入场景 | 8 种 |
| | 测试数 | 50+ |
| | IDE Extension | 1 |
| **P3 (6 月)** | Marketplace | 4 云 |
| | 文档站 | 上线 |
| | 漏洞奖励 | 启动 |
| | 用户社区 | 启动 |

### 6.2 质量指标

- [ ] broker uptime ≥ 99.9%
- [ ] proxy P95 < 300ms
- [ ] AI 接触明文次数 = 0
- [ ] 100% 操作审计
- [ ] 测试覆盖率 ≥ 80%

---

## 7. 风险与应对

| 风险 | 概率 | 影响 | 应对 |
|---|---|---|---|
| **时间延误** | 中 | 中 | 分阶段交付,每阶段有 demo |
| **scope creep** | 高 | 中 | 严格按 DESIGN-V4 范围,不做范围内的事 |
| **依赖变更** | 中 | 中 | 锁定 minor version;自动更新 |
| **安全漏洞** | 低 | 高 | 每月扫描;快速响应;Bug Bounty |
| **API 格式变更** | 中 | 中 | SDK Sync 自动检测 |
| **大云厂商 SDK 接口变更** | 低 | 高 | 抽象 signing 接口,易替换 |

---

## 8. 每周交付计划

### 8.1 P1 详细(8 周)

| 周 | 任务 | 交付 |
|---|---|---|
| W1 | WebAuthn | `broker/webauthn.js` + 4 端点 + 5 测试 |
| W2 | MFA Policy + Risk Score | `mfa-policy.js` + `risk-score.js` + 10 测试 |
| W3 | SDK Sync 工具 | `bin/sync-templates.js` + 30 sources + 文档 |
| W4 | 模板扩充 (1) | 20 新模板(AI + 云中国) |
| W5 | 模板扩充 (2) | 14 新模板(云国际 + 容器 + 通信) |
| W6 | Auto-Rotate | `auto-rotate.js` + cron + 5 测试 |
| W7 | OpenAPI + SDK 生成 | `docs/openapi.yaml` + Node SDK |
| W8 | 文档 + 测试收尾 | 5 DESIGN 文档 + QUICKSTART + 测试覆盖 |

### 8.2 P2 详细(8 周)

| 周 | 任务 | 交付 |
|---|---|---|
| W9 | Workload Identity (1) | OIDC 验证 + STS |
| W10 | Workload Identity (2) | SDK + 测试 + 文档 |
| W11 | SSH Proxy | `ssh-proxy.js` + 测试 |
| W12 | WebSocket | `ws.js` + 测试 |
| W13 | Python SDK | Python 包 + 测试 + 文档 |
| W14 | Go SDK | Go module + 测试 + 文档 |
| W15 | VS Code Extension | Extension + 文档 |
| W16 | P2 收尾 | 文档 + 测试 + Demo |

### 8.3 P3 详细(8 周)

| 周 | 任务 | 交付 |
|---|---|---|
| W17 | AWS Marketplace | AMI + Terraform module |
| W18 | Azure + GCP Marketplace | 镜像 |
| W19 | 阿里云 / 腾讯云 ROS | 模板 |
| W20 | Helm chart | chart + 测试 |
| W21 | Grafana dashboard | JSON + 文档 |
| W22 | 文档站(mkdocs) | 站点 + 部署 |
| W23 | Bug Bounty 启动 | 政策 + 流程 |
| W24 | V4.2 GA 发布 | 总结 + 公告 |

---

## 附录 A:依赖管理

### A.1 新增依赖(P1)

```json
// broker/package.json
{
  "dependencies": {
    "yaml": "^2.9.0",            // 已有
    "@simplewebauthn/server": "^13.0.0"  // V4 新增
  }
}
```

### A.2 锁版本

- `package-lock.json` 锁 minor
- CI 用 `npm ci`(而非 `install`)
- 升级:`npm outdated` + 单独 PR

---

## 附录 B:发布流程

### B.1 版本号

V4.0.0 → V4.0.1 (patch) → V4.1.0 (minor) → V5.0.0 (major)

### B.2 发布检查清单

- [ ] 所有测试通过
- [ ] CHANGELOG 更新
- [ ] 文档更新
- [ ] 模板覆盖 ≥ 95%
- [ ] 安全扫描 0 high
- [ ] Docker image rebuild
- [ ] 部署到双云(灰度)
- [ ] 通知用户

### B.3 回滚

- Git tag 保留
- Docker image 保留 90 天
- 1-command 回滚:`./scripts/deploy.sh --version v4.0.0`

---

## 附录 C:团队 OKR

### C.1 P1 OKR

- **O1**:broker 成为 AI 友好、安全、易用的统一密钥平台
- **KR1**:支持 40+ 服务商(基线:6)
- **KR2**:6 种认证因子(基线:2)
- **KR3**:100% OpenAPI 化(基线:50%)
- **KR4**:Auto-Rotate 上线(基线:手动)
- **KR5**:文档 5 篇(基线:0 V4)

### C.2 P2 OKR

- **O2**:覆盖所有 AI / DevOps 接入场景
- **KR1**:8 种调用入口(基线:4)
- **KR2**:3 个 SDK(基线:0)
- **KR3**:1 个 IDE Extension
- **KR4**:OIDC / SSH Proxy 上线

### C.3 P3 OKR

- **O3**:生态化、可商用
- **KR1**:4 个云 Marketplace
- **KR2**:Helm + Terraform
- **KR3**:Bug Bounty 启动
- **KR4**:100+ stars on GitHub

---

**作者**:Mavis (AI 架构助手) + 脱永军 (项目所有者)
**最后更新**:2026-09-01
**版本**:V4.0-ROADMAP
