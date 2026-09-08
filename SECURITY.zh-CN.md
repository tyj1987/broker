# 安全策略

> English version: [SECURITY.md](SECURITY.md)

## 支持的版本

| 版本 | 支持情况 | EOL |
|---|---|---|
| 4.x     | ✅ | 活跃 (GA 2026 Q3) |
| 3.8.x   | ✅ | 仅关键修复 (2027-01-01) |
| 3.7.x   | ❌ | EOL 2026-06-01 |
| 3.6.x   | ❌ | EOL 2026-01-01 |
| < 3.6   | ❌ | EOL |

## 报告漏洞

**请勿在公开 GitHub issue 中报告安全漏洞。**

邮件: **security@broker.example.com** (PGP 密钥见
`.well-known/pgp-key.asc`)

响应 SLA:初次确认 **48 小时**,完整评估 **7 天**,修复(或协调披露)
**30 天**。

## 漏洞赏金计划

!!! info "自 2026-08-01 起生效"
    范围: `broker/` 服务端、`sdk/` 客户端、`deploy/helm/broker/`、
    `deploy/terraform/modules/broker/`,以及任何含可验证利用代码的
    文档。

| 严重性 | 奖金 (美元) | 示例 |
|----------|-------------|----------|
| **严重** | $5,000 | 远程未授权 RCE、mTLS 绕过、审计日志明文密钥泄漏 |
| **高危**   | $2,000 | 已授权 RCE、审计数据库的 SQLi、跨客户端权限提升 |
| **中危**   | $500   | 管理 UI 存储型 XSS、rotate 端点 CSRF、WebSocket 洪泛 DoS、未授权 `/health` 泄漏 SOPS/服务清单 |
| **低危**   | $100   | 已授权响应泄漏 broker 版本信息、`/health` 缺少速率限制 |

### 资格

- 必须能针对 [Helm chart](https://github.com/tyj1987/broker/tree/main/deploy/helm/broker)
  中的**最新发布**版本复现。
- 不得是已知或公开披露的漏洞。
- 社工、物理和 DDoS 攻击不在范围内。
- **不要**针对生产客户实例测试。

### 不在范围内

- Self-XSS
- 不泄漏凭据的冗长错误消息
- 第三方依赖中的漏洞(请向其上游报告)
- 没有可用 PoC 的理论漏洞

### 披露时间线

1. **第 0 天** —— 你报告漏洞。
2. **第 1-2 天** —— 我们确认。
3. **第 3-7 天** —— 我们分诊并确认。
4. **第 8-30 天** —— 我们开发修复并与你协调披露。
5. **第 30 天后** —— 我们发布 CVE + 公告 + 致谢。

## 安全架构

完整设计见 [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md)。

关键属性:

- **零凭据泄漏**:每一层(服务端、SDK、审计日志)都通过脱敏引擎
  处理密钥值,然后再序列化为 JSON、日志或错误消息。
- **仅 mTLS**:无明文 HTTP,无匿名端点,无共享 API 密钥。
- **纵深防御**:WebAuthn + TOTP + 风险评分 + per-client 锁定。
- **无遥测**:broker 除了你显式配置的外呼(如 OIDC 交换、webhook 告警)外,
  不会进行任何出站网络调用。

## 威胁模型

| 攻击者 | 范围内 | 防御 |
|-----------|----------|---------|
| 网络攻击者(被动) | 是 | mTLS 1.2+ |
| 网络攻击者(主动 MITM) | 是 | mTLS + 客户端绑定的 CA |
| 被盗的客户端证书 | 是 | 短 TTL (24h) + 自动轮换;按 `clients[].services` ACL 限权 |
| 恶意 AI agent(不受信任的模型输出) | **主要** | Proxy 模式、脱敏引擎、AI 永不接触原始密钥 |
| 内部人员(broker 管理员) | 有限 | 所有管理操作都有审计;静态 SOPS 加密,age/PGP 密钥托管 |
| 被攻破的 broker 服务端 | 有限 | SOPS 解密密钥从不在静态加载到内存;密钥仅作为加密的 YAML 存在 |
| 被攻破的 K8s 节点 | 是 | broker pod 上无持久状态;PVC 静态加密;密钥按请求重取 |

## 加固清单

- [ ] 启用 `readOnlyRootFilesystem: true`(Helm 默认)
- [ ] 启用 `runAsNonRoot: true`(Helm 默认)
- [ ] 启用 `capabilities.drop: [ALL]`(Helm 默认)
- [ ] 在 liveness/readiness 探针上设 `failureThreshold: 3`
- [ ] 将 `BROKER_CA_CERT` 设为私有 CA,而不是公共 CA
- [ ] 使用 `--set-file secrets.brokerYaml=secrets/broker.yaml`(sops 加密)
- [ ] 通过 `NetworkPolicy` 限制为已知客户端 CIDR
- [ ] 启用 `alerting.channels: [slack, pagerduty]`
- [ ] 通过 WebSocket 订阅 `secret.rotated`、`auth.brute_force`、`mfa.fail_threshold`
- [ ] 每次升级后跑 `helm test broker`
- [ ] 在 [`deploy/grafana/alerts.yml`](deploy/grafana/alerts.yml) 中订阅 Grafana 告警

## 密码学

- **mTLS**:TLS 1.2 最低,TLS 1.3 优先;RSA 2048+ / ECDSA P-256+
- **SOPS**:age(推荐)或 PGP;见
  [THREAT-MODEL § 密码学](docs/THREAT-MODEL.md)
- **哈希**:SHA-256(审计链),Argon2id(WebAuthn)
- **CSPRNG**:Node `crypto.randomBytes`(用于 session token、MFA 码)

## 审计日志

broker 将仅追加的审计日志写入 `audit/YYYY-MM-DD.jsonl` (SOPS 加密形式)。
每个事件包括:

- `action`(如 `secret.resolve`、`auth.login`、`ssh_exec`)
- `cn`(mTLS 证书的客户端通用名)
- `ts`(ISO 8601 UTC)
- `request_id`(用于与追踪交叉引用)
- `redacted_payload`(由脱敏引擎自动脱敏)

审计链每天用 SHA-256 哈希链签名。篡改历史记录在验证时
可被检测出来。

## 联系方式

- 安全问题:security@broker.example.com (PGP 可用)
- 常规问题:GitHub Discussions
- 实时聊天:Discord 上的 #broker(链接在 README)
