# Secret Broker V4 — Security Model & Zero-Trust

> **本文档**:V4 安全模型 + 零信任架构 + 攻击面分析 + 应急响应
> **基础**:v3.0 零明文 + v3.2 90天证书 + v3.5 IP 白名单 + v3.8 审计
> **目标**:**任何攻击面都有 mitigation,任何异常都有检测,任何泄露都有响应**

---

## 目录

1. [零信任原则](#1-零信任原则)
2. [威胁建模 (STRIDE)](#2-威胁建模-stride)
3. [攻击面分析](#3-攻击面分析)
4. [凭据生命周期安全](#4-凭据生命周期安全)
5. [网络层安全](#5-网络层安全)
6. [应用层安全](#6-应用层安全)
7. [数据层安全](#7-数据层安全)
8. [审计与告警](#8-审计与告警)
9. [应急响应 (IR)](#9-应急响应-ir)
10. [合规与认证](#10-合规与认证)
11. [安全测试](#11-安全测试)
12. [持续改进](#12-持续改进)

---

## 1. 零信任原则

### 1.1 NIST 8 大零信任原则(V4 全部满足)

| 原则 | broker 实施 |
|---|---|
| **1. 资源即边界** | 每个 secret/service 显式 ACL,默认 deny |
| **2. 一切通信加密** | TLS 1.3 / mTLS / SSH over TLS |
| **3. 逐会话访问** | session 24h,滑动续期,可主动撤销 |
| **4. 动态策略** | risk score 决定 MFA 要求 |
| **5. 持续监控** | 100% audit JSONL + Prometheus + OpenTelemetry |
| **6. 动态认证** | mTLS/Password/TOTP/WebAuthn/SMS 多因子可叠加 |
| **7. 最小权限** | 服务账号/子账号都有限定 scope,无 admin |
| **8. 假设失陷** | 异常检测 → 自动撤销 cert + rotate secret |

### 1.2 关键不变量

```
不变 1: AI 永远不接触明文
  - 强制:proxy 是默认入口
  - 强制:MCP 响应 redact value 字段
  - 强制:exec 子进程结束即丢

不变 2: 凭据只在 broker 内存
  - 静态:SOPS+age 加密
  - 内存:从 resolve 到 fetch < 100ms
  - 转发后立即 GC

不变 3: 100% 关键操作审计
  - 任何密钥访问
  - 任何 ACL 变化
  - 任何认证事件
  - 任何配置变化

不变 4: 默认拒绝
  - 不在 clients: 的 cert → 401
  - 不在 allowed_proxy 的 service → 403
  - 不在 allow_paths 的 path → 403
  - 不在 ip_whitelist 的 IP → 403
  - 不在 mfa_factor 的因子 → 401

不变 5: 短命凭证
  - API Key 默认 24h
  - Child Key 1h
  - Master Key 30d
  - mTLS cert 90d
  - TOTP code 30s
  - Recovery code 一次性
  - WebAuthn cred 永久(公钥不变)
```

---

## 2. 威胁建模 (STRIDE)

### 2.1 STRIDE 6 大类威胁

| 类别 | 威胁 | broker 缓解 |
|---|---|---|
| **S**poofing 伪装 | 攻击者伪造 client cert | CA 私钥在 broker 服务器 600 权限;CRL 立即吊销 |
| **T**ampering 篡改 | broker.yaml/secrets 被改 | SOPS+age 加密;git 仓库 .gitignore;部署端 mTLS 推送 |
| **R**epudiation 否认 | 用户否认操作 | 100% audit JSONL,7 年保留 |
| **I**nformation Disclosure 信息泄露 | secret value 落日志 | 强制 redact 函数;Prometheus 监控;Linting |
| **D**enial of Service 拒绝服务 | DDoS / 资源耗尽 | mTLS 天然屏障;rate limit;Cloudflare WAF |
| **E**levation of Privilege 权限提升 | client 调 admin API | ACL 显式;admin 操作要 2 因子 |

### 2.2 数据流图 + 威胁(DFD)

```
┌────────┐    ┌─────────────┐    ┌──────────────┐    ┌─────────┐
│ Client │ →  │ broker      │ →  │ 上游 API     │    │ 攻击者  │
│ (AI)   │    │  ├─ Auth    │    │ (GitHub等)   │    │         │
└────────┘    │  ├─ ACL     │    └──────────────┘    └─────────┘
              │  ├─ Resolve │            ↑                ↑
              │  ├─ Proxy   │            │                │
              │  └─ Audit   │            │                │
              └─────────────┘            │                │
                                       T1: 伪造上游    T6: 调 admin API
                                       T2: 注入恶意 path
                                                        
T1-T9 威胁:
T1 = 伪造上游响应    → TLS 1.3 + cert verify
T2 = 注入恶意 path  → path 校验 + allow_paths regex
T3 = 滥用 IP         → ip_whitelist + rate limit
T4 = AI 提权         → scope 严格 + admin 单独
T5 = 设备丢失         → revoke cert + 通知
T6 = 调 admin API    → 需 2 因子
T7 = 凭据老化         → 自动 rotate + 告警
T8 = SOPS 私钥泄露  → key rotation 流程
T9 = Docker 容器逃逸  → read_only rootfs + no-new-privileges
```

---

## 3. 攻击面分析

### 3.1 攻击面清单

| 攻击面 | 暴露给 | 风险等级 | 缓解 |
|---|---|---|---|
| **broker HTTPS 端口 8443** | 公网 / 内网 | **高** | mTLS 双向;Cloudflare WAF;rate limit;IP 白名单 |
| **SSH Proxy 端口 7222** | 内网 | 中 | mTLS 二次认证;command 审计 |
| **OIDC token 端点** | 集群内 | 中 | K8s SA 校验;OIDC issuer 验证 |
| **MCP HTTP 端口 3001** | 本地 / 隧道 | 低 | 仅监听 127.0.0.1 |
| **Dashboard 静态资源** | 公网 | 低 | 无 server-side state |
| **CA 私钥文件** | broker 服务器 | **极高** | 600 权限 + 永不出服务器 |
| **age 私钥文件** | broker 服务器 | **极高** | 600 权限 + 不入 git |
| **SOPS 加密文件** | Git | 中 | 多钥匙 + 备份 |
| **client cert + key** | 用户设备 | **高** | 90d 强制 rotate;revoke 立即生效 |
| **API Key (memory)** | 用户 session | 中 | 短 TTL;显示一次;SHA-256 存 |
| **MCP child key** | MCP server 内存 | 低 | 1h TTL;不在磁盘 |
| **broker 进程内存** | OS | 中 | 短 GC;不 swap;core dump 关 |
| **审计日志** | broker 服务器 | 低 | 7 年保留;access 控制 |
| **依赖链 (npm 包)** | 构建 | 中 | lockfile;Snyk 扫描;最小依赖 |
| **Docker image layer** | registry | 中 | 多 stage;非 root user;read-only |

### 3.2 攻击者画像 + 攻击路径

#### 攻击者 A: 拿到 client cert 的攻击者

```
A1: 物理偷走用户笔记本
  → cert + key 一起丢
  缓解:cert 90d 强制 rotate + 用户发现后立即 revoke

A2: 从 GitHub 偷到一份老 cert
  → 90d 过期了
  缓解:CRL 检查 + 过期拒绝

A3: 拿到 cert 但不知道 broker endpoint
  → 不知道 mTLS 私钥(不在 cert 里)
  缓解:TLS 双向,无 key 拒
```

#### 攻击者 B: 拿到 broker 临时 API Key

```
B1: 拿到 mb_live_xxx(从日志/截图/聊天)
  → revoke 立即失效
  缓解:短 TTL + 用户可见的 revoke UI

B2: AI prompt injection 让它泄露 key
  → 不会被注入,因为 AI 永远不接触 key
  缓解:proxy/exec 模式;redact

B3: 重放
  → X-Idempotency-Key 防止
  缓解:可选用幂等键 + trace_id
```

#### 攻击者 C: 攻陷 broker 服务器

```
C1: 拿到 root 权限
  → 读到 age 私钥 + SOPS 密文
  缓解:age 私钥可独立 rotate;SOPS 多钥匙;主 A + 备份 B
  → 读到 mTLS CA 私钥
  缓解:新 CA + 重发所有 cert
  → 内存中正在解密的 secret
  缓解:短 GC;不 swap;core dump 关
  → 历史审计日志
  缓解:异地归档 + 防篡改

C2: 横向移动
  → 攻陷 broker 后想跳到上游
  缓解:broker 出向连接只到指定 upstream;Egress 防火墙

C3: 持久化后门
  → 改 broker 二进制
  缓解:Image digest 校验;定期重启
```

#### 攻击者 D: 内部恶意 admin

```
D1: admin 拉走所有 secret
  → audit 立刻记录
  缓解:admin 操作也审计 + 告警;敏感操作要 2 因子
  → 但 admin 能解 SOPS
  缓解:age 私钥不在 broker 服务器明文,需要 admin + 物理访问 USB 备份
  → 双钥匙机制:生产部署 age key 在 USB,broker 服务器只解密不导出

D2: admin 撤销所有 cert
  → 自己被锁外
  缓解:CRL 同步;re-issue 流程
```

### 3.3 攻击路径矩阵

| 攻击 | 路径长度 | 难度 | 检测 | 响应时间 |
|---|---|---|---|---|
| 偷笔记本 + 用 cert | 1 | 低 | 设备列表 | 5 秒 |
| 偷 mb_live_xxx | 1 | 中 | audit 异常 IP | 立即 |
| 重放请求 | 1 | 中 | X-Idempotency-Key | 立即 |
| 攻陷 broker 服务器 | 5 | 高 | OS 监控 / EDR | 分钟级 |
| 内部 admin 拉走 secret | 2 | 中 | audit 拉取告警 | 立即 |
| AI prompt 注入 | 0 | N/A | proxy 不返明文 | N/A |
| 暴力破解密码 | 1 | 中 | 5 次失败锁定 | 立即 |
| SSRF 攻击 broker | 2 | 高 | upstream 白名单 | 立即 |
| DDoS | 1 | 低 | Cloudflare WAF | 秒级 |

---

## 4. 凭据生命周期安全

### 4.1 创建

```
1. Admin 登录 Dashboard(TOTP)
2. 选 secret type → 自动渲染表单
3. 填值,前端本地加密(client-side RSA-OAEP,可选)
4. POST /api/v1/admin/secrets { type, name, fields: {...} }
5. broker 端:
   a. 验证 admin role + TOTP
   b. audit { action: 'create_secret', cn, name, type }
   c. SOPS 加密字段
   d. 写 secrets-detail.json
   e. 重新解密内存中的 secrets map
   f. 立即触发 healthcheck(后台)
6. 返 200 { name, type, last_used: null }
```

**安全控制**:
- 前端可选 client-side encryption(用户密码作为 RSA-OAEP 密钥)
- 服务端再次 SOPS 加密(double encryption)
- 创建操作要 2 因子(admin 角色要求)
- 立即健康检查

### 4.2 存储

```
静态:  secrets-detail.json(磁盘, SOPS 加密, Git 仓库)
传输:  TLS 1.3
内存:  in-memory map,GC 立即清

不存储:
  - 历史 secret 值(rotate 后旧值从内存清掉)
  - 明文 password(只存 scrypt hash)
  - 完整 recovery code(只存 SHA-256 hash)
  - 明文 TOTP secret(只存 base32 secret 用于 verify)
```

**磁盘加密**:
- SOPS + age (X25519 + scrypt)
- 主 key A 在 broker 服务器
- 备份 key B 在 USB 离线(异地)
- 文件 mode 600,owner only

### 4.3 使用

```
1. Client 调 POST /api/v1/proxy/:service
2. broker:
   a. ACL check
   b. 找 svc.token_secret
   c. resolveSecret(name) → 内存明文
   d. buildUpstreamRequest(签名注入)
   e. fetch upstream
   f. 清内存(GC)
   g. audit emit
   h. 返回响应(无 secret)
```

**不变量**:
- secret value 永远不在 audit/response/log
- secret value 在内存中存活 < 100ms
- secret value 永不入 response body

### 4.4 轮换

#### 4.4.1 自动触发

```yaml
# broker.yaml
rotation:
  enabled: true
  default_interval_days: 90
  warn_before_days: 14
  auto_rotate_services: []  # 空 = 不自动
  notification:
    - type: slack_webhook
      url: '{{secret.slack_alerts.url}}'
```

#### 4.4.2 流程

```
T-14d:  发 Slack "github.pat 将在 14 天后到期"
T-7d:   发 Slack "7 天"
T-1d:   发 Slack "明天"
T+0d:   cron 健康检查发现到期
        ↓
        自动调 provider API rotate(若支持)
        例:GitHub: revoke + 重建 fine-grained PAT
        例:阿里云 AK: 创建新 RAM user AK + 禁用旧的
        ↓
        SOPS 加密新值
        写 secrets-detail.json
        audit: { action: 'rotate', from, to, status }
        发 Slack "已 rotate"
```

#### 4.4.3 Rollback

```bash
# 误 rotate 可回滚(旧值 SOPS 备份过)
secret-broker secrets rollback github.pat --to-version 2026-08-15
# → 从 git 拉旧版本(自动备份)
# → SOPS 解密旧值
# → 写当前
# → audit
```

### 4.5 销毁

| 销毁方式 | 触发 | 实施 |
|---|---|---|
| **revoke API Key** | 用户/admin | `DELETE /api/v1/api-keys/:id`,标记 `revoked_at` |
| **rotate secret** | 到期/手动 | 旧值从内存清,SOPS 重写新值 |
| **revoke cert** | 设备丢失 | `revoke-cert.ps1` → CRL 列表 |
| **delete secret** | 永久不要 | SOPS 重写,字段全空,审计 |
| **destroy broker** | 服务器退役 | age 私钥销毁,SOPS 重新加密所有 |

---

## 5. 网络层安全

### 5.1 端口规划

| 端口 | 协议 | 暴露 | 用途 |
|---|---|---|---|
| 8443 | mTLS HTTPS | 公网/内网 | 主入口 |
| 7222 | SSH | 内网 | SSH Proxy |
| 3001 | HTTP (MCP) | **127.0.0.1 only** | MCP Server |
| 9100 | HTTP (metrics) | 内网 | Prometheus |
| 9090 | HTTP (health) | 内网 | K8s probe |

### 5.2 防火墙规则

```bash
# 阿里云 ECS 安全组
# 入站:
8443/8443  0.0.0.0/0     # mTLS HTTPS(可选 Cloudflare WAF 兜底)
7222/7222  192.168.0.0/16  # SSH Proxy,内网
9100/9100  192.168.0.0/16  # Prometheus 抓取

# 出站:
443/443    api.github.com      # 调上游
443/443    api.openai.com
443/443    ecs.aliyuncs.com
443/443    sts.amazonaws.com
# 全部白名单,其他 deny
```

### 5.3 TLS 1.3 强制

```javascript
// broker/server.js
const httpsOptions = {
  key: readFileSync(serverKey),
  cert: readFileSync(serverCert),
  ca: readFileSync(caCert),
  crl: readFileSync(crlPath),  // V4 强化
  minVersion: 'TLSv1.3',
  maxVersion: 'TLSv1.3',
  ciphers: [
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_GCM_SHA256',
  ],
  honorCipherOrder: true,
  requestCert: true,           // mTLS
  rejectUnauthorized: true,
};
```

### 5.4 证书管理

- **CA**:broker 服务器本地,10 年期,4096-bit RSA
- **Server cert**:90 天,自动续签
- **Client cert**:90 天,强制 rotate(`scripts/issue-client-cert.ps1`)
- **CRL**:每次 revoke 后立即更新,broker 启动时加载,热加载支持

---

## 6. 应用层安全

### 6.1 输入验证

```javascript
// broker/lib/validate.js
export function validateProxyRequest(body) {
  // method
  if (!ALLOWED_METHODS.has(body.method)) {
    throw new BadRequest('Invalid method');
  }
  // path
  if (!/^\/[a-zA-Z0-9\-._~!$&'()*+,;=:@/]+$/.test(body.path)) {
    throw new BadRequest('Invalid path characters');
  }
  if (body.path.length > 2048) {
    throw new BadRequest('Path too long');
  }
  // headers
  for (const [k, v] of Object.entries(body.headers || {})) {
    if (BLOCKED_HEADERS.has(k.toLowerCase())) {
      throw new BadRequest(`Header ${k} is reserved`);
    }
    if (v.length > 4096) {
      throw new BadRequest(`Header ${k} too long`);
    }
  }
  // body
  const bodyStr = typeof body.body === 'string' ? body.body : JSON.stringify(body.body || '');
  if (bodyStr.length > 10 * 1024 * 1024) {
    throw new BadRequest('Body too large (10MB)');
  }
}
```

### 6.2 路径白名单(SSRF 防御)

```yaml
# broker.yaml
services:
  my_service:
    type: header
    upstream: https://api.example.com
    allow_paths:
      - "^/v1/.*"        # 只允许 v1/ 开头
      - "^/v2/users/.*"  # + v2/users/
    # 默认拒绝任何 path
```

### 6.3 输出清洗

```javascript
// 任何日志/响应都不包含 secret
function redactSecrets(s) {
  // GitHub PAT
  s = s.replace(/ghp_[a-zA-Z0-9]+/g, 'ghp_***');
  s = s.replace(/github_pat_[a-zA-Z0-9_]+/g, 'github_pat_***');
  // OpenAI
  s = s.replace(/sk-[a-zA-Z0-9]+/g, 'sk-***');
  s = s.replace(/sk-proj-[a-zA-Z0-9]+/g, 'sk-proj-***');
  // Anthropic
  s = s.replace(/sk-ant-[a-zA-Z0-9]+/g, 'sk-ant-***');
  // 阿里云
  s = s.replace(/LTAI[a-zA-Z0-9]+/g, 'LTAI***');
  // AWS
  s = s.replace(/AKIA[A-Z0-9]{16}/g, 'AKIA***');
  s = s.replace(/ASIA[A-Z0-9]{16}/g, 'ASIA***');
  // 通用 Bearer / API key
  s = s.replace(/(Bearer\s+)[a-zA-Z0-9_\-\.]{20,}/g, '$1***');
  return s;
}
```

### 6.4 防重放

- **mTLS** 已防重放(每个 TLS 会话唯一)
- **X-Idempotency-Key** 可选:`POST` 请求附 `Idempotency-Key` 头,broker 缓存 24h
- **trace_id** 透传,客户端可检测重复

### 6.5 SSRF 防护

```javascript
// broker 不解析 DNS,但 upstream host 必须匹配 allowlist
const ALLOWED_UPSTREAMS = new Set([
  'api.github.com',
  'api.openai.com',
  'api.anthropic.com',
  'ecs.aliyuncs.com',
  // ...
]);

function validateUpstream(url) {
  const u = new URL(url);
  if (!ALLOWED_UPSTREAMS.has(u.hostname)) {
    throw new BadRequest(`Upstream ${u.hostname} not allowed`);
  }
}
```

---

## 7. 数据层安全

### 7.1 静态加密

```
secrets-detail.json (Git)
  ↓ SOPS 加密
  ↓ age (X25519 + ChaCha20-Poly1305)
  ↓ 密文存储
  ↑ 传输: TLS 1.3
  ↑ 内存: 短 GC
```

### 7.2 双钥匙机制

```bash
# 主钥匙 A(日常用)
~/.config/sops/age/key-a.txt
# 备份钥匙 B(物理 USB)
USB:/key-b-backup.txt

# 加密:双钥匙都参与
sops --encrypt --age age1A... --age age1B... secrets.yaml

# 解密:任一即可
# → 主服务器用 A
# → 恢复时用 B(USB 物理访问)
```

### 7.3 数据库(无 broker 自身的 DB)

- broker 不依赖外部 DB
- 所有数据在 SOPS 加密的 YAML/JSON 文件
- 审计日志是 JSONL append-only(无 DB)

### 7.4 内存安全

- **不 swap**:`MemoryDenyWrite=true` (systemd)
- **不 core dump**:`LimitCORE=0`
- **随机布局**:`Personality=random`
- **GC 立即清**:secret value 用后立即置 null
- **HSTS + CSP** (dashboard)

---

## 8. 审计与告警

### 8.1 审计事件分类

| 类别 | 事件 | 频率 |
|---|---|---|
| **认证** | login / login_mfa / logout / totp_setup / webauthn_register | 中 |
| **凭据访问** | resolve / proxy / exec | 高 |
| **管理** | secret_create / secret_update / secret_delete / service_create | 低 |
| **证书** | cert_issue / cert_rotate / cert_revoke | 低 |
| **API Key** | key_create / key_revoke / key_use | 中 |
| **错误** | auth_fail / mfa_fail / rate_limit / upstream_error | 中 |
| **系统** | config_reload / broker_start / broker_stop | 极低 |

### 8.2 告警规则

```yaml
# broker.yaml
alerting:
  rules:
    - name: secret_expired
      condition: secret.healthcheck.status == 'expired'
      severity: critical
      actions: [slack_alerts, email_admin]

    - name: secret_expiring_soon
      condition: secret.expires_in_days < 14
      severity: warning
      actions: [slack_alerts]

    - name: mfa_fail_threshold
      condition: auth.mfa_fail_count_5min > 5
      severity: high
      actions: [slack_alerts, lock_account]

    - name: rate_limit_exceeded
      condition: rate_limit.exceeded_count_1h > 100
      severity: medium
      actions: [slack_alerts]

    - name: cert_expiring_soon
      condition: cert.expires_in_days < 7
      severity: warning
      actions: [slack_alerts, email_owner]

    - name: admin_login_unusual
      condition: admin.login + risk_score > 60
      severity: critical
      actions: [slack_alerts, require_2fa]

    - name: upstream_5xx
      condition: upstream.status_5xx_count_5min > 10
      severity: medium
      actions: [slack_alerts]

    - name: broker_unhealthy
      condition: health.status != 'ok'
      severity: critical
      actions: [pagerduty, slack_alerts]
```

### 8.3 告警降噪

- **聚合**:同源 5 分钟内告警合并
- **抑制**:已知维护窗口不告警
- **静默**:acknowledged 告警不重复
- **分级**:critical / high / medium / warning

---

## 9. 应急响应 (IR)

### 9.1 事件分级

| 级别 | 示例 | 响应 SLA |
|---|---|---|
| **P0** | broker 服务器被攻陷 | 15 分钟 |
| **P1** | cert/key 泄露 | 1 小时 |
| **P2** | 凭据误用 | 4 小时 |
| **P3** | 异常登录尝试 | 24 小时 |

### 9.2 应急剧本

#### IR-1: Client cert 丢失

```bash
# 1. 立即撤销
ssh broker
scripts/broker/revoke-cert.ps1 -Fingerprint <fp>

# 2. 重新签发(可选,新设备)
scripts/broker/issue-client-cert.ps1 -CN client.newlaptop -Role developer

# 3. broker 热加载 CRL
curl -X POST -H "Authorization: Bearer $RELOAD_TOKEN" https://broker:8443/api/v1/admin/reload

# 4. 通知
# → Slack: "client.oldlaptop cert revoked at <ts>"

# 5. 审计
# 自动: action=cert_revoke, fp, reason, by
```

#### IR-2: API Key 泄露

```bash
# 1. 立即 revoke
secret-broker keys revoke <id> --reason "leaked on twitter"

# 2. 找泄露源
secret-broker audit list --action api_key_use --cn client.test --since 1d
# → 看 IP/UA 异常

# 3. 重新签发(可选)
secret-broker keys create --name "client.test-v2"

# 4. 通知 + audit
# 自动
```

#### IR-3: Secret value 泄露

```bash
# 1. 立即 rotate
secret-broker secrets rotate github.pat --reason "leaked"

# 2. 强制所有 session 失效
curl -X POST https://broker:8443/api/v1/admin/force-logout-all

# 3. 验证新值生效
secret-broker healthcheck run

# 4. 通知
# → Slack: "github.pat rotated, reason: leaked"
# → 旧 PAT 在 GitHub 端 disable
```

#### IR-4: Broker 服务器被攻陷

```bash
# 1. 立即停 broker
ssh broker "systemctl stop secret-broker"

# 2. 隔离网络
# → 阿里云安全组 deny 0.0.0.0
# → 切到腾讯云备

# 3. 评估损失
#   age 私钥是否泄露?
#   CA 私钥是否泄露?
#   audit log 是否被改?

# 4. 重建
#   新服务器
#   新 CA + 重发所有 cert
#   导入 SOPS 加密文件(用备份 B key)
#   重启服务

# 5. 通知用户
#   "broker 已迁移,所有 client cert 需重新签发"

# 6. 后审查
#   root cause 分析
#   timeline 复盘
#   修复 + 文档化
```

#### IR-5: AI 越权尝试

```bash
# audit 检测
secret-broker audit list --cn client.test --since 1h | grep -i "denied"

# 例:
# 2026-09-01 07:00:01 proxy  denied  service=admin    client.test
# 2026-09-01 07:00:02 secrets denied  name=*         client.test

# 1. 立即 lock account
secret-broker admin lock --cn client.test --reason "privilege_escalation_attempt"

# 2. revoke cert + API key
secret-broker pki revoke --fingerprint <fp>
secret-broker keys revoke <id>

# 3. 调查
# → IP/UA 记录
# → 通知合法用户
```

### 9.3 工具准备

```yaml
# IR 工具箱
ir_tools:
  - scripts/ir/revoke-all.sh          # 一键撤销所有 cert + key
  - scripts/ir/rotate-all.sh         # 一键 rotate 所有 secret
  - scripts/ir/backup-now.sh         # 立即备份
  - scripts/ir/dump-audit.sh         # 导出全量 audit
  - scripts/ir/verify-integrity.sh   # 验证 broker 完整性
  - docs/IR-PLAYBOOK.md              # 详细剧本
```

---

## 10. 合规与认证

### 10.1 标准对照

| 标准 | 满足项 | broker 实施 |
|---|---|---|
| **等保 2.0 三级** | 身份鉴别 / 访问控制 / 安全审计 / 入侵防范 | 6 因子 + ACL + JSONL audit + mTLS |
| **SOC 2 Type II** | CC6.1 (访问控制) CC7.2 (监控) | RBAC + alert + audit |
| **ISO 27001** | A.9 (访问控制) A.12 (运维) | full coverage |
| **GDPR** | 最小化收集 | broker 不收集用户 PII(只有 cert 指纹) |
| **HIPAA**(医疗) | PHI 保护 | 0 数据落地;proxy 模式不存任何响应 |

### 10.2 合规 checklist

- [x] 强制 mTLS
- [x] 6 因子认证
- [x] 100% 审计(JSONL, 7 年保留)
- [x] 凭据加密(SOPS+age)
- [x] 短命凭证(API Key 24h, child 1h)
- [x] 最小权限(ACL)
- [x] 凭据零接触(proxy/exec 模式)
- [x] 自动 rotate + 告警
- [x] 应急响应剧本
- [x] 备份 + 异地(主 A + USB B)

---

## 11. 安全测试

### 11.1 必测项

| 类别 | 测试 | 工具 |
|---|---|---|
| **静态分析** | 代码 lint + secret scan | ESLint / gitleaks / Snyk |
| **依赖审计** | npm audit / cargo audit | `npm audit` |
| **DAST** | OWASP ZAP 扫 broker | OWASP ZAP |
| **SAST** | 静态应用安全测试 | SonarQube / CodeQL |
| **密钥扫描** | git 历史查泄漏 | gitleaks / trufflehog |
| **配置审计** | broker.yaml / Docker | CIS Benchmarks |
| **渗透测试** | 模拟攻击者 | 第三方 |
| **红队** | 高级持续威胁演练 | 内部/外部 |

### 11.2 CI 安全检查

```yaml
# .github/workflows/security.yml
on: [push, pull_request]
jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: gitleaks/gitleaks-action@v2

  npm-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm audit --audit-level=high

  owasp-zap:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker compose up -d broker
      - run: sleep 5
      - run: zap-baseline.py -t https://localhost:8443 -r zap-report.html

  dependency-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
```

### 11.3 定期审计

- **每周**:npm audit + 自动安全补丁
- **每月**:第三方漏洞扫描 + 配置审计
- **每季**:渗透测试
- **每年**:SOC 2 Type II 审计(可选)

---

## 12. 持续改进

### 12.1 安全指标

```promql
# 关键 SLI/SLO
auth_login_success_rate 5m
secret_healthcheck_ok_rate 5m
proxy_429_rate 5m
cert_expiring_within_30d_count

# SLO
- 认证可用性: ≥ 99.9%
- 凭据健康: ≥ 95%(允许 5% expired/等 rotate)
- API 错误率: < 1%
- 90 天 cert 到期: < 5 个
```

### 12.2 威胁情报

- 订阅 [NIST NVD](https://nvd.nist.gov/) / [GitHub Advisory](https://github.com/advisories)
- 监控 0-day(deps 升级 ≤ 24h)
- 季度 threat model 复审

### 12.3 学习与培训

- 用户:每季度安全培训(钓鱼/密码/2FA)
- 开发者:OWASP Top 10 / SANS Top 25
- 运维:应急响应演练(每年 1+ 次)

### 12.4 Roadmap 安全增强

- [ ] WebAuthn 强制(2026 Q4)
- [ ] KMS 集成(用户自管,broker 只读)(2027 Q1)
- [ ] 量子安全签名(ML-DSA / PQC)(2027+)
- [ ] Zero-Trust 评估(FedRAMP / NIST 800-207)
- [ ] Bug Bounty 计划(2027+)

---

## 附录 A:OWASP Top 10 防护矩阵

| OWASP 风险 | broker 缓解 |
|---|---|
| **A01 Broken Access Control** | mTLS + ACL 显式 + 6 因子 + 2 因子 admin |
| **A02 Cryptographic Failures** | TLS 1.3 + SOPS+age + scrypt + 密钥长度 ≥ 2048 |
| **A03 Injection** | 输入验证 + path 白名单 + headers 黑名单 |
| **A04 Insecure Design** | 零信任 + 威胁建模 + STRIDE |
| **A05 Security Misconfig** | Docker hardening + no-new-privileges + read-only rootfs |
| **A06 Vulnerable Components** | 最小依赖 + lockfile + npm audit + 自动更新 |
| **A07 Auth Failures** | 6 因子 + 锁定 + 风险评分 + session revoke |
| **A08 Data Integrity** | SOPS 加密 + git 签名 + CRL |
| **A09 Security Logging** | 100% JSONL audit + alert + 监控 |
| **A10 SSRF** | upstream 白名单 + path 校验 + 阻止内网 IP |

## 附录 B:NIST 800-53 控制项映射

| 控件 | broker 实施 |
|---|---|
| **AC-2 账户管理** | 显式 client 列表,role-based |
| **AC-3 访问执行** | ACL 默认 deny |
| **AC-6 最小权限** | allowed_proxy 显式 |
| **AU-2 审计事件** | 100% JSONL |
| **AU-9 审计信息保护** | append-only + 7 年 |
| **IA-2 身份认证** | 6 因子 |
| **IA-5 认证管理** | scrypt + WebAuthn + 风险评分 |
| **SC-8 传输保密** | TLS 1.3 |
| **SC-13 密码学使用** | SOPS+age(ChaCha20-Poly1305) |
| **SI-4 信息监控** | Prometheus + alert |

## 附录 C:安全事件 runbook 索引

| 事件 | 文档 |
|---|---|
| cert 丢失 | IR-1 |
| API Key 泄露 | IR-2 |
| Secret value 泄露 | IR-3 |
| broker 服务器被攻陷 | IR-4 |
| AI 越权 | IR-5 |
| DDoS | RUNBOOK § 5.4 |
| 数据篡改 | RUNBOOK § 5.5 |
| 备份恢复 | RUNBOOK § 5.6 |

---

**作者**:Mavis (AI 架构助手) + 脱永军 (项目所有者)
**最后更新**:2026-09-01
**版本**:V4.0-SECURITY-MODEL
