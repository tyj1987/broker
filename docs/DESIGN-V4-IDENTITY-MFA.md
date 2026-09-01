# Secret Broker V4 — Identity & MFA Design

> **本文档**:V4 身份认证与多因素验证的完整设计
> **基础**:v3.0 TOTP + v3.2 IP 白名单 + v3.5 session/cookie
> **新增**:WebAuthn / SMS / Recovery / 风险评分 / MFA Policy
> **目标**:**"全方位身份验证"** — 6 种因子叠加,按风险动态要求

---

## 目录

1. [设计目标](#1-设计目标)
2. [6 种认证因子](#2-6-种认证因子)
3. [登录状态机](#3-登录状态机)
4. [MFA Policy 引擎](#4-mfa-policy-引擎)
5. [风险评分算法](#5-风险评分算法)
6. [会话生命周期](#6-会话生命周期)
7. [凭证生命周期](#7-凭证生命周期)
8. [API 端点(完整)](#8-api-端点完整)
9. [客户端实现](#9-客户端实现)
10. [测试矩阵](#10-测试矩阵)
11. [兼容性与迁移](#11-兼容性与迁移)

---

## 1. 设计目标

### 1.1 必须满足

| 目标 | 验收 |
|---|---|
| **6 种认证因子** | mTLS / Password / TOTP / WebAuthn / SMS / Recovery 全部可用 |
| **风险评分自适应** | 1-2 因子 (低风险) 到 2-3 因子 (高风险) 动态切换 |
| **零明文日志** | 任何凭证字段(password / totp / webauthn challenge)不进 audit |
| **离线恢复** | 用户丢失 TOTP 设备后能用 recovery code / SMS 找回 |
| **设备绑定** | 单一 mTLS cert = 单一设备,丢失秒级 revoke |
| **跨场景登录** | 同账号在 笔记本 / 桌面 / 手机 / CI runner / Web 都能用 |
| **可插拔** | 新因子(如 future 数字身份证)通过 provider 接口即可加入 |

### 1.2 与 v3 的差异

| 项 | v3.8 | V4 |
|---|---|---|
| 二验因子 | TOTP only | TOTP + WebAuthn + SMS + Recovery |
| 风险评分 | 无 | 5 维评分,动态决定因子要求 |
| SMS 验证 | 无 | 完整实现 + 可插拔 provider |
| WebAuthn | 无 | 完整实现(YubiKey / Touch ID / Windows Hello) |
| 凭据恢复 | recovery code | + SMS + 邮箱 + admin 紧急恢复 |
| 跨设备 | mTLS 一证一设备 | mTLS + Browser passkey + WebAuthn 多设备 |

---

## 2. 6 种认证因子

### 2.1 因子清单

| ID | 名称 | 强度 | 用户体验 | 部署成本 | 推荐度 |
|---|---|---|---|---|---|
| `mtls` | mTLS 客户端证书 | **强 (设备绑定)** | 无感(已签发) | 一次性 | ⭐⭐⭐⭐⭐ 主认证 |
| `password` | 密码(scrypt hash) | 中 | 输密码 | 0 | ⭐⭐⭐⭐ 主认证 / 紧急 |
| `totp` | TOTP (RFC 6238) | **强 (时间窗 ±1)** | 输 6 位码 | 装 App | ⭐⭐⭐⭐⭐ 二验 |
| `webauthn` | FIDO2 / Passkey | **强 (防钓鱼)** | 指纹/USB Key | 0(浏览器) | ⭐⭐⭐⭐⭐ 二验 |
| `sms` | SMS 验证码 | 中(易劫持) | 收短信 | 部署网关 | ⭐⭐ 兜底 |
| `recovery` | 一次性恢复码 | 弱(单次) | 输 8 位 | 0 | ⭐⭐⭐⭐ 应急 |

### 2.2 因子组合矩阵

V4 推荐组合(由 `MFA Policy` 决策):

| 场景 | 主认证 | 二验 | 强度 |
|---|---|---|---|
| **日常 mTLS 登录(同设备)** | mTLS | (跳过) | 中 |
| **日常 mTLS 登录(30 天后)** | mTLS | TOTP | 强 |
| **Web 登录(浏览器)** | Password | TOTP | 强 |
| **Web 登录(新设备)** | Password | TOTP + WebAuthn | 强+ |
| **敏感操作**(rotate cert / delete secret) | mTLS | WebAuthn | 强+ |
| **丢失 TOTP 设备** | mTLS | Recovery Code | 中 |
| **彻底无设备** | Password | SMS + Recovery | 中 |

### 2.3 因子元数据 schema

```javascript
// broker/lib/factor-registry.js
export const FACTORS = {
  mtls: {
    type: 'mtls',
    label: 'Client Certificate (mTLS)',
    icon: '🔐',
    strength: 5,  // 1-5
    setup_required: false,  // 部署时即配置
    user_setup: false,
    description: 'Per-device X.509 certificate',
  },
  password: {
    type: 'password',
    label: 'Password (scrypt)',
    icon: '🔑',
    strength: 3,
    setup_required: false,
    user_setup: false,
    description: 'Master password hashed with scrypt(N=16384)',
  },
  totp: {
    type: 'totp',
    label: 'TOTP (Authenticator App)',
    icon: '📱',
    strength: 4,
    setup_required: true,
    user_setup: true,
    description: 'RFC 6238, 6 digits, 30s window ±1',
    setup_endpoint: '/api/v1/me/totp/setup',
    verify_endpoint: '/api/v1/me/totp/verify',
  },
  webauthn: {
    type: 'webauthn',
    label: 'Passkey / Security Key',
    icon: '🛡️',
    strength: 5,
    setup_required: true,
    user_setup: true,
    description: 'FIDO2 / WebAuthn (YubiKey, Touch ID, Windows Hello)',
    setup_endpoint: '/api/v1/me/webauthn/register/begin',
    verify_endpoint: '/api/v1/me/webauthn/register/finish',
  },
  sms: {
    type: 'sms',
    label: 'SMS Code',
    icon: '📨',
    strength: 2,
    setup_required: true,
    user_setup: true,
    description: 'One-time SMS code (requires SMS provider config)',
    setup_endpoint: '/api/v1/me/phone/set',
    verify_endpoint: '/api/v1/me/phone/verify',
  },
  recovery: {
    type: 'recovery',
    label: 'Recovery Code',
    icon: '🆘',
    strength: 2,
    setup_required: true,  // 启用 TOTP 时自动生成
    user_setup: false,
    description: '10 one-time codes, generated at TOTP setup',
  },
};
```

---

## 3. 登录状态机

V4 把 v3 的"PASSWORD_OK → MFA_REQUIRED → MFA_OK → SESSION"扩展为完整状态机。

### 3.1 状态图

```
                    ┌─────────────────┐
                    │   ANONYMOUS     │
                    │   (无凭据)      │
                    └────────┬────────┘
                             │
            ┌────────────────┼────────────────┐
            │                │                │
       mTLS 证书       Password (body)    (其他入口)
            │                │                │
            ▼                ▼                ▼
    ┌───────────────┐  ┌───────────────┐  ┌────────────┐
    │ CERT_VERIFIED │  │ PW_VERIFIED   │  │  ...       │
    │ (device+fp)   │  │ (user+role)   │  │            │
    └───────┬───────┘  └───────┬───────┘  └────────────┘
            │                  │
            └────────┬─────────┘
                     │
                     ▼
           ┌─────────────────┐
           │ PRIMARY_OK      │  ← ctx: client, role, fp
           │  (risk_score?)  │
           └────────┬────────┘
                    │
      ┌─────────────┼─────────────┐
      │             │             │
   score≤20      20<score≤60   score>60
      │             │             │
      ▼             ▼             ▼
  SESSION      MFA_REQUIRED   MFA_REQUIRED+
  (直接)       (TOTP or       (TOTP + WebAuthn,
                WebAuthn)     or 2FA combination)
                    │             │
                    ▼             ▼
           ┌────────────────────────────┐
           │  MFA_PENDING                │
           │  (5min TTL, single-use)     │
           └─────────────┬──────────────┘
                         │
                         ▼
                  ┌─────────────┐
                  │ MFA_OK      │
                  │ → SESSION   │
                  └─────────────┘
                         │
                         ▼
                  ┌─────────────┐
                  │ SESSION     │ ← ctx: client + session_token + cookie
                  │ (24h TTL)   │
                  └─────────────┘
```

### 3.2 端点清单

#### 3.2.1 主登录

| 端点 | 用途 |
|---|---|
| `POST /api/v1/login` | 密码登录(也可隐式 mTLS 登录) |
| `POST /api/v1/login/mfa` | TOTP / WebAuthn 完成二验 |
| `POST /api/v1/login/sms` | SMS 验证码完成二验(走 SMS provider) |
| `POST /api/v1/login/recovery` | Recovery Code 完成二验 |
| `POST /api/v1/logout` | 注销,清 session + cookie |

#### 3.2.2 mTLS 证书(已有,v3 完整)

| 端点 | 用途 |
|---|---|
| `GET /api/v1/identity` | 返回当前 cert 身份(mTLS) |
| `POST /api/v1/me/rotate-cert` | 自助 rotate 自己的 cert(需 TOTP) |

#### 3.2.3 TOTP 生命周期(已有 v3,V4 增强)

| 端点 | 用途 |
|---|---|
| `POST /api/v1/me/totp/setup` | 开始 setup,返回 otpauth:// + base32 secret |
| `POST /api/v1/me/totp/verify` | 验证用户输入的 6 位码,启用 TOTP |
| `POST /api/v1/me/totp/disable` | 禁用 TOTP(需已 verify TOTP) |
| `POST /api/v1/me/totp/regen-recovery` | 重新生成 10 个 recovery code(需 TOTP) |
| `GET  /api/v1/me/recovery-codes/remaining` | 看还剩几个 |

#### 3.2.4 WebAuthn (V4 新增)

| 端点 | 用途 |
|---|---|
| `POST /api/v1/me/webauthn/register/begin` | 开始注册,返回 challenge + options |
| `POST /api/v1/me/webauthn/register/finish` | 完成注册,存公钥 |
| `POST /api/v1/me/webauthn/authenticate/begin` | 开始登录,返回 challenge |
| `POST /api/v1/me/webauthn/authenticate/finish` | 完成登录,验证签名 |
| `GET  /api/v1/me/webauthn/credentials` | 列出已注册凭据 |
| `DELETE /api/v1/me/webauthn/credentials/:id` | 删除某个凭据(需二验) |

#### 3.2.5 SMS (V4 新增)

| 端点 | 用途 |
|---|---|
| `POST /api/v1/me/phone/set` | 设置手机号(发短信验证) |
| `POST /api/v1/me/phone/verify` | 验证短信,完成手机号绑定 |
| `POST /api/v1/me/phone/remove` | 解绑 |
| `GET  /api/v1/login/sms/challenge` | 登录时发短信 |
| `POST /api/v1/login/sms` | 提交短信码完成登录 |

#### 3.2.6 Recovery (V4 增强)

| 端点 | 用途 |
|---|---|
| `POST /api/v1/login/recovery` | 提交 recovery code,二验通过 |
| `POST /api/v1/admin/emergency/recover` | admin 紧急为用户重置二验(需双 admin 二次确认) |

### 3.3 MFA Pending 状态存储

```javascript
// broker/auth-flow.js (V4 增强)
const MFA_PENDING = new Map();
// key: mfa_token
// value: {
//   clientName: 'tyj',
//   fp: 'AB:CD:...',           // mTLS fingerprint (可能为空)
//   primary_method: 'password',  // 或 'mtls'
//   factors_required: ['totp', 'webauthn'],
//   factors_verified: [],         // 已验证的因子
//   createdAt: Date.now(),
//   used: false,
// }

const MFA_TOKEN_TTL_MS = 5 * 60 * 1000;  // 5 分钟
```

---

## 4. MFA Policy 引擎

### 4.1 配置文件位置

```yaml
# secrets/broker.yaml
mfa_policy:
  # 全局默认:每种角色要求哪些因子
  default_policy:
    developer:
      primary: [mtls, password]      # 至少 1 个
      secondary_required_when: [unusual_ip, no_mtls, sensitive_action]
      secondary_options: [totp, webauthn, sms]
      secondary_min_count: 1

    admin:
      primary: [mtls, password]
      secondary_required_when: [always]  # admin 永远要二验
      secondary_options: [totp, webauthn]
      secondary_min_count: 1

    ci:  # CI runner
      primary: [mtls]                  # 机器只用 cert
      secondary_required_when: []
      secondary_min_count: 0

  # 风险评分阈值(决定二验是否需要)
  risk_score_thresholds:
    no_mfa: 20          # ≤20 不需要二验
    require_one: 60     # 21-60 要 1 个二验
    require_two: 100    # 61-100 要 2 个二验(强二验)

  # 敏感操作列表(强制二验)
  sensitive_actions:
    - rotate-cert
    - delete-secret
    - revoke-api-key
    - admin:reload
    - change-password
    - change-phone
    - disable-totp
    - add-webauthn
```

### 4.2 Policy 决策函数

```javascript
// broker/lib/mfa-policy.js
export function decideMfaRequirement(ctx) {
  const policy = loadMfaPolicy();
  const clientPolicy = policy.default_policy[ctx.client.role] || policy.default_policy.developer;
  const score = calcRiskScore(ctx);

  // 1. 敏感操作强制二验
  if (ctx.action && policy.sensitive_actions.includes(ctx.action)) {
    return {
      mfa_required: true,
      min_count: 1,
      options: clientPolicy.secondary_options,
      reason: 'sensitive_action',
    };
  }

  // 2. 角色级 always 要求
  if (clientPolicy.secondary_required_when.includes('always')) {
    return {
      mfa_required: true,
      min_count: clientPolicy.secondary_min_count,
      options: clientPolicy.secondary_options,
      reason: 'role_admin_always',
    };
  }

  // 3. 风险评分决定
  const t = policy.risk_score_thresholds;
  if (score <= t.no_mfa) {
    return { mfa_required: false, min_count: 0, options: [], reason: 'low_risk' };
  } else if (score <= t.require_one) {
    return {
      mfa_required: true,
      min_count: 1,
      options: clientPolicy.secondary_options,
      reason: 'medium_risk',
    };
  } else {
    return {
      mfa_required: true,
      min_count: 2,
      options: clientPolicy.secondary_options,
      reason: 'high_risk',
    };
  }
}
```

### 4.3 多因子验证流(MFA_REQUIRED+)

当 min_count=2 时:

```json
// POST /api/v1/login 响应
{
  "ok": false,
  "mfa_required": true,
  "mfa_token": "uuid-...",
  "factors_required": 2,
  "factors_remaining": 2,
  "factors_verified": [],
  "factors_available": [
    { "id": "totp", "label": "TOTP" },
    { "id": "webauthn", "label": "Passkey" }
  ],
  "expires_in": 300
}
```

用户依次提交多个因子(任一顺序):

```json
// POST /api/v1/login/mfa { mfa_token, factor: "totp", code: "123456" }
// → 200: factors_remaining: 1, factors_verified: ["totp"]
// POST /api/v1/login/mfa { mfa_token, factor: "webauthn", credential: {...} }
// → 200: factors_remaining: 0 → 返回 session
```

---

## 5. 风险评分算法

### 5.1 5 维评分

```javascript
// broker/lib/risk-score.js
export function calcRiskScore(ctx) {
  let score = 0;
  const factors = [];

  // 维度 1: IP 不在白名单
  if (ctx.source_ip) {
    const isAllowed = isIpAllowed(ctx.client.ip_whitelist, ctx.source_ip);
    if (!isAllowed) {
      score += 30;
      factors.push('unusual_ip');
    }
  }

  // 维度 2: 长期未登录(>30 天)
  if (ctx.last_login_at) {
    const daysSince = (Date.now() - ctx.last_login_at) / 86400_000;
    if (daysSince > 30) {
      score += 20;
      factors.push('stale_account');
    } else if (daysSince > 7) {
      score += 10;
    }
  }

  // 维度 3: 敏感操作
  if (ctx.action && SENSITIVE_ACTIONS.has(ctx.action)) {
    score += 25;
    factors.push('sensitive_action');
  }

  // 维度 4: 时间异常(深夜 0-6 点)
  const hour = new Date().getHours();
  if (hour < 6 || hour >= 23) {
    score += 10;
    factors.push('unusual_hour');
  }

  // 维度 5: User-Agent 改变(浏览器登录)
  if (ctx.user_agent && ctx.last_user_agent &&
      ctx.user_agent !== ctx.last_user_agent) {
    score += 15;
    factors.push('user_agent_changed');
  }

  return { score, factors };
}
```

### 5.2 评分调试端点

```http
GET /api/v1/me/risk-score
Authorization: Bearer mb_live_xxx
X-Forwarded-For: 8.8.8.8

→ 200:
{
  "score": 45,
  "max": 100,
  "factors": ["unusual_ip", "unusual_hour"],
  "threshold_no_mfa": 20,
  "threshold_one": 60,
  "result": "medium_risk → require 1 factor"
}
```

---

## 6. 会话生命周期

### 6.1 Session 创建(继承 v3.5 + V4 增强)

```javascript
// broker/lib/session.js
function makeSession({ cn, fp, role, clientName, cert, mfa_methods, ip, ua, login_method }) {
  return {
    token: randomUUID(),
    cn, fp, role, clientName,
    mfa_methods: mfa_methods || [],  // ['totp', 'webauthn']
    cert_subject: cert?.subject?.CN,
    created_at: Date.now(),
    expires_at: Date.now() + SESSION_TTL_MS,
    last_seen_at: Date.now(),
    last_seen_ip: ip,
    last_seen_ua: ua,
    login_method,  // 'mtls' | 'password' | 'webauthn' | 'sso'
    mfa_factors_count: mfa_methods?.length || 0,
  };
}
```

### 6.2 Session TTL 分级

| 场景 | TTL | 依据 |
|---|---|---|
| **mTLS + 0 因子** | 4h | 机器短期 |
| **mTLS + 1 因子 (TOTP)** | 24h | 日常 |
| **mTLS + 2 因子** | 7d | 强认证 |
| **Password + 1 因子** | 8h | Web 登录 |
| **Password + 2 因子** | 24h | Web 强认证 |
| **敏感操作 session** | 15min | 临时 |

```javascript
function sessionTtlFor(ctx) {
  const mfa = ctx.mfa_factors_count;
  const m = ctx.login_method;
  if (m === 'mtls' && mfa === 0) return 4 * 3600_000;
  if (m === 'mtls' && mfa === 1) return 24 * 3600_000;
  if (m === 'mtls' && mfa >= 2) return 7 * 24 * 3600_000;
  if (m === 'password' && mfa === 1) return 8 * 3600_000;
  if (m === 'password' && mfa >= 2) return 24 * 3600_000;
  return 1 * 3600_000;  // 默认
}
```

### 6.3 Session 续期

```javascript
// 每次请求滑动续期
function touchSession(session) {
  session.last_seen_at = Date.now();
  // 续期到 50% TTL(防抖)
  const elapsed = Date.now() - session.created_at;
  const halfTtl = (session.expires_at - session.created_at) / 2;
  if (elapsed > halfTtl) {
    session.expires_at = Date.now() + (session.expires_at - session.created_at);
  }
}
```

### 6.4 Session 撤销

| 触发 | 动作 |
|---|---|
| 用户 logout | 删除 session + 清 cookie |
| rotate cert | 撤销该 client 全部 session |
| 密码改了 | 撤销除当前 session 外的全部 |
| 检测到异常 | 立即撤销 |
| TTL 到期 | 后台 GC |

---

## 7. 凭证生命周期

### 7.1 全部凭证一览

| 凭证 | 创建 | 验证 | 轮换 | 销毁 |
|---|---|---|---|---|
| **mTLS cert** | `issue-client-cert.ps1` | TLS handshake | `rotate-cert.ps1` (90 天) | `revoke-cert.ps1` → CRL |
| **Password** | Dashboard / CLI | scrypt verify | 用户改 | 撤销 session |
| **TOTP secret** | `POST /me/totp/setup` | RFC 6238 verify | 重 setup | 禁用 → 清 secret |
| **WebAuthn cred** | `POST /me/webauthn/register/finish` | 椭圆曲线签名 | 不轮换(公钥不变) | `DELETE /me/webauthn/credentials/:id` |
| **SMS phone** | `POST /me/phone/set` | 短信码 verify | 不轮换 | `POST /me/phone/remove` |
| **Recovery code** | TOTP setup 时自动生成 | SHA-256 hash 匹配 | 重 setup 时重新生成 | 用过即删 |
| **API Key** | Dashboard | SHA-256 hash 匹配 | revoke + reissue | revoke |
| **API Key (master)** | Dashboard (TOTP 必) | SHA-256 hash 匹配 | 30d TTL | revoke |
| **API Key (child)** | master 创建 | 同上 | 1h TTL 自动 expire | TTL 到期 |

### 7.2 轮换流程

```
cert / password / TOTP / API Key 轮换流程:

1. 触发 (到期/手动/告警)
2. 生成新凭证
3. 双重验证 (旧+新)
4. 更新 broker.yaml
5. reload broker
6. 撤销旧凭证
7. 通知 (Slack/email/webhook)
8. 审计 (action: 'rotate', success/fail)
```

### 7.3 90 天强制 cert 轮换(V3 已有,V4 强化)

```bash
# cron 每日检查
0 4 * * * /opt/secret-broker/scripts/check-cert-expiry.sh
# → 接近 90 天:发邮件
# → 接近 90 天(剩余 7 天):发 Slack
# → 超过 90 天:cert 自动吊销
```

---

## 8. API 端点(完整)

### 8.1 公开端点(无需认证)

| 端点 | 用途 |
|---|---|
| `GET /health` | 健康检查 |
| `GET /ready` | 就绪(检查依赖) |
| `GET /metrics` | Prometheus 指标 |
| `GET /` | Dashboard 静态 |
| `GET /api/v1/login` | 登录页面(GET 显示 form) |
| `POST /api/v1/login` | 密码登录 |
| `POST /api/v1/login/sms/challenge` | 触发短信 |

### 8.2 半公开(mTLS 或 session)

| 端点 | 用途 |
|---|---|
| `GET /api/v1/identity` | 返回当前身份 |
| `GET /api/v1/me` | 个人信息 |
| `POST /api/v1/me/change-password` | 改密码(需已 login) |
| `POST /api/v1/me/totp/setup` | 开始 TOTP setup |
| `POST /api/v1/me/totp/verify` | 完成 TOTP setup |
| `POST /api/v1/me/webauthn/register/begin` | 开始 WebAuthn |
| `GET  /api/v1/me/webauthn/credentials` | 列出 webauthn creds |

### 8.3 已认证(session/cookie)

| 端点 | 用途 |
|---|---|
| `GET /api/v1/secrets` | 列出可见 secrets |
| `POST /api/v1/secrets/resolve` | resolve(强审计) |
| `POST /api/v1/proxy/:service` | proxy(主流) |
| `GET /api/v1/services` | 列出可见 services |
| `GET /api/v1/me/audit` | 看自己活动 |
| `POST /api/v1/api-keys` | 创建 API Key |
| `GET  /api/v1/api-keys` | 列出 API Keys |
| `DELETE /api/v1/api-keys/:id` | revoke |

### 8.4 Admin(role=admin)

| 端点 | 用途 |
|---|---|
| `GET /api/v1/admin/secrets` | 全部 secrets |
| `POST /api/v1/admin/secrets` | 创建 secret |
| `POST /api/v1/admin/services` | 创建 service |
| `GET /api/v1/admin/clients` | 全部 clients |
| `GET /api/v1/admin/audit` | 全局 audit |
| `POST /api/v1/admin/reload` | 热加载配置(需 2 因子) |
| `POST /api/v1/admin/emergency/recover` | 紧急恢复(双 admin 确认) |

---

## 9. 客户端实现

### 9.1 CLI:secret-broker login

```bash
# 交互式登录
secret-broker login
# 输出:
#   选择认证方式:
#     1. mTLS (推荐,如果你有 cert)
#     2. Password + TOTP
#     3. Password + WebAuthn
#     4. Password + SMS
#   > 2
#
#   Password: ********
#   TOTP Code: 123456
#
#   ✓ Login successful
#     Session token: mb_session_xxxxx (saved to ~/.broker/session)
#     Expires: 2026-09-02 07:06:35 (24h)
#     Identity: client.tyj-laptop (developer)
#     MFA methods used: password + totp

# 非交互式(脚本)
secret-broker login --user tyj --password-stdin --totp-stdin

# WebAuthn 模式
secret-broker login --webauthn
# 触发浏览器 prompt(Touch ID / YubiKey)

# SMS 模式
secret-broker login --sms
# → 提示输入手机号
# → 输入验证码

# Recovery mode
secret-broker login --recovery
# → 输入 8 位恢复码
```

### 9.2 WebAuthn 浏览器流程

```
1. 用户在 Dashboard 输入密码
2. → 200: { mfa_token, options: { webauthn: { challenge, rpId, allowCredentials } } }
3. 浏览器调用 navigator.credentials.get()
4. 用户触摸 YubiKey / 指纹
5. 浏览器返回 credential (签名 + challenge)
6. → POST /api/v1/login/mfa { mfa_token, factor: 'webauthn', credential }
7. broker 验证签名
8. → 200: session
```

### 9.3 MCP 工具扩展(V4)

新增 2 个工具:

```json
{
  "name": "list_mfa_factors",
  "description": "列出当前 client 的可用 MFA 因子",
  "inputSchema": { "type": "object", "properties": {} }
}

{
  "name": "enroll_webauthn",
  "description": "为当前 client 启用 WebAuthn 二验 (返回 challenge)",
  "inputSchema": {
    "type": "object",
    "properties": {
      "display_name": { "type": "string", "description": "Passkey 名称" }
    }
  }
}
```

---

## 10. 测试矩阵

### 10.1 必须通过的测试

| # | 测试名 | 覆盖 |
|---|---|---|
| 1 | `test-mfa-totp-basic` | TOTP 注册/验证/禁用 |
| 2 | `test-mfa-totp-window` | ±1 窗口,边界 30s |
| 3 | `test-mfa-webauthn-register` | 注册 challenge 验证 |
| 4 | `test-mfa-webauthn-authenticate` | 认证签名验证 |
| 5 | `test-mfa-sms-send` | 短信发送(可插拔 provider) |
| 6 | `test-mfa-sms-verify` | 短信码验证 |
| 7 | `test-mfa-recovery-code` | 恢复码用一次即删 |
| 8 | `test-risk-score-unusual-ip` | IP 异常 +30 |
| 9 | `test-risk-score-stale-account` | 30 天未登录 +20 |
| 10 | `test-risk-score-sensitive-action` | 敏感操作 +25 |
| 11 | `test-mfa-policy-1-factor` | mid 风险 1 因子 |
| 12 | `test-mfa-policy-2-factor` | high 风险 2 因子 |
| 13 | `test-mfa-policy-no-mfa` | low 风险 0 因子 |
| 14 | `test-mfa-policy-admin-always` | admin 永远 2 因子 |
| 15 | `test-session-ttl-tiered` | 4h/24h/7d 等级 |
| 16 | `test-session-touch-renewal` | 滑动续期 |
| 17 | `test-session-revocation` | 改密码撤销其他 session |
| 18 | `test-rotation-90d-cert` | cert 90 天到期自动 revoke |
| 19 | `test-rotation-api-key` | API Key 轮换 |
| 20 | `test-rotation-recovery-regen` | 重新生成恢复码 |
| 21 | `test-concurrent-mfa-pending` | 同一用户多端并发登录 |
| 22 | `test-mfa-fail-counter` | 5 次错误锁定 |
| 23 | `test-webauthn-fido-u2f-fallback` | 旧 U2F 设备兼容 |
| 24 | `test-sms-provider-pluggable` | 替换 SMS provider |
| 25 | `test-rate-limit-on-mfa-fail` | 防爆破 |

### 10.2 性能测试

- TOTP verify P95 < 50ms
- WebAuthn verify P95 < 100ms
- Risk score 计算 P95 < 5ms

---

## 11. 兼容性与迁移

### 11.1 v3 → V4 兼容

| v3 字段 | V4 等价 | 兼容策略 |
|---|---|---|
| `client.totp_secret` | `client.factors.totp.secret` | 读老字段,启动时 migrate |
| `client.totp_recovery_codes_hash` | `client.factors.totp.recovery_codes` | 同上 |
| `client.allow_password_login` | `client.factors.password.enabled` | 同上 |
| `client.mfa_required` | `mfa_policy.default_policy.<role>.secondary_required_when` | 整体升级 policy |
| `client.mtls.fingerprint` | `client.factors.mtls.fingerprints[]` | 升级为数组(多设备) |

### 11.2 一次性迁移脚本

```bash
# 升级时执行
secret-broker migrate v3-to-v4
# → 读 broker.yaml
# → 把 client.<name>.totp_secret → client.<name>.factors.totp.secret
# → 把 cert_fingerprint_sha256 → factors.mtls.fingerprints
# → 加 factors: { totp, recovery, webauthn, sms, mtls, password } 骨架
# → 写回(自动备份 .bak)
# → 输出迁移报告
```

### 11.3 旧 TOTP 恢复码保留

- 10 个老 recovery code 仍然有效(只是字段路径变了)
- 新 TOTP setup 时,老的会被废弃(自动生成新的 10 个)
- 用户应主动 verify 一次老 TOTP 触发 migration

---

## 附录 A:WebAuthn 注册流程详解

```javascript
// POST /api/v1/me/webauthn/register/begin
{
  "response": {
    "rp": { "name": "Secret Broker", "id": "broker.52trz.com" },
    "user": {
      "id": "tyj",  // base64(client.name)
      "name": "tyj",
      "displayName": "脱永军"
    },
    "challenge": "base64-random-32-bytes",
    "pubKeyCredParams": [
      { "type": "public-key", "alg": -7 },   // ES256
      { "type": "public-key", "alg": -257 }  // RS256
    ],
    "timeout": 60000,
    "excludeCredentials": [],  // 已注册的 cred ID 列表(防止重注册)
    "authenticatorSelection": {
      "residentKey": "preferred",
      "userVerification": "preferred"
    },
    "attestation": "direct"
  }
}

// 浏览器 navigator.credentials.create() 后 POST finish:
{
  "response": {
    "id": "base64-credential-id",
    "rawId": "base64-credential-id",
    "type": "public-key",
    "response": {
      "clientDataJSON": "base64",
      "attestationObject": "base64",  // 包含公钥 + 签名
      "transports": ["usb", "nfc"]
    },
    "clientExtensionResults": {}
  }
}

// broker 验证:
// 1. 解析 clientDataJSON(校验 type=create, challenge 匹配)
// 2. 解析 attestationObject(提取公钥 + AAGUID)
// 3. 验证 attestation 签名(可选,或 none 模式)
// 4. 存 client.factors.webauthn.credentials[]
// 5. 返 200 + credential_id
```

---

## 附录 B:SMS Provider 接口契约

```javascript
// broker/lib/sms-provider.js (V4)
export interface SmsProvider {
  name: string;
  // 发送短信验证码
  send(phone: string, code: string, opts?: object): Promise<{ message_id: string, cost?: number }>;
  // 查询发送状态(可选)
  query?(messageId: string): Promise<{ status: 'sent' | 'delivered' | 'failed' }>;
}

// 内置实现
export const aliyunSmsProvider: SmsProvider = { ... };
export const tencentSmsProvider: SmsProvider = { ... };
export const twilioSmsProvider: SmsProvider = { ... };

// 用户自定义
// broker.yaml:
sms:
  provider: my_custom_sms
  providers:
    my_custom_sms:
      type: webhook
      url: 'https://my-sms-gateway.com/send'
      auth: 'Bearer xyz'
```

---

## 附录 C:Recovery Code 格式

```
8 字符,字母+数字(去 0/O/1/I/L 防误读)
例:7K3M-9PXQ
```

生成:
```javascript
const RECOVERY_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 32 字符
const buf = crypto.randomBytes(8);
let s = '';
for (let i = 0; i < 8; i++) s += ALPHABET[buf[i] % 32];
return s.slice(0, 4) + '-' + s.slice(4);
```

存储:SHA-256 hash(去掉 - 后),用一次即删。

---

## 附录 D:与第三方 MFA 服务集成

### D.1 阿里云 MFA(可选)

```yaml
mfa:
  external_provider:
    type: aliyun_mfa
    access_key: '{{secret.aliyun_mfa_ak}}'
    region: cn-hangzhou
```

### D.2 Auth0 / Okta(可选)

```yaml
mfa:
  external_provider:
    type: auth0
    domain: 'broker.us.auth0.com'
    client_id: '...'
    client_secret: '{{secret.auth0_cs}}'
```

---

**作者**:Mavis (AI 架构助手) + 脱永军 (项目所有者)
**最后更新**:2026-09-01
**版本**:V4.0-IDENTITY-MFA
