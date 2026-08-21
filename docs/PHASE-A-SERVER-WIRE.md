# Phase A — server.js 接线清单（5 处外科手术）

分支 `optimize/phase-a-hardening` 已完成：

- `broker/package.json` → `3.2.0`
- `broker/version.js`（单一版本源）
- `broker/lib/ip-allowlist.js` + `isClientIpAllowed` in `api-keys.js`
- `cert-issuer` 默认 **90 天**
- `broker-test/test-ip-allowlist.js`

`server.js` 体量过大，为避免一次巨型 diff，请在合并前对 `broker/server.js` 做以下 5 处改动（均可独立验证）。

---

## 1. 导入

在 `api-keys.js` 的 import 块中增加：

```js
  isClientIpAllowed,
```

并增加：

```js
import { BROKER_VERSION } from './version.js';
```

## 2. 启动 banner

```js
console.log('  Secret Broker v2.0');
```

改为：

```js
console.log(`  Secret Broker v${BROKER_VERSION}`);
```

## 3. 所有 `X-Broker-Version` / health version / User-Agent

全局替换：

| 旧 | 新 |
|----|----|
| `'X-Broker-Version': '2.0.0'` | `'X-Broker-Version': BROKER_VERSION` |
| `version: '2.0.0'`（`/health`） | `version: BROKER_VERSION` |
| `'User-Agent': 'secret-broker/2.0'` | `` `User-Agent': `secret-broker/${BROKER_VERSION}` `` |

## 4. issueAndPersist 默认天数

```js
const cert = await issueClientCert(name, { days: 365 });
```

改为（与 cert-issuer 默认一致；也可省略 days）：

```js
const cert = await issueClientCert(name); // DEFAULT_CERT_DAYS = 90
```

## 5. API Key IP 白名单（`getApiKeyIdentity`）

在 `findApiKey` 成功之后、`rateLimitApiKey` 之前插入：

```js
  // v3.2: enforce ip_whitelist when set
  const remoteIp = req.socket?.remoteAddress
    || req.headers['x-forwarded-for']?.toString().split(',')[0]?.trim()
    || '';
  if (!isClientIpAllowed(k, remoteIp)) {
    audit({
      action: 'connect',
      status: 'denied',
      reason: 'api_key_ip_denied',
      cn: k.client,
      remote: remoteIp,
    });
    return null;
  }
```

## 6.（可选）删除死代码

`GET /api/v1/secrets` 非 admin 分支末尾有重复：

```js
    return send(res, 200, { secrets: out });
    return send(res, 200, { secrets: visible }); // 删除这一行
```

---

合并后在本地跑：

```bash
node broker-test/test-ip-allowlist.js
# 以及现有套件回归
```
