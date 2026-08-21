# Phase A — server.js 接线清单（5 处外科手术）

分支 `optimize/phase-a-hardening` 已完成：

- `broker/package.json` → `3.2.0`
- `broker/version.js`（单一版本源）
- `broker/lib/ip-allowlist.js` + `isClientIpAllowed` in `api-keys.js`
- `cert-issuer` 默认 **90 天**
- `broker-test/test-ip-allowlist.js`
- **`scripts/broker/apply-phase-a-server-wire.mjs`** — 一键完成下面 5 处改动

---

## 一键应用（推荐）

在仓库根目录：

```bash
node scripts/broker/apply-phase-a-server-wire.mjs
node broker-test/test-ip-allowlist.js
# 以及现有套件回归
```

脚本幂等，可重复执行。

---

## 手工改动对照（若不用脚本）

### 1. 导入

在 `api-keys.js` 的 import 块中增加 `isClientIpAllowed`，并：

```js
import { BROKER_VERSION } from './version.js';
```

### 2. 启动 banner

```js
console.log(`  Secret Broker v${BROKER_VERSION}`);
```

### 3. 所有 `X-Broker-Version` / health version / User-Agent

| 旧 | 新 |
|----|----|
| `'X-Broker-Version': '2.0.0'` | `'X-Broker-Version': BROKER_VERSION` |
| `version: '2.0.0'`（`/health`） | `version: BROKER_VERSION` |
| `'User-Agent': 'secret-broker/2.0'` | `` 'User-Agent': `secret-broker/${BROKER_VERSION}` `` |

### 4. issueAndPersist 默认天数

```js
const cert = await issueClientCert(name); // DEFAULT_CERT_DAYS = 90
```

### 5. API Key IP 白名单（`getApiKeyIdentity`）

在 `findApiKey` 成功之后、`rateLimitApiKey` 之前插入 `isClientIpAllowed` 检查（见脚本）。

### 6. 删除死代码

`GET /api/v1/secrets` 非 admin 分支末尾重复 `return` 删掉。

---

合并后在本地跑全量测试，再 merge 到 `master`。
