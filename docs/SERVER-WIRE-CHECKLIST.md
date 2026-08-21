# server.js 完整接线清单（Phase A–F / v3.8.0）

目标：在**不一次性重写 140KB 单体**的前提下，把已合并的 `lib/*` + `routes/*` 接到运行中的 `broker/server.js`。

当前仓库状态：
- 模块与测试已在 `master`（至 **3.8.0**）
- `server.js` 仍可能是未接线的 legacy 主体
- 幂等脚本：`scripts/broker/apply-phase-b2-server-wire.mjs` 等

---

## 0. 前置

```bash
git pull origin master
cd broker
npm run test:modular
```

在**仓库根目录**执行 wire 脚本（不是 `C:\Users\Administrator`）：

```bash
# 若尚未 clone：
# git clone https://github.com/tyj1987/sops-age-template.git
# cd sops-age-template

node scripts/broker/apply-phase-b2-server-wire.mjs
node scripts/broker/apply-phase-b4-server-wire.mjs
node scripts/broker/apply-phase-b5-cutover.mjs
```

脚本覆盖的自动化项见下文「脚本已做 / 需手写」。

---

## 1. Import 区（文件顶部）

在现有 `import` 之后增加（或确认脚本已写入）：

```js
import { BROKER_VERSION } from './version.js';
import { isClientIpAllowed } from './api-keys.js'; // 若已从 api-keys 解构，合并进同一 import

// Phase B routes
import {
  handleHealth,
  handleStatic,
  handleAuth,
  handleMe,
  handleSecrets,
  handleServices,
  handleClients,
  handleProxy,
  handleMetrics,
  handleOps,
  dispatch,
  PUBLIC_HANDLERS,
  API_HANDLERS,
} from './routes/index.js';

// Phase B–F lib
import {
  // optional replacements for inlined helpers (cutover 后删除本地副本):
  // send, readBody, jsonError, sopsDecrypt, sopsEncryptAtomic, buildZip,
  // createAudit, createRateLimiter, createSessionStore,
  buildRouteDeps,
  useModularRoutes,
  installGracefulShutdown,
  rejectIfShuttingDown,
  validateBrokerConfig,
  formatValidationReport,
  preflightPaths,
  withAuditSampling,
  pruneAuditFiles,
  auditPolicyFromEnv,
  runWithRequestContext,
  setResponseTraceHeaders,
  getRequestId,
  getTraceparent,
  outboundTraceHeaders,
  inc,
  observeMs,
  log,
  runProbes,
  probesFromConfig,
  buildBackupManifest,
} from './lib/index.js';

import {
  createMfaPending,
  getMfaPending,
  consumeMfaPending,
  verifyMfaCode,
  isMfaRequired,
  MFA_TOKEN_TTL_MS,
} from './auth-flow.js';
import { stopCronLoop, registerCron, startCronLoop } from './cron-tasks.js';
```

**脚本已做（B.2）**：`BROKER_VERSION`、`handleHealth`/`handleStatic`、`isClientIpAllowed`（部分）。  
**需手写**：C–F 全量 import、auth-flow / shutdown / probes 等。

---

## 2. Phase A — 加固（必须）

| # | 位置 | 动作 | 脚本 |
|---|------|------|------|
| A1 | 启动 banner | `Secret Broker v${BROKER_VERSION}` | B.2 ✅ |
| A2 | 响应头 | `'X-Broker-Version': BROKER_VERSION` | B.2 ✅ |
| A3 | `/health` JSON | `version: BROKER_VERSION` | B.2 ✅ |
| A4 | 上游 User-Agent | `` `secret-broker/${BROKER_VERSION}` `` | B.2 ✅ |
| A5 | `issueClientCert` | 去掉 `{ days: 365 }`，用默认 90 天 | B.2 ✅ |
| A6 | `getApiKeyIdentity` | `isClientIpAllowed` + audit deny | B.2 ✅ |
| A7 | secrets list | 删除死代码第二行 `return` | B.2 ✅ |

---

## 3. `handle()` 请求管道（推荐顺序）

把 `async function handle(req, res) { ... }` 改成如下骨架（保留其后 legacy 分支作回退）：

```js
async function handle(req, res) {
  return runWithRequestContext(req.headers, async () => {
    setResponseTraceHeaders(res);

    if (rejectIfShuttingDown(shuttingDown, res, jsonError)) return;

    const url = new URL(req.url, `https://${req.headers.host}`);
    const m = req.method;
    const p = url.pathname;
    const t0 = Date.now();
    const route = { method: m, pathname: p };

    // —— 公共模块路由（无需登录）——
    const publicDeps = {
      send,
      jsonError,
      readBody,
      version: BROKER_VERSION,
      secretCache: SECRET_CACHE,
      config: CONFIG,
      dashboardDir: join(__dirname, 'dashboard'),
      requireSops: true, // /ready 是否要求已加载 secrets
      runReadyProbes: () => runProbes(probesFromConfig(CONFIG)),
    };
    if (await handleHealth(req, res, route, publicDeps)) {
      observeMs('broker_http_request_duration_ms', Date.now() - t0);
      inc('broker_http_requests_total', 1, { route: p });
      return;
    }
    if (handleStatic(req, res, route, publicDeps)) {
      observeMs('broker_http_request_duration_ms', Date.now() - t0);
      inc('broker_http_requests_total', 1, { route: p });
      return;
    }
    if (handleMetrics(req, res, route, publicDeps)) {
      observeMs('broker_http_request_duration_ms', Date.now() - t0);
      return;
    }

    // —— 身份（现有 getIdentity / session / api-key / mTLS）——
    const ctx = getIdentity(req); // 保持你现有实现

    // —— 可选：模块化 API（需 deps 齐全；与 legacy 双路径）——
    if (useModularRoutes()) {
      const apiDeps = buildRouteDeps({
        send, jsonError, readBody, audit,
        config: CONFIG,
        secretCache: SECRET_CACHE,
        version: BROKER_VERSION,
        ctx,
        getIdentity,
        verifyClientPassword,
        isMfaRequired, createMfaPending, getMfaPending,
        consumeMfaPending, verifyMfaCode, MFA_TOKEN_TTL_MS,
        makeSession, deleteSession, sessions: SESSION_MAP, // 名称以你代码为准
        checkLoginLock, recordLoginFail, clearLoginLock,
        canAccessSecret, putSecret, deleteSecret, persistConfig,
        canProxy, proxyRequest: doProxyUpstream, // 你的上游函数
        certPaths, existsSync,
        backupPaths: {
          configPath: CONFIG_PATH,
          secretsSopsPath: SECRETS_PATH,
          ageKeyPath: AGE_KEY_PATH,
          // caCert, caKey, serverCert, serverKey, auditDir, clientsDir
        },
      });
      if (await dispatch(API_HANDLERS, req, res, route, apiDeps)) {
        observeMs('broker_http_request_duration_ms', Date.now() - t0);
        inc('broker_http_requests_total', 1, { route: p });
        return;
      }
    }

    // —— 以下保持原有 legacy if (m === ... && p === ...) ——
    // ...

    observeMs('broker_http_request_duration_ms', Date.now() - t0);
    inc('broker_http_requests_total', 1, { route: p });
  });
}
```

**脚本已做（B.2）**：仅 health + static 早期 dispatch。  
**需手写**：`runWithRequestContext`、shutdown 503、metrics、probes、API `dispatch`。

### Proxy 上游头

在真正 `http(s).request` / `fetch` 前合并：

```js
headers: {
  ...upstreamHeaders,
  ...outboundTraceHeaders({
    traceparent: getTraceparent(),
    requestId: getRequestId(),
  }),
  'User-Agent': `secret-broker/${BROKER_VERSION}`,
}
```

---

## 4. 启动路径 `start()` / `main`

在 `listen` 前后按序：

```js
// 1) 路径预检（路径常量名按你仓库实际修改）
const pf = preflightPaths({
  configPath: CONFIG_PATH,
  ageKey: AGE_KEY_PATH,
  caCert: CA_CERT_PATH,
  serverCert: SERVER_CERT_PATH,
  serverKey: SERVER_KEY_PATH,
}, { existsSync });
if (!pf.ok) {
  console.error(formatValidationReport(pf));
  process.exit(1);
}

// 2) 加载 CONFIG / 迁移后
const vr = validateBrokerConfig(CONFIG);
if (!vr.ok) {
  console.error(formatValidationReport(vr));
  process.exit(1);
}
for (const w of vr.warnings) console.warn('[config]', w.path, w.message);

// 3) Audit 采样（可选）
const auditPolicy = auditPolicyFromEnv();
// const audit = withAuditSampling(rawAudit, auditPolicy);

// 4) listen 之后
const { shuttingDown } = installGracefulShutdown({
  server,
  onShutdown: [
    () => stopCronLoop(),
  ],
});

// 5) Cron：审计清理 + 可选备份清单
registerCron('03:30', () => {
  pruneAuditFiles(AUDIT_DIR, auditPolicy.retainDays);
});
// registerCron('sunday 04:00', () => writeBackupManifest(...));
startCronLoop();

log.info('broker_started', { version: BROKER_VERSION, port: PORT });
```

---

## 5. 环境变量一览

| 变量 | 默认 | 作用 |
|------|------|------|
| `USE_MODULAR_ROUTES` | off | 走 `API_HANDLERS` dispatch |
| `BROKER_LOG_LEVEL` | `info` | JSON 日志级别 |
| `METRICS_REQUIRE_AUTH` | off | `/metrics` 需 admin |
| `AUDIT_SAMPLE_RATE` | `1` | 审计采样（login/denied 始终记） |
| `AUDIT_RETAIN_DAYS` | `30` | 审计文件保留天数 |
| `SHUTDOWN_TIMEOUT_MS` | `15000` | 优雅退出超时 |
| `READY_PROBES` | on | `0` 关闭依赖探针 |

---

## 6. 冒烟清单

```bash
# 测试
cd broker && npm run test:modular

# 启动（legacy 或混合）
node server.js

# 公共
curl -k https://127.0.0.1:8443/health
curl -k https://127.0.0.1:8443/live
curl -k https://127.0.0.1:8443/ready
curl -k https://127.0.0.1:8443/metrics
curl -k https://127.0.0.1:8443/metrics.json

# 模块化 API（可选）
USE_MODULAR_ROUTES=1 node server.js
# 再测 login / me / proxy

# 关闭信号
kill -TERM <pid>   # 应看到 shutdown 日志并在超时内退出
```

---

## 7. 提交

```bash
git add broker/server.js
git commit -m "wire: Phase A–F server.js (version, routes, obs, shutdown)"
git push origin master
```

---

## 8. 切勿过早删除的代码

在以下条件满足前，**不要**删除 legacy `if (m/p)` 分支与内联 `send`/`sops*`：

1. 非生产环境 `USE_MODULAR_ROUTES=1` 跑通 login + secret get + proxy
2. `/ready`、`/metrics`、SIGTERM 行为符合预期
3. 审计与指标有样本

删除顺序建议：先公共路由重复块 → auth/me → secrets/services/clients → proxy → 最后内联 helpers。

---

## 9. 相关文档

| Doc | 内容 |
|-----|------|
| `docs/PHASE-A-SERVER-WIRE.md` | A 补丁细节 |
| `docs/PHASE-B-MODULARIZE.md` / `PHASE-B5-CUTOVER.md` | 模块化 |
| `docs/PHASE-C-OBSERVABILITY.md` | 指标/日志 |
| `docs/PHASE-D-TRACING-AUDIT.md` | 追踪/审计策略 |
| `docs/PHASE-E-OPS.md` | 退出/配置校验 |
| `docs/PHASE-F-BACKUP-PROBES.md` | 备份/探针 |
| `CHANGELOG.md` | 3.2.0–3.8.0 |
