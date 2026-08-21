#!/usr/bin/env node
/**
 * apply-phase-af-full-wire.mjs
 * Idempotent full Phase A–F wiring for broker/server.js
 * Run from repo root: node scripts/broker/apply-phase-af-full-wire.mjs
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '../..');
const SERVER = join(ROOT, 'broker/server.js');

if (!existsSync(SERVER)) {
  console.error('broker/server.js not found at', SERVER);
  process.exit(1);
}

let src = readFileSync(SERVER, 'utf8');
const original = src;
let n = 0;

function once(label, find, replace) {
  if (!src.includes(find)) {
    if (typeof replace === 'string' && src.includes(replace.slice(0, Math.min(40, replace.length)))) {
      console.log('[skip]', label);
      return;
    }
    console.warn('[miss]', label);
    return;
  }
  src = src.replace(find, replace);
  n++;
  console.log('[ok]  ', label);
}

function replaceAll(label, find, replace) {
  if (!src.includes(find)) {
    console.warn('[miss]', label);
    return;
  }
  const before = src;
  src = src.split(find).join(replace);
  if (src !== before) {
    n++;
    console.log('[ok]  ', label);
  }
}

// ===== Imports after api-keys =====
once(
  'import isClientIpAllowed',
  `  generateMasterKey,
  createChildKey,
  canCreateChild,
} from './api-keys.js';`,
  `  generateMasterKey,
  createChildKey,
  canCreateChild,
  isClientIpAllowed,
} from './api-keys.js';`
);

once(
  'import phase A-F modules',
  `} from './api-keys.js';
// v3.0: schema migration (in start())`,
  `} from './api-keys.js';
import { BROKER_VERSION } from './version.js';
import {
  handleHealth,
  handleStatic,
  handleMetrics,
  handleOps,
  dispatch,
  API_HANDLERS,
} from './routes/index.js';
import {
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
// v3.0: schema migration (in start())`
);

// ===== Version strings =====
once('startup banner', "console.log('  Secret Broker v2.0');", 'console.log(`  Secret Broker v${BROKER_VERSION}`);');
replaceAll('X-Broker-Version', "'X-Broker-Version': '2.0.0'", "'X-Broker-Version': BROKER_VERSION");
once('health version', "version: '2.0.0',", 'version: BROKER_VERSION,');
once('User-Agent', "'User-Agent': 'secret-broker/2.0',", "'User-Agent': `secret-broker/${BROKER_VERSION}`,");
once('issueAndPersist days', 'const cert = await issueClientCert(name, { days: 365 });', 'const cert = await issueClientCert(name); // DEFAULT_CERT_DAYS = 90');

// ===== API key IP allowlist =====
once(
  'API key IP whitelist',
  `  const k = findApiKey(CONFIG.api_keys, secret);
  if (!k) return null;
  // 找到归属 client
  const owner = CONFIG.clients[k.client];
  if (!owner) return null;
  // 限速 (per api key)`,
  `  const k = findApiKey(CONFIG.api_keys, secret);
  if (!k) return null;
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
  // 找到归属 client
  const owner = CONFIG.clients[k.client];
  if (!owner) return null;
  // 限速 (per api key)`
);

// ===== dead return =====
once(
  'dead return secrets list',
  `    return send(res, 200, { secrets: out });
    return send(res, 200, { secrets: visible });
  }`,
  `    return send(res, 200, { secrets: out });
  }`
);

// ===== handle() wrap =====
{
  const marker = 'Phase AF: modular request pipeline';
  if (src.includes(marker)) {
    console.log('[skip] handle pipeline');
  } else {
    const needle = `async function handle(req, res) {
  const url = new URL(req.url, \`https://\${req.headers.host}\`);
  const m = req.method;
  const p = url.pathname;
  const t0 = Date.now();

  // ----- Public: /health -----`;
    const insert = `async function handle(req, res) {
  return runWithRequestContext(req.headers || {}, async () => {
  setResponseTraceHeaders(res);
  if (rejectIfShuttingDown(globalThis.__brokerShuttingDown || (() => false), res, jsonError)) return;

  const url = new URL(req.url, \`https://\${req.headers.host}\`);
  const m = req.method;
  const p = url.pathname;
  const t0 = Date.now();
  const route = { method: m, pathname: p };

  // Phase AF: modular request pipeline (public routes)
  {
    const publicDeps = {
      send,
      jsonError,
      readBody,
      version: typeof BROKER_VERSION !== 'undefined' ? BROKER_VERSION : '3.8.0',
      secretCache: SECRET_CACHE,
      config: CONFIG,
      dashboardDir: join(__dirname, 'dashboard'),
      requireSops: true,
      runReadyProbes: () => runProbes(probesFromConfig(CONFIG || {})),
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
  }

  // ----- Public: /health -----`;
    if (src.includes(needle)) {
      src = src.replace(needle, insert);
      n++;
      console.log('[ok]   handle pipeline start');
    } else {
      console.warn('[miss] handle pipeline start');
    }
  }
}

{
  const marker = 'Phase AF: end request pipeline';
  if (src.includes(marker)) {
    console.log('[skip] handle pipeline end');
  } else {
    const needle = `  // 404
  audit({ action: 'unknown', cn: ctx.cn, fp: ctx.fp, method: m, path: p, status: '404' });
  return jsonError(res, 404, \`Not found: \${m} \${p}\`);
}`;
    const insert = `  // 404
  audit({ action: 'unknown', cn: ctx.cn, fp: ctx.fp, method: m, path: p, status: '404' });
  observeMs('broker_http_request_duration_ms', Date.now() - t0);
  inc('broker_http_requests_total', 1, { route: p });
  return jsonError(res, 404, \`Not found: \${m} \${p}\`);
  }); // Phase AF: end request pipeline (runWithRequestContext)
}`;
    if (src.includes(needle)) {
      src = src.replace(needle, insert);
      n++;
      console.log('[ok]   handle pipeline end');
    } else {
      console.warn('[miss] handle pipeline end');
    }
  }
}

once(
  'outbound trace headers',
  `  const outHeaders = {
    'User-Agent': \`secret-broker/\${BROKER_VERSION}\`,
    ...injectHeaders,
    ...(headers || {}),
  };`,
  `  const outHeaders = {
    'User-Agent': \`secret-broker/\${BROKER_VERSION}\`,
    ...outboundTraceHeaders({
      traceparent: getTraceparent?.() || undefined,
      requestId: getRequestId?.() || undefined,
    }),
    ...injectHeaders,
    ...(headers || {}),
  };`
);
once(
  'outbound trace headers (legacy UA)',
  `  const outHeaders = {
    'User-Agent': 'secret-broker/2.0',
    ...injectHeaders,
    ...(headers || {}),
  };`,
  `  const outHeaders = {
    'User-Agent': \`secret-broker/\${typeof BROKER_VERSION !== 'undefined' ? BROKER_VERSION : '3.8.0'}\`,
    ...outboundTraceHeaders({
      traceparent: typeof getTraceparent === 'function' ? getTraceparent() : undefined,
      requestId: typeof getRequestId === 'function' ? getRequestId() : undefined,
    }),
    ...injectHeaders,
    ...(headers || {}),
  };`
);

once(
  'graceful shutdown replace signals',
  `  process.on('SIGINT',  () => { console.log('\\n[broker] shutting down'); server.close(); stopCronLoop(); process.exit(0); });
  process.on('SIGTERM', () => { server.close(); stopCronLoop(); process.exit(0); });
}`,
  `  // Phase E: graceful shutdown (SIGTERM/SIGINT drain)
  const _shutdownCtl = installGracefulShutdown({
    server,
    onShutdown: [() => stopCronLoop()],
  });
  globalThis.__brokerShuttingDown = _shutdownCtl.shuttingDown;

  try {
    const policy = auditPolicyFromEnv();
    registerCron('03:30', () => {
      const r = pruneAuditFiles(AUDIT_DIR, policy.retainDays);
      console.log('[cron] audit prune deleted=', r.deleted?.length || 0);
    });
  } catch (e) {
    console.warn('[cron] audit prune register failed:', e.message);
  }
}`
);

once(
  'bootstrap validate after loadConfig',
  `    await loadConfig();
    await loadSecrets();
    // v3.0: 启动时跑一次 schema 迁移（幂等）`,
  `    await loadConfig();
    await loadSecrets();
    try {
      const vr = validateBrokerConfig(CONFIG);
      if (!vr.ok) {
        console.error('[config] validation failed:\\n' + formatValidationReport(vr));
        process.exit(1);
      }
      for (const w of vr.warnings || []) console.warn('[config]', w.path, w.message);
    } catch (e) {
      console.warn('[config] validate skipped:', e.message);
    }
    try {
      const pf = preflightPaths({
        configPath: CONFIG_PATH,
        ageKey: AGE_KEY_FILE,
        caCert: TLS_CA,
        serverCert: TLS_CERT,
        serverKey: TLS_KEY,
      }, { existsSync });
      if (!pf.ok) {
        console.error('[preflight] failed:\\n' + formatValidationReport(pf));
        process.exit(1);
      }
    } catch (e) {
      console.warn('[preflight] skipped:', e.message);
    }
    // v3.0: 启动时跑一次 schema 迁移（幂等）`
);

if (src === original) {
  console.log('\\nNo changes applied (already wired or patterns drifted).');
  process.exit(0);
}

writeFileSync(SERVER, src);
console.log('\\nWrote', SERVER, '(' + n + ' patch groups).');
console.log('Next: cd broker && npm run test:modular');
