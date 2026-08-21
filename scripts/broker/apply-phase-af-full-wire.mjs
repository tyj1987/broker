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

once(
  'import isClientIpAllowed',
  `  generateMasterKey,\n  createChildKey,\n  canCreateChild,\n} from './api-keys.js';`,
  `  generateMasterKey,\n  createChildKey,\n  canCreateChild,\n  isClientIpAllowed,\n} from './api-keys.js';`
);

once(
  'import phase A-F modules',
  `} from './api-keys.js';\n// v3.0: schema migration (in start())`,
  `} from './api-keys.js';\nimport { BROKER_VERSION } from './version.js';\nimport {\n  handleHealth,\n  handleStatic,\n  handleMetrics,\n  handleOps,\n  dispatch,\n  API_HANDLERS,\n} from './routes/index.js';\nimport {\n  buildRouteDeps,\n  useModularRoutes,\n  installGracefulShutdown,\n  rejectIfShuttingDown,\n  validateBrokerConfig,\n  formatValidationReport,\n  preflightPaths,\n  withAuditSampling,\n  pruneAuditFiles,\n  auditPolicyFromEnv,\n  runWithRequestContext,\n  setResponseTraceHeaders,\n  getRequestId,\n  getTraceparent,\n  outboundTraceHeaders,\n  inc,\n  observeMs,\n  log,\n  runProbes,\n  probesFromConfig,\n  buildBackupManifest,\n} from './lib/index.js';\n// v3.0: schema migration (in start())`
);

once('startup banner', "console.log('  Secret Broker v2.0');", 'console.log(`  Secret Broker v${BROKER_VERSION}`);');
replaceAll('X-Broker-Version', "'X-Broker-Version': '2.0.0'", "'X-Broker-Version': BROKER_VERSION");
once('health version', "version: '2.0.0',", 'version: BROKER_VERSION,');
once('User-Agent', "'User-Agent': 'secret-broker/2.0',", "'User-Agent': `secret-broker/${BROKER_VERSION}`,");
once('issueAndPersist days', 'const cert = await issueClientCert(name, { days: 365 });', 'const cert = await issueClientCert(name); // DEFAULT_CERT_DAYS = 90');

once(
  'API key IP whitelist',
  `  const k = findApiKey(CONFIG.api_keys, secret);\n  if (!k) return null;\n  // 找到归属 client\n  const owner = CONFIG.clients[k.client];\n  if (!owner) return null;\n  // 限速 (per api key)`,
  `  const k = findApiKey(CONFIG.api_keys, secret);\n  if (!k) return null;\n  // v3.2: enforce ip_whitelist when set\n  const remoteIp = req.socket?.remoteAddress\n    || req.headers['x-forwarded-for']?.toString().split(',')[0]?.trim()\n    || '';\n  if (!isClientIpAllowed(k, remoteIp)) {\n    audit({\n      action: 'connect',\n      status: 'denied',\n      reason: 'api_key_ip_denied',\n      cn: k.client,\n      remote: remoteIp,\n    });\n    return null;\n  }\n  // 找到归属 client\n  const owner = CONFIG.clients[k.client];\n  if (!owner) return null;\n  // 限速 (per api key)`
);

once(
  'dead return secrets list',
  `    return send(res, 200, { secrets: out });\n    return send(res, 200, { secrets: visible });\n  }`,
  `    return send(res, 200, { secrets: out });\n  }`
);

{
  const marker = 'Phase AF: modular request pipeline';
  if (src.includes(marker)) {
    console.log('[skip] handle pipeline');
  } else {
    const needle =
      'async function handle(req, res) {\n' +
      '  const url = new URL(req.url, `https://${req.headers.host}`);\n' +
      '  const m = req.method;\n' +
      '  const p = url.pathname;\n' +
      '  const t0 = Date.now();\n\n' +
      '  // ----- Public: /health -----';
    const insert =
      'async function handle(req, res) {\n' +
      '  return runWithRequestContext(req.headers || {}, async () => {\n' +
      '  setResponseTraceHeaders(res);\n' +
      '  if (rejectIfShuttingDown(globalThis.__brokerShuttingDown || (() => false), res, jsonError)) return;\n\n' +
      '  const url = new URL(req.url, `https://${req.headers.host}`);\n' +
      '  const m = req.method;\n' +
      '  const p = url.pathname;\n' +
      '  const t0 = Date.now();\n' +
      '  const route = { method: m, pathname: p };\n\n' +
      '  // Phase AF: modular request pipeline (public routes)\n' +
      '  {\n' +
      '    const publicDeps = {\n' +
      '      send,\n' +
      '      jsonError,\n' +
      '      readBody,\n' +
      '      version: typeof BROKER_VERSION !== \'undefined\' ? BROKER_VERSION : \'3.8.0\',\n' +
      '      secretCache: SECRET_CACHE,\n' +
      '      config: CONFIG,\n' +
      '      dashboardDir: join(__dirname, \'dashboard\'),\n' +
      '      requireSops: true,\n' +
      '      runReadyProbes: () => runProbes(probesFromConfig(CONFIG || {})),\n' +
      '    };\n' +
      '    if (await handleHealth(req, res, route, publicDeps)) {\n' +
      '      observeMs(\'broker_http_request_duration_ms\', Date.now() - t0);\n' +
      '      inc(\'broker_http_requests_total\', 1, { route: p });\n' +
      '      return;\n' +
      '    }\n' +
      '    if (handleStatic(req, res, route, publicDeps)) {\n' +
      '      observeMs(\'broker_http_request_duration_ms\', Date.now() - t0);\n' +
      '      inc(\'broker_http_requests_total\', 1, { route: p });\n' +
      '      return;\n' +
      '    }\n' +
      '    if (handleMetrics(req, res, route, publicDeps)) {\n' +
      '      observeMs(\'broker_http_request_duration_ms\', Date.now() - t0);\n' +
      '      return;\n' +
      '    }\n' +
      '  }\n\n' +
      '  // ----- Public: /health -----';
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
  if (src.includes('Phase AF: end request pipeline')) {
    console.log('[skip] handle pipeline end');
  } else {
    const needle =
      '  // 404\n' +
      '  audit({ action: \'unknown\', cn: ctx.cn, fp: ctx.fp, method: m, path: p, status: \'404\' });\n' +
      '  return jsonError(res, 404, `Not found: ${m} ${p}`);\n}';
    const insert =
      '  // 404\n' +
      '  audit({ action: \'unknown\', cn: ctx.cn, fp: ctx.fp, method: m, path: p, status: \'404\' });\n' +
      '  observeMs(\'broker_http_request_duration_ms\', Date.now() - t0);\n' +
      '  inc(\'broker_http_requests_total\', 1, { route: p });\n' +
      '  return jsonError(res, 404, `Not found: ${m} ${p}`);\n' +
      '  }); // Phase AF: end request pipeline (runWithRequestContext)\n}';
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
  'outbound trace headers (legacy UA)',
  `  const outHeaders = {\n    'User-Agent': 'secret-broker/2.0',\n    ...injectHeaders,\n    ...(headers || {}),\n  };`,
  `  const outHeaders = {\n    'User-Agent': \`secret-broker/\${typeof BROKER_VERSION !== 'undefined' ? BROKER_VERSION : '3.8.0'}\`,\n    ...outboundTraceHeaders({\n      traceparent: typeof getTraceparent === 'function' ? getTraceparent() : undefined,\n      requestId: typeof getRequestId === 'function' ? getRequestId() : undefined,\n    }),\n    ...injectHeaders,\n    ...(headers || {}),\n  };`
);

once(
  'outbound trace headers',
  `  const outHeaders = {\n    'User-Agent': \`secret-broker/\${BROKER_VERSION}\`,\n    ...injectHeaders,\n    ...(headers || {}),\n  };`,
  `  const outHeaders = {\n    'User-Agent': \`secret-broker/\${BROKER_VERSION}\`,\n    ...outboundTraceHeaders({\n      traceparent: typeof getTraceparent === 'function' ? getTraceparent() : undefined,\n      requestId: typeof getRequestId === 'function' ? getRequestId() : undefined,\n    }),\n    ...injectHeaders,\n    ...(headers || {}),\n  };`
);

once(
  'graceful shutdown replace signals',
  `  process.on('SIGINT',  () => { console.log('\\n[broker] shutting down'); server.close(); stopCronLoop(); process.exit(0); });\n  process.on('SIGTERM', () => { server.close(); stopCronLoop(); process.exit(0); });\n}`,
  `  // Phase E: graceful shutdown (SIGTERM/SIGINT drain)\n  const _shutdownCtl = installGracefulShutdown({\n    server,\n    onShutdown: [() => stopCronLoop()],\n  });\n  globalThis.__brokerShuttingDown = _shutdownCtl.shuttingDown;\n\n  // Phase D/F: audit prune\n  try {\n    const policy = auditPolicyFromEnv();\n    registerCron('03:30', () => {\n      const r = pruneAuditFiles(AUDIT_DIR, policy.retainDays);\n      console.log('[cron] audit prune deleted=', r.deleted?.length || 0);\n    });\n  } catch (e) {\n    console.warn('[cron] audit prune register failed:', e.message);\n  }\n}`
);

once(
  'bootstrap validate after loadConfig',
  `    await loadConfig();\n    await loadSecrets();\n    // v3.0: 启动时跑一次 schema 迁移（幂等）`,
  `    await loadConfig();\n    await loadSecrets();\n    // Phase E: config validation\n    try {\n      const vr = validateBrokerConfig(CONFIG);\n      if (!vr.ok) {\n        console.error('[config] validation failed:\\n' + formatValidationReport(vr));\n        process.exit(1);\n      }\n      for (const w of vr.warnings || []) console.warn('[config]', w.path, w.message);\n    } catch (e) {\n      console.warn('[config] validate skipped:', e.message);\n    }\n    try {\n      const pf = preflightPaths({\n        configPath: CONFIG_PATH,\n        ageKey: AGE_KEY_FILE,\n        caCert: TLS_CA,\n        serverCert: TLS_CERT,\n        serverKey: TLS_KEY,\n      }, { existsSync });\n      if (!pf.ok) {\n        console.error('[preflight] failed:\\n' + formatValidationReport(pf));\n        process.exit(1);\n      }\n    } catch (e) {\n      console.warn('[preflight] skipped:', e.message);\n    }\n    // v3.0: 启动时跑一次 schema 迁移（幂等）`
);

if (src === original) {
  console.log('\\nNo changes applied (already wired or patterns drifted).');
  process.exit(0);
}

writeFileSync(SERVER, src);
console.log('\\nWrote', SERVER, '(' + n + ' patch groups).');
