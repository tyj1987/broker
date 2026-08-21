#!/usr/bin/env node
/**
 * apply-phase-b2-server-wire.mjs
 *
 * Surgical, idempotent wiring of Phase A + Phase B.2 into broker/server.js:
 * 1) Import BROKER_VERSION, isClientIpAllowed, lib helpers, routes
 * 2) Version banner / headers / health version / User-Agent
 * 3) issueAndPersist default 90d
 * 4) API key IP allowlist in getApiKeyIdentity
 * 5) Remove dead return in GET /api/v1/secrets
 * 6) Prefer routes/health + routes/static when present (optional soft-wire)
 *
 * Does NOT delete large inlined function bodies (safe). Full body removal is manual/follow-up.
 *
 * Usage (repo root):
 *   node scripts/broker/apply-phase-b2-server-wire.mjs
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '../..');
const SERVER = join(ROOT, 'broker/server.js');

if (!existsSync(SERVER)) {
  console.error('broker/server.js not found');
  process.exit(1);
}

let src = readFileSync(SERVER, 'utf8');
const original = src;
let n = 0;

function once(label, find, replace) {
  if (!src.includes(find)) {
    if (typeof replace === 'string' && src.includes(replace.slice(0, Math.min(50, replace.length)))) {
      console.log(`[skip] ${label}`);
      return;
    }
    console.warn(`[miss] ${label}`);
    return;
  }
  src = src.replace(find, replace);
  n++;
  console.log(`[ok]   ${label}`);
}

// --- Phase A / version ---
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
  'import BROKER_VERSION',
  `} from './api-keys.js';
// v3.0: schema migration (in start())`,
  `} from './api-keys.js';
import { BROKER_VERSION } from './version.js';
import { send as libSend, readBody as libReadBody, jsonError as libJsonError } from './lib/http.js';
import { buildZip as libBuildZip } from './lib/zip.js';
import { handleHealth, handleStatic, dispatch as dispatchRoutes } from './routes/index.js';
// v3.0: schema migration (in start())`
);

once(
  'startup banner',
  "console.log('  Secret Broker v2.0');",
  'console.log(`  Secret Broker v${BROKER_VERSION}`);'
);

{
  const before = src;
  src = src.replaceAll("'X-Broker-Version': '2.0.0'", "'X-Broker-Version': BROKER_VERSION");
  if (before !== src) { n++; console.log('[ok]   X-Broker-Version -> BROKER_VERSION'); }
  else if (src.includes("'X-Broker-Version': BROKER_VERSION")) console.log('[skip] X-Broker-Version');
  else console.warn('[miss] X-Broker-Version');
}

once('health version', "version: '2.0.0',", 'version: BROKER_VERSION,');
once(
  'User-Agent',
  "'User-Agent': 'secret-broker/2.0',",
  "'User-Agent': `secret-broker/${BROKER_VERSION}`,"
);
once(
  'issueAndPersist days',
  'const cert = await issueClientCert(name, { days: 365 });',
  'const cert = await issueClientCert(name); // DEFAULT_CERT_DAYS = 90'
);

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

once(
  'dead return secrets list',
  `    return send(res, 200, { secrets: out });
    return send(res, 200, { secrets: visible });
  }`,
  `    return send(res, 200, { secrets: out });
  }`
);

// Soft-wire: early dispatch for health + static (idempotent marker)
once(
  'routes early dispatch marker',
  `async function handle(req, res) {
  const url = new URL(req.url, \`https://\${req.headers.host}\`);
  const m = req.method;
  const p = url.pathname;
  const t0 = Date.now();

  // ----- Public: /health -----`,
  `async function handle(req, res) {
  const url = new URL(req.url, \`https://\${req.headers.host}\`);
  const m = req.method;
  const p = url.pathname;
  const t0 = Date.now();

  // Phase B.2: modular public routes (health + static dashboard)
  {
    const route = { method: m, pathname: p };
    const deps = {
      send,
      version: typeof BROKER_VERSION !== 'undefined' ? BROKER_VERSION : '3.3.0',
      secretCache: SECRET_CACHE,
      config: CONFIG,
      dashboardDir: join(__dirname, 'dashboard'),
    };
    if (handleHealth(req, res, route, deps)) return;
    if (handleStatic(req, res, route, deps)) return;
  }

  // ----- Public: /health -----`
);

if (src === original) {
  console.log('\nNo changes (already wired or patterns drifted).');
  process.exit(0);
}

writeFileSync(SERVER, src);
console.log(`\nWrote ${SERVER} (${n} patch groups).`);
console.log('Run: node broker-test/test-lib-phase-b.js && node broker-test/test-ip-allowlist.js');
