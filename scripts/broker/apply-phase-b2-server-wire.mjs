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
 * 6) Early-dispatch routes/health + routes/static
 *
 * Does NOT delete large inlined function bodies (safe).
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
    if (typeof replace === 'string' && src.includes(replace.slice(0, Math.min(48, replace.length)))) {
      console.log('[skip] ' + label);
      return;
    }
    console.warn('[miss] ' + label);
    return;
  }
  src = src.replace(find, replace);
  n++;
  console.log('[ok]   ' + label);
}

once(
  'import isClientIpAllowed',
  "  generateMasterKey,\n  createChildKey,\n  canCreateChild,\n} from './api-keys.js';",
  "  generateMasterKey,\n  createChildKey,\n  canCreateChild,\n  isClientIpAllowed,\n} from './api-keys.js';"
);

once(
  'import BROKER_VERSION + routes',
  "} from './api-keys.js';\n// v3.0: schema migration (in start())",
  "} from './api-keys.js';\nimport { BROKER_VERSION } from './version.js';\nimport { handleHealth, handleStatic } from './routes/index.js';\n// v3.0: schema migration (in start())"
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
  "  const k = findApiKey(CONFIG.api_keys, secret);\n  if (!k) return null;\n  // 找到归属 client\n  const owner = CONFIG.clients[k.client];\n  if (!owner) return null;\n  // 限速 (per api key)",
  "  const k = findApiKey(CONFIG.api_keys, secret);\n  if (!k) return null;\n  // v3.2: enforce ip_whitelist when set\n  const remoteIp = req.socket?.remoteAddress\n    || req.headers['x-forwarded-for']?.toString().split(',')[0]?.trim()\n    || '';\n  if (!isClientIpAllowed(k, remoteIp)) {\n    audit({\n      action: 'connect',\n      status: 'denied',\n      reason: 'api_key_ip_denied',\n      cn: k.client,\n      remote: remoteIp,\n    });\n    return null;\n  }\n  // 找到归属 client\n  const owner = CONFIG.clients[k.client];\n  if (!owner) return null;\n  // 限速 (per api key)"
);

once(
  'dead return secrets list',
  "    return send(res, 200, { secrets: out });\n    return send(res, 200, { secrets: visible });\n  }",
  "    return send(res, 200, { secrets: out });\n  }"
);

// Early dispatch: insert after "const t0 = Date.now();" that precedes health block
{
  const marker = '  // Phase B.2: modular public routes';
  if (src.includes(marker)) {
    console.log('[skip] routes early dispatch');
  } else {
    const needle = "  const t0 = Date.now();\n\n  // ----- Public: /health -----";
    const insert =
      "  const t0 = Date.now();\n\n" +
      "  // Phase B.2: modular public routes (health + static dashboard)\n" +
      "  {\n" +
      "    const route = { method: m, pathname: p };\n" +
      "    const deps = {\n" +
      "      send,\n" +
      "      version: typeof BROKER_VERSION !== 'undefined' ? BROKER_VERSION : '3.3.0',\n" +
      "      secretCache: SECRET_CACHE,\n" +
      "      config: CONFIG,\n" +
      "      dashboardDir: join(__dirname, 'dashboard'),\n" +
      "    };\n" +
      "    if (handleHealth(req, res, route, deps)) return;\n" +
      "    if (handleStatic(req, res, route, deps)) return;\n" +
      "  }\n\n" +
      "  // ----- Public: /health -----";
    if (src.includes(needle)) {
      src = src.replace(needle, insert);
      n++;
      console.log('[ok]   routes early dispatch');
    } else {
      console.warn('[miss] routes early dispatch');
    }
  }
}

if (src === original) {
  console.log('\nNo changes (already wired or patterns drifted).');
  process.exit(0);
}

writeFileSync(SERVER, src);
console.log('\nWrote ' + SERVER + ' (' + n + ' patch groups).');
console.log('Run: node broker-test/test-lib-phase-b.js && node broker-test/test-routes-phase-b2.js');
