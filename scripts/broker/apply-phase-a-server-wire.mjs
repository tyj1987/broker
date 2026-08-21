#!/usr/bin/env node
/**
 * apply-phase-a-server-wire.mjs
 *
 * Applies the 5 Phase-A surgical edits to broker/server.js.
 * Idempotent: safe to re-run.
 *
 * Usage (from repo root):
 *   node scripts/broker/apply-phase-a-server-wire.mjs
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
    // already applied or different formatting
    if (src.includes(replace) || (typeof replace === 'string' && src.includes(replace.slice(0, 40)))) {
      console.log(`[skip] ${label} (already present)`);
      return;
    }
    console.warn(`[miss] ${label}: pattern not found`);
    return;
  }
  src = src.replace(find, replace);
  n++;
  console.log(`[ok]   ${label}`);
}

// 1) Import isClientIpAllowed from api-keys
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

// 2) Import BROKER_VERSION
once(
  'import BROKER_VERSION',
  `} from './api-keys.js';
// v3.0: schema migration (in start())`,
  `} from './api-keys.js';
import { BROKER_VERSION } from './version.js';
// v3.0: schema migration (in start())`
);

// 3) Banner
once(
  'startup banner version',
  "console.log('  Secret Broker v2.0');",
  'console.log(`  Secret Broker v${BROKER_VERSION}`);'
);

// 4) X-Broker-Version header (all occurrences)
{
  const before = src;
  src = src.replaceAll("'X-Broker-Version': '2.0.0'", "'X-Broker-Version': BROKER_VERSION");
  const c = (before.length - src.length) / ("'2.0.0'".length - 'BROKER_VERSION'.length || 1);
  if (before !== src) {
    n++;
    console.log(`[ok]   X-Broker-Version -> BROKER_VERSION (global)`);
  } else if (src.includes("'X-Broker-Version': BROKER_VERSION")) {
    console.log('[skip] X-Broker-Version (already wired)');
  } else {
    console.warn('[miss] X-Broker-Version pattern');
  }
}

// 5) /health version field
once(
  'health version field',
  "version: '2.0.0',",
  'version: BROKER_VERSION,'
);

// 6) User-Agent
once(
  'User-Agent',
  "'User-Agent': 'secret-broker/2.0',",
  "'User-Agent': `secret-broker/${BROKER_VERSION}`,"
);

// 7) issueAndPersist days 365 -> default 90
once(
  'issueAndPersist default days',
  'const cert = await issueClientCert(name, { days: 365 });',
  'const cert = await issueClientCert(name); // DEFAULT_CERT_DAYS = 90'
);

// 8) IP whitelist in getApiKeyIdentity
once(
  'API key IP whitelist enforcement',
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

// 9) Dead return in GET /api/v1/secrets
once(
  'remove dead return after secrets list',
  `    return send(res, 200, { secrets: out });
    return send(res, 200, { secrets: visible });
  }`,
  `    return send(res, 200, { secrets: out });
  }`
);

if (src === original) {
  console.log('\nNo changes written (already up to date or patterns drifted).');
  process.exit(0);
}

writeFileSync(SERVER, src);
console.log(`\nWrote ${SERVER} (${n} patch groups applied).`);
console.log('Next: node broker-test/test-ip-allowlist.js && run full suite.');
