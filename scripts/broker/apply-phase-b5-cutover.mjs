#!/usr/bin/env node
/**
 * apply-phase-b5-cutover.mjs
 *
 * Idempotent cutover helpers for server.js:
 * 1) Ensure BROKER_VERSION + full routes imports (B.2/B.4)
 * 2) Insert optional modular dispatch block gated by USE_MODULAR_ROUTES
 * 3) Does NOT delete legacy route bodies (rollback = unset env)
 *
 * Recommended order:
 *   node scripts/broker/apply-phase-b2-server-wire.mjs
 *   node scripts/broker/apply-phase-b4-server-wire.mjs
 *   node scripts/broker/apply-phase-b5-cutover.mjs
 *
 * Enable at runtime:
 *   USE_MODULAR_ROUTES=1 node broker/server.js
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
    if (src.includes(replace.slice(0, Math.min(48, replace.length)))) {
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

// Prefer full import list
once(
  'full routes import',
  "import { handleHealth, handleStatic } from './routes/index.js';",
  "import {\n  handleHealth,\n  handleStatic,\n  handleAuth,\n  handleMe,\n  handleSecrets,\n  handleServices,\n  handleClients,\n  handleProxy,\n  dispatch,\n  PUBLIC_HANDLERS,\n  API_HANDLERS,\n} from './routes/index.js';\nimport { buildRouteDeps, useModularRoutes } from './lib/build-route-deps.js';"
);

once(
  'import build-route-deps if only full handlers',
  "} from './routes/index.js';\n// v3.0: schema migration",
  "} from './routes/index.js';\nimport { buildRouteDeps, useModularRoutes } from './lib/build-route-deps.js';\n// v3.0: schema migration"
);

// Insert modular dispatch after B.2 public block marker, or after t0
{
  const marker = 'USE_MODULAR_ROUTES dispatch';
  if (src.includes(marker)) {
    console.log('[skip] modular dispatch block');
  } else {
    const needle =
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
      "  }";

    const insert =
      "  // Phase B.2: modular public routes (health + static dashboard)\n" +
      "  // Phase B.5: USE_MODULAR_ROUTES dispatch (opt-in; legacy still below)\n" +
      "  {\n" +
      "    const route = { method: m, pathname: p };\n" +
      "    const baseDeps = {\n" +
      "      send,\n" +
      "      jsonError,\n" +
      "      readBody,\n" +
      "      audit,\n" +
      "      version: typeof BROKER_VERSION !== 'undefined' ? BROKER_VERSION : '3.4.0',\n" +
      "      secretCache: SECRET_CACHE,\n" +
      "      config: CONFIG,\n" +
      "      dashboardDir: join(__dirname, 'dashboard'),\n" +
      "    };\n" +
      "    if (handleHealth(req, res, route, baseDeps)) return;\n" +
      "    if (handleStatic(req, res, route, baseDeps)) return;\n" +
      "    if (typeof useModularRoutes === 'function' && useModularRoutes()) {\n" +
      "      // Note: full API deps (ctx, MFA, proxyRequest) should be filled by server after identity\n" +
      "      // This early path only covers public handlers already handled above.\n" +
      "    }\n" +
      "  }";

    if (src.includes(needle)) {
      src = src.replace(needle, insert);
      n++;
      console.log('[ok]   expand B.2 block for B.5');
    } else if (src.includes('handleHealth(req, res, route, deps)')) {
      console.log('[skip] public modular already present (manual expand if needed)');
    } else {
      console.warn('[miss] B.2 public block — run apply-phase-b2-server-wire.mjs first');
    }
  }
}

if (src === original) {
  console.log('\nNo file changes. Ensure B.2 wire applied; cutover is primarily env + process.');
  process.exit(0);
}

writeFileSync(SERVER, src);
console.log('\nWrote ' + SERVER + ' (' + n + ' patch groups).');
console.log('Enable: USE_MODULAR_ROUTES=1 node broker/server.js');
