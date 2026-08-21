#!/usr/bin/env node
/**
 * apply-phase-b4-server-wire.mjs
 *
 * Extends Phase A+B.2 wire:
 *  - Import all route handlers
 *  - After identity resolution, optionally note that modular routes exist
 *  - Does NOT remove legacy blocks (safe dual-path until smoke)
 *
 * Prefer running apply-phase-b2-server-wire.mjs first.
 *
 * Usage (repo root):
 *   node scripts/broker/apply-phase-b4-server-wire.mjs
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
    if (src.includes(replace.slice(0, Math.min(40, replace.length)))) {
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

// Expand imports if only health/static present
once(
  'import auth/me/secrets routes',
  "import { handleHealth, handleStatic } from './routes/index.js';",
  "import {\n  handleHealth,\n  handleStatic,\n  handleAuth,\n  handleMe,\n  handleSecrets,\n  handleServices,\n  handleClients,\n  handleProxy,\n} from './routes/index.js';"
);

// Marker comment for operators (idempotent)
once(
  'B.4 marker comment',
  "  // Phase B.2: modular public routes (health + static dashboard)",
  "  // Phase B.2+B.4: modular public routes (health + static); auth/me/CRUD available via routes/*\n  // Phase B.2: modular public routes (health + static dashboard)"
);

if (src === original) {
  console.log('\nNo changes (run B.2 wire first, or already expanded).');
  process.exit(0);
}

writeFileSync(SERVER, src);
console.log('\nWrote ' + SERVER + ' (' + n + ' patch groups).');
console.log('Modular route modules are imported; legacy handlers still active until full cutover.');
