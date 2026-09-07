// broker-test/test-dashboard-admin-visibility.js
// Contract for the identity event → admin chrome. No jsdom.

import { applyAdminVisibility, isAdminIdentity } from '../broker/lib/admin-visibility.js';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
let passed = 0, failed = 0;
function assert(c, m) {
  if (c) { passed++; console.log('  OK  ', m); }
  else { failed++; console.error('  FAIL', m); }
}

console.log('=== isAdminIdentity ===');
assert(isAdminIdentity({ role: 'admin' }) === true, 'admin');
assert(isAdminIdentity({ role: 'developer' }) === false, 'developer');
assert(isAdminIdentity({ role: 'readonly' }) === false, 'readonly');
assert(isAdminIdentity(null) === false, 'null');
assert(isAdminIdentity(undefined) === false, 'undefined');

console.log('=== applyAdminVisibility ===');
{
  const els = [{ hidden: true }, { hidden: true }, { hidden: false }];
  applyAdminVisibility(true, els);
  assert(els.every(e => e.hidden === false), 'admin unhides all');
  applyAdminVisibility(false, els);
  assert(els.every(e => e.hidden === true), 'non-admin hides all');
}

console.log('=== dashboard scripts subscribe instead of 30s poll ===');
{
  const root = join(__dirname, '..', 'broker', 'dashboard');
  const files = [
    'app.js',
    'home.js',
    'admin/secrets.js',
    'admin/services.js',
    'admin/clients.js',
    'admin/audit.js',
  ];
  for (const f of files) {
    const src = readFileSync(join(root, f), 'utf8');
    assert(!src.includes('setInterval'), `${f} has no identity setInterval`);
    assert(!src.includes('30000'), `${f} has no 30s poll timeout`);
  }
  const app = readFileSync(join(root, 'app.js'), 'utf8');
  assert(app.includes("CustomEvent('broker:identity'"), 'app.js emits broker:identity');
  assert(app.includes('emitBrokerIdentity(ident)'), 'boot emits identity');
  assert(app.includes('emitBrokerIdentity(null)'), 'logout clears identity');
  assert(!/loadServices\(\)\.catch/.test(app.split('async function boot')[1] || ''), 'boot does not eager-load services');
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
