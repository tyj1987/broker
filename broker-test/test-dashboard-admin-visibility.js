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
  const html = readFileSync(join(root, 'index.html'), 'utf8');
  const auditUi = readFileSync(join(root, 'admin/audit.js'), 'utf8');
  const clientsUi = readFileSync(join(root, 'admin/clients.js'), 'utf8');
  const server = readFileSync(join(root, '..', 'server.js'), 'utf8');
  assert(!html.includes('btn-audit-clear'), 'dashboard has no audit deletion control');
  assert(!auditUi.includes('clearAuditLogs'), 'dashboard cannot request audit deletion');
  assert(server.includes("jsonError(res, 405, 'Audit records are immutable')"), 'server denies audit deletion');
  assert(!clientsUi.includes('配置有 fp, 文件缺失'), 'clients UI does not misreport externally managed certificates as missing');
  assert(clientsUi.includes('已注册（外部管理）'), 'clients UI labels registered certificates in external-management mode');
  assert(clientsUi.includes('if (!pkiWritable)'), 'external-management label is limited to read-only PKI mode');
  assert(clientsUi.includes('⚠ 证书副本缺失'), 'writable PKI mode still warns when its certificate copy is missing');
  assert(html.includes('Broker 只保存已授权证书指纹，不保存客户端私钥'), 'read-only PKI banner explains the production trust boundary');
  assert(!html.includes('scripts/issue-client-cert.sh'), 'dashboard does not recommend a missing production script');
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
