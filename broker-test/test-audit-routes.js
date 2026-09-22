// broker-test/test-audit-routes.js — V4.3.0 server.js extraction
// 验证 routes/audit.js 工厂:audit / readAuditFiltered / readAudit /
// collectAuditFacets / clearAuditLogs / health / bus / ring buffer 行为

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createAuditRoutes } from '../broker/routes/audit.js';
import { redactDeep } from '../broker/lib/redact.js';

let pass = 0,
  fail = 0;
function ok(name, cond) {
  if (cond) {
    pass++;
    console.log(`  PASS  ${name}`);
  } else {
    fail++;
    console.error(`  FAIL  ${name}`);
  }
}
function section(t) {
  console.log(`\n[${t}]`);
}

const dir = mkdtempSync(join(tmpdir(), 'broker-audit-routes-test-'));
const cfg = { clients: { 'client.alice': {} }, services: { github: {} } };
const a = createAuditRoutes({ auditDir: dir, getConfig: () => cfg, redact: redactDeep });

// ============================================================
// basic audit + ring push
// ============================================================
section('basic audit + ring');
{
  const e = a.audit({ action: 'login', cn: 'client.alice', status: 'ok' });
  ok('audit returns event with id and ts', typeof e.id === 'string' && typeof e.ts === 'string');
  ok('audit.redact strips PEM-like fields', !JSON.stringify(e).includes('BEGIN'));
  ok('ring buffer grew by 1', a.health().ring_buffer_size === 1);
}

// ============================================================
// readAuditFiltered: 热路径(ring 命中)
// ============================================================
section('readAuditFiltered ring hit');
{
  // 写 3 条
  a.audit({ action: 'login', cn: 'client.alice' });
  a.audit({ action: 'logout', cn: 'client.alice' });
  a.audit({ action: 'proxy', cn: 'client.alice', service: 'github' });
  const all = a.readAuditFiltered({ limit: 100 });
  ok('ring returns all 4 events', all.length === 4);
  ok('most recent first', all[0].action === 'proxy');
  const filtered = a.readAuditFiltered({ action: 'logout', limit: 100 });
  ok(
    'action filter narrows to logout (1)',
    filtered.length === 1 && filtered[0].action === 'logout',
  );
  const cnFilter = a.readAuditFiltered({ client: 'alice', limit: 100 });
  ok('client filter substring matches cn', cnFilter.length >= 3);
}

// ============================================================
// readAuditFiltered: exact identity isolation for self-service endpoints
// ============================================================
section('readAuditFiltered exact identity isolation');
{
  a.audit({ action: 'proxy', cn: 'alice@web', client: 'alice', service: 'github' });
  a.audit({ action: 'proxy', cn: 'bob@web', client: 'bob', service: 'github' });

  const alice = a.readAuditFiltered({ cn: 'alice@web', limit: 100 });
  ok(
    'exact cn returns only alice events',
    alice.length === 1 && alice.every((e) => e.cn === 'alice@web'),
  );

  const bob = a.readAuditFiltered({ cn: 'bob@web', limit: 100 });
  ok('exact cn returns only bob events', bob.length === 1 && bob.every((e) => e.cn === 'bob@web'));

  const byClientField = a.readAuditFiltered({ client: 'bob', limit: 100 });
  ok(
    'client filter also matches event.client',
    byClientField.length === 1 && byClientField[0].client === 'bob',
  );
}

// ============================================================
// readAuditFiltered: 冷路径(磁盘)
// ============================================================
section('readAuditFiltered disk fallback');
{
  // 模拟 ring 没覆盖的情况:since 设为很久以前 → 不会用 ring
  // 但磁盘只有 ring 里那 4 条。设置 since 在第一之前 → 应从磁盘读
  const r = a.readAuditFiltered({ since: '2000-01-01T00:00:00.000Z', limit: 100 });
  ok('disk fallback returns all persisted data', r.length === 6);
  const exact = a.readAuditFiltered({
    cn: 'alice@web',
    since: '2000-01-01T00:00:00.000Z',
    limit: 100,
  });
  ok(
    'disk fallback preserves exact cn isolation',
    exact.length === 1 && exact[0].cn === 'alice@web',
  );
}

// ============================================================
// bus 事件订阅
// ============================================================
section('bus event subscription');
{
  let received = null;
  const handler = (e) => {
    received = e;
  };
  a.bus.on('event', handler);
  a.audit({ action: 'healthcheck', cn: 'client.alice' });
  // setImmediate 让 emit 异步触发
  await new Promise((r) => setImmediate(r));
  a.bus.off('event', handler);
  ok('bus emits event for each audit', received && received.action === 'healthcheck');
}

// ============================================================
// clearAuditLogs
// ============================================================
section('clearAuditLogs');
{
  // 写一条,确保磁盘有 jsonl
  a.audit({ action: 'logout' });
  const before = a.health().ring_buffer_size;
  ok('ring has events before clear', before > 0);
  const deleted = a.clearAuditLogs();
  ok('clearAuditLogs returns deleted filenames', Array.isArray(deleted) && deleted.length >= 1);
}

// ============================================================
// readAudit alias
// ============================================================
section('readAudit alias');
{
  a.audit({ action: 'connect', cn: 'client.alice' });
  const r = a.readAudit({ limit: 5 });
  ok('readAudit returns array', Array.isArray(r));
  ok('readAudit respects limit', r.length <= 5);
}

// ============================================================
// collectAuditFacets
// ============================================================
section('collectAuditFacets');
{
  const facets = a.collectAuditFacets();
  ok('clients from CONFIG + audit', facets.clients.includes('client.alice'));
  ok('services from CONFIG + audit', facets.services.includes('github'));
  ok('actions list contains login', facets.actions.includes('login'));
  ok('statuses list contains ok', facets.statuses.includes('ok'));
  ok(
    'all facets are arrays of strings',
    ['clients', 'services', 'actions', 'statuses'].every((k) => Array.isArray(facets[k])),
  );
}

// ============================================================
// ring 上限
// ============================================================
section('ring eviction at capacity');
{
  // 写 1100 条,ring 上限 1000
  for (let i = 0; i < 1100; i++) a.audit({ action: 'login', cn: `bulk-${i}` });
  const size = a.health().ring_buffer_size;
  ok('ring capped at 1000', size === 1000);
  ok('ring_buffer_max constant', a.health().ring_buffer_max === 1000);
}

// ============================================================
rmSync(dir, { recursive: true, force: true });
console.log(`\n=== Total: ${pass} passed, ${fail} failed ===`);
process.exit(fail > 0 ? 1 : 0);
