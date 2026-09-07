// broker-test/test-phase-f-backup-probes.js
import {
  buildBackupManifest,
  redactConfigForExport,
  writeBackupManifest,
} from '../broker/lib/backup.js';
import { runProbes, probesFromConfig, probeTcp } from '../broker/lib/probes.js';
// chore/oss-modular-security: handleOps moved to experimental (UNSUPPORTED).
import { handleOps } from '../broker/experimental/modular-routes/ops.js';
import { handleHealth } from '../broker/routes/health.js';
import { mkdirSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { BROKER_VERSION } from '../broker/version.js';

let passed = 0, failed = 0;
function assert(c, m) {
  if (c) { passed++; console.log('  OK  ', m); }
  else { failed++; console.error('  FAIL', m); }
}

console.log('=== version ===');
assert(BROKER_VERSION === '4.1.4', '4.1.4');

console.log('=== redactConfigForExport ===');
{
  const r = redactConfigForExport({
    clients: { a: { role: 'admin', password: 'secret', totp_secret: 'ABC' } },
    api_keys: [{ secret: 'sk_live', client: 'a' }],
  });
  assert(r.clients.a.password === '[REDACTED]', 'password');
  assert(r.clients.a.totp_secret === '[REDACTED]', 'totp');
  assert(r.api_keys[0].secret === '[REDACTED]', 'api key');
}

console.log('=== buildBackupManifest ===');
{
  const dir = join(tmpdir(), 'broker-bak-' + Date.now());
  mkdirSync(dir, { recursive: true });
  const cfg = join(dir, 'config.yaml');
  writeFileSync(cfg, 'clients: {}\n');
  const m = buildBackupManifest({
    configPath: cfg,
    ageKeyPath: join(dir, 'missing.key'),
  });
  assert(m.files.some((f) => f.present && f.name === 'config.yaml'), 'config present');
  assert(m.missing_required.some((p) => p.includes('missing.key')), 'missing age');
  assert(m.checklist.length >= 5, 'checklist');
  const out = writeBackupManifest(dir, { configPath: cfg });
  assert(readFileSync(out, 'utf8').includes('generated_at'), 'write manifest');
  rmSync(dir, { recursive: true, force: true });
}

console.log('=== probesFromConfig ===');
{
  const specs = probesFromConfig({
    services: {
      a: { healthcheck: { url: 'http://127.0.0.1:1/x', critical: false } },
      b: { probe: { host: '127.0.0.1', port: 1, critical: false } },
    },
  });
  assert(specs.length === 2, 'two probes');
}

console.log('=== runProbes non-critical fail still ok ===');
{
  const r = await runProbes([
    { name: 'x', type: 'tcp', host: '127.0.0.1', port: 1, critical: false, timeoutMs: 200 },
  ]);
  assert(r.ok === true, 'non-critical');
  assert(r.probes[0].ok === false, 'probe failed');
}

console.log('=== handleOps admin ===');
{
  const res = { status: 0, body: null };
  const send = (r, s, b) => { r.status = s; r.body = b; };
  const jsonError = (r, s, m) => { r.status = s; r.body = { error: m }; };
  await handleOps({}, res, { method: 'GET', pathname: '/api/v1/ops/config-export' }, {
    send, jsonError, ctx: { client: { role: 'developer' } }, config: {},
  });
  assert(res.status === 403, 'forbidden');
  await handleOps({}, res, { method: 'GET', pathname: '/api/v1/ops/config-export' }, {
    send, jsonError,
    ctx: { client: { role: 'admin' } },
    config: { clients: { a: { password: 'x' } } },
  });
  assert(res.status === 200 && res.body.config.clients.a.password === '[REDACTED]', 'export');
}

console.log('=== ready with probes hook ===');
{
  const res = { status: 0, body: null };
  const send = (r, s, b) => { r.status = s; r.body = b; };
  await handleHealth({}, res, { method: 'GET', pathname: '/ready' }, {
    send,
    secretCache: new Map([['k', 1]]),
    config: {},
    requireSops: true,
    surface: 'local',
    runReadyProbes: async () => ({ ok: true, probes: [{ name: 't', ok: true }] }),
  });
  assert(res.status === 200 && res.body.probes?.[0]?.ok === true, 'ready probes');
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
