// broker-test/test-lib-phase-b.js — unit tests for Phase B lib modules
// Run: node broker-test/test-lib-phase-b.js

import { createRateLimiter, parseRateLimit } from '../broker/lib/rate-limit.js';
import { buildZip, computeCrc32 } from '../broker/lib/zip.js';
import { createAudit } from '../broker/lib/audit.js';
import { send, jsonError } from '../broker/lib/http.js';
import { BROKER_VERSION } from '../broker/version.js';
import { requireValidBrokerConfig } from '../broker/lib/index.js';
import { mkdtempSync, rmSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

let passed = 0;
let failed = 0;

if (typeof requireValidBrokerConfig !== 'function') {
  throw new Error('lib index must export requireValidBrokerConfig used by server startup');
}

function assert(cond, msg) {
  if (cond) { passed++; console.log('  OK  ', msg); }
  else { failed++; console.error('  FAIL', msg); }
}

console.log('=== parseRateLimit ===');
{
  const p = parseRateLimit('100/hour');
  assert(p && p.max === 100 && p.windowMs === 3_600_000, '100/hour');
  assert(parseRateLimit('unlimited') === null, 'unlimited');
  assert(parseRateLimit('10/minute')?.windowMs === 60_000, '10/minute');
  assert(parseRateLimit('bad') === null, 'invalid');
}

console.log('=== createRateLimiter ===');
{
  const check = createRateLimiter();
  assert(check('k1', '2/hour') === true, 'first allow');
  assert(check('k1', '2/hour') === true, 'second allow');
  assert(check('k1', '2/hour') === false, 'third deny');
  assert(check('k2', '2/hour') === true, 'other key independent');
}

console.log('=== zip CRC + buildZip ===');
{
  const empty = computeCrc32(Buffer.alloc(0));
  assert(empty === 0, 'CRC32 empty');
  const z = buildZip([{ name: 'a.txt', data: 'hello' }]);
  assert(Buffer.isBuffer(z) && z.length > 30, 'buildZip produces buffer');
  assert(z.readUInt32LE(0) === 0x04034b50, 'local header signature');
}

console.log('=== createAudit ===');
{
  const dir = mkdtempSync(join(tmpdir(), 'broker-audit-'));
  try {
    const { audit, readAudit, bus } = createAudit(dir);
    let saw = false;
    bus.on('event', () => { saw = true; });
    const e = audit({ action: 'test', status: 'ok' });
    assert(!!e.id && !!e.ts, 'audit returns event');
    // bus emits async via setImmediate
    // sync read from file
    const events = readAudit({ limit: 10 });
    assert(events.length >= 1 && events[0].action === 'test', 'readAudit sees event');
    const files = readdirSync(dir).filter(f => f.endsWith('.jsonl'));
    assert(files.length >= 1, 'jsonl file created');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

console.log('=== http send omits version unless requested ===');
{
  const headers = {};
  const res = {
    writeHead(status, h) { Object.assign(headers, h); this.status = status; },
    end() {},
  };
  send(res, 200, { ok: true });
  assert(headers['X-Broker-Version'] === undefined, 'no version on public send');
  send(res, 200, { ok: true }, { exposeVersion: true });
  assert(headers['X-Broker-Version'] === BROKER_VERSION, `exposeVersion sets ${BROKER_VERSION}`);
  jsonError(res, 400, 'bad');
  assert(res.status === 400, 'jsonError status');
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
