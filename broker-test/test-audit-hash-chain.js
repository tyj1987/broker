// broker-test/test-audit-hash-chain.js — V4.1.1 tests for broker/lib/audit-hash-chain.js
//
// Verifies the tamper-evident hash chain for audit events.
//
// Coverage:
//   1. computeHash is deterministic
//   2. computeHash differs for different inputs
//   3. sealEvent produces event with prev_hash + hash
//   4. Genesis event uses 0x00 * 32 as prev_hash
//   5. Two events chain via prev_hash
//   6. verifyChain passes for valid chain
//   7. verifyChain fails on tampered event
//   8. verifyChain fails on tampered prev_hash
//   9. verifyChain fails when an event is removed from middle
//  10. verifyChain passes for empty array
//  11. createChainWriter chains correctly across many events
//  12. createChainWriter counts events
//  13. verifyAuditDir works on real files

import {
  computeHash,
  sealEvent,
  verifyChain,
  verifyAuditDir,
  createChainWriter,
  GENESIS_HASH,
} from '../broker/lib/audit-hash-chain.js';
import { mkdtempSync, rmSync, writeFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

let pass = 0, fail = 0;
function ok(name, cond, detail) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`); }
}
function section(t) { console.log(`\n[${t}]`); }

// ---------- tests ----------

section('1. computeHash determinism');

{
  const h1 = computeHash({ a: 1, b: 'x' });
  const h2 = computeHash({ a: 1, b: 'x' });
  ok('same input → same hash', h1 === h2);
  ok('64 hex chars', /^[a-f0-9]{64}$/.test(h1));
}

section('2. computeHash distinguishes inputs');

{
  const h1 = computeHash({ a: 1 });
  const h2 = computeHash({ a: 2 });
  ok('different input → different hash', h1 !== h2);
}

section('3. sealEvent adds prev_hash + hash');

{
  const e = sealEvent({ action: 'login', cn: 'alice' }, null);
  ok('event has prev_hash', typeof e.prev_hash === 'string');
  ok('event has hash', typeof e.hash === 'string');
  ok('original fields preserved', e.action === 'login' && e.cn === 'alice');
}

section('4. Genesis event uses 0x00 * 32 as prev_hash');

{
  const e = sealEvent({ action: 'genesis' }, null);
  ok('prev_hash is GENESIS', e.prev_hash === GENESIS_HASH);
}

section('5. Two events chain');

{
  const e1 = sealEvent({ action: 'login' }, null);
  const e2 = sealEvent({ action: 'resolve' }, e1.hash);
  ok('e2.prev_hash === e1.hash', e2.prev_hash === e1.hash);
  ok('hashes differ', e1.hash !== e2.hash);
}

section('6. verifyChain passes for valid chain');

{
  const e1 = sealEvent({ action: 'login' }, null);
  const e2 = sealEvent({ action: 'resolve' }, e1.hash);
  const e3 = sealEvent({ action: 'logout' }, e2.hash);
  const r = verifyChain([e1, e2, e3]);
  ok('ok=true', r.ok === true);
  ok('count=3', r.count === 3);
}

section('7. verifyChain fails on tampered event');

{
  const e1 = sealEvent({ action: 'login' }, null);
  const e2 = sealEvent({ action: 'resolve' }, e1.hash);
  const e3 = sealEvent({ action: 'logout' }, e2.hash);
  // Tamper with e2's action
  const tampered = [{ ...e1 }, { ...e2, action: 'resolve-FORGED' }, { ...e3 }];
  const r = verifyChain(tampered);
  ok('ok=false', r.ok === false);
  ok('broken_at=1', r.broken_at === 1);
  ok('reason mentions hash mismatch', /hash mismatch/.test(r.reason || ''));
}

section('8. verifyChain fails on tampered prev_hash');

{
  const e1 = sealEvent({ action: 'login' }, null);
  const e2 = sealEvent({ action: 'resolve' }, e1.hash);
  const e3 = sealEvent({ action: 'logout' }, e2.hash);
  // Tamper with e3's prev_hash
  const tampered = [{ ...e1 }, { ...e2 }, { ...e3, prev_hash: '0'.repeat(64) }];
  const r = verifyChain(tampered);
  ok('ok=false', r.ok === false);
  ok('broken_at=2', r.broken_at === 2);
  ok('reason mentions prev_hash', /prev_hash/.test(r.reason || ''));
}

section('9. verifyChain fails when event is removed from middle');

{
  const e1 = sealEvent({ action: 'login' }, null);
  const e2 = sealEvent({ action: 'resolve' }, e1.hash);
  const e3 = sealEvent({ action: 'logout' }, e2.hash);
  const r = verifyChain([e1, e3]); // skip e2
  ok('ok=false', r.ok === false);
}

section('10. verifyChain passes for empty array');

{
  const r = verifyChain([]);
  ok('ok=true', r.ok === true);
  ok('count=0', r.count === 0);
}

section('11. createChainWriter chains correctly');

{
  const events = [];
  const writer = createChainWriter({ onEvent: e => events.push(e) });
  for (let i = 0; i < 10; i++) {
    writer.write({ action: 'test', n: i });
  }
  ok('count=10', writer.count === 10);
  ok('10 events captured', events.length === 10);
  const r = verifyChain(events);
  ok('chain verifies', r.ok === true);
}

section('12. createChainWriter survives tampering');

{
  const events = [];
  const writer = createChainWriter({ onEvent: e => events.push(e) });
  for (let i = 0; i < 5; i++) writer.write({ action: 'test', n: i });
  // Tamper with event #2
  events[2].action = 'TAMPERED';
  const r = verifyChain(events);
  ok('tampering detected', r.ok === false);
  ok('broken_at=2', r.broken_at === 2);
}

section('13. verifyAuditDir works on real files');

{
  const WORK = mkdtempSync(join(tmpdir(), 'broker-chain-'));
  process.on('exit', () => { try { rmSync(WORK, { recursive: true, force: true }); } catch {} });
  // Create some audit files with chained events
  const writer = createChainWriter({ onEvent: e => {} });
  const events = [];
  for (let i = 0; i < 3; i++) {
    const ev = writer.write({ action: 'test', n: i });
    events.push(ev);
  }
  // Write to a file in the canonical location
  const day = new Date().toISOString().slice(0, 10);
  const file = join(WORK, `audit-${day}.jsonl`);
  const content = events.map(e => JSON.stringify(e)).join('\n') + '\n';
  writeFileSync(file, content);
  const r = await verifyAuditDir(WORK);
  ok('ok=true', r.ok === true);
  ok('count=3', r.count === 3);
  ok('files=1', r.files === 1);
}

// ---------- summary ----------

console.log(`\n=== ${pass} pass / ${fail} fail ===`);
process.exit(fail === 0 ? 0 : 1);
