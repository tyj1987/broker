// broker-test/test-sse-cap.js — V4.8.0 broker/lib/sse-cap.js 单元测试
// 覆盖 adminSseKey / tryAcquireSseSlot / releaseSseSlot / 边界 / per-admin 隔离

import {
  createSseCap,
  adminSseKey,
  tryAcquireSseSlot,
  releaseSseSlot,
  _resetSseCapForTests,
  _getSseCountForTests,
} from '../broker/lib/sse-cap.js';

let pass = 0,
  fail = 0;
function ok(name, cond, detail) {
  if (cond) {
    pass++;
    console.log(`  PASS  ${name}`);
  } else {
    fail++;
    console.error(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`);
  }
}
function section(t) {
  console.log(`\n[${t}]`);
}

const cap = createSseCap();
_resetSseCapForTests();

// ============================================================
// adminSseKey
// ============================================================
section('adminSseKey');
{
  ok('uses clientName when present', adminSseKey('client.alice') === 'audit-stream:client.alice');
  ok('falls back to "unknown" for null', adminSseKey(null) === 'audit-stream:unknown');
  ok('falls back to "unknown" for empty string', adminSseKey('') === 'audit-stream:unknown');
}

// ============================================================
// tryAcquireSseSlot — basic
// ============================================================
section('tryAcquireSseSlot (basic)');
{
  const key = 'audit-stream:test-admin';
  const r1 = cap.tryAcquireSseSlot(key);
  ok('first acquire: acquired=true', r1.acquired === true);
  ok('first acquire: current=0 (before)', r1.current === 0);
  ok('first acquire: limit=3', r1.limit === 3);
  ok('count is now 1', cap._getSseCountForTests(key) === 1);

  const r2 = cap.tryAcquireSseSlot(key);
  ok('second acquire: acquired=true', r2.acquired === true);
  ok('count is now 2', cap._getSseCountForTests(key) === 2);

  const r3 = cap.tryAcquireSseSlot(key);
  ok('third acquire: acquired=true', r3.acquired === true);
  ok('count is now 3', cap._getSseCountForTests(key) === 3);

  const r4 = cap.tryAcquireSseSlot(key);
  ok('fourth acquire: acquired=false (at limit)', r4.acquired === false);
  ok('fourth acquire: current=3', r4.current === 3);
  ok('count remains 3 after rejected attempt', cap._getSseCountForTests(key) === 3);

  const r5 = cap.tryAcquireSseSlot(key);
  ok('fifth acquire: still rejected', r5.acquired === false);
}

// ============================================================
// releaseSseSlot
// ============================================================
section('releaseSseSlot');
{
  const key = 'audit-stream:release-test';
  cap.tryAcquireSseSlot(key);
  cap.tryAcquireSseSlot(key);
  cap.tryAcquireSseSlot(key); // count = 3
  ok('at limit', cap.tryAcquireSseSlot(key).acquired === false);

  cap.releaseSseSlot(key); // 2
  ok('after release: can acquire again', cap.tryAcquireSseSlot(key).acquired === true);
  ok('count back to 3', cap._getSseCountForTests(key) === 3);
}

// ============================================================
// release past zero (should not underflow)
// ============================================================
section('release past zero');
{
  const key = 'audit-stream:underflow';
  cap.tryAcquireSseSlot(key);
  cap.releaseSseSlot(key);
  ok('count is 0 after full release', cap._getSseCountForTests(key) === 0);
  cap.releaseSseSlot(key); // extra release
  cap.releaseSseSlot(key); // extra release
  ok('extra release: count still 0 (no underflow)', cap._getSseCountForTests(key) === 0);
  // Key should be removed from Map (cleanup)
  cap.tryAcquireSseSlot(key);
  ok('after re-acquire, count is 1', cap._getSseCountForTests(key) === 1);
}

// ============================================================
// per-admin isolation
// ============================================================
section('per-admin isolation');
{
  _resetSseCapForTests();
  const keyA = adminSseKey('client.alice');
  const keyB = adminSseKey('client.bob');
  // alice fills her quota
  cap.tryAcquireSseSlot(keyA);
  cap.tryAcquireSseSlot(keyA);
  cap.tryAcquireSseSlot(keyA);
  ok('alice at limit', cap.tryAcquireSseSlot(keyA).acquired === false);
  // bob can still acquire
  ok('bob can still acquire (per-admin isolation)', cap.tryAcquireSseSlot(keyB).acquired === true);
  ok('bob count is 1', cap._getSseCountForTests(keyB) === 1);
  ok('alice count still 3', cap._getSseCountForTests(keyA) === 3);
}

// ============================================================
// _resetSseCapForTests
// ============================================================
section('_resetSseCapForTests');
{
  cap.tryAcquireSseSlot('test');
  cap.tryAcquireSseSlot('test');
  ok('count > 0 before reset', cap._getSseCountForTests('test') > 0);
  _resetSseCapForTests();
  ok('count is 0 after reset', cap._getSseCountForTests('test') === 0);
}

// ============================================================
// module-level factory vs createSseCap
// ============================================================
section('module-level + factory share state');
{
  _resetSseCapForTests();
  const cap2 = createSseCap(); // new factory instance
  // Both instances share the underlying Map (module-level)
  tryAcquireSseSlot('shared');
  ok('cap2 sees the same state', cap2._getSseCountForTests('shared') === 1);
  cap2.releaseSseSlot('shared');
  ok('cap2 release reflected in module-level', _getSseCountForTests('shared') === 0);
}

console.log(`\n=== Total: ${pass} passed, ${fail} failed ===`);
process.exit(fail > 0 ? 1 : 0);
