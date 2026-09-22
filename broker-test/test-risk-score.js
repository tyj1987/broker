// broker-test/test-risk-score.js — V4.7.0 broker/lib/risk-score.js 单元测试
// 覆盖 calcRiskScore 的 5 维度(unusual_ip / stale_account / sensitive_action /
// unusual_hour / user_agent_changed)+ 累积 cap=100 + SENSITIVE_ACTIONS set。

import { calcRiskScore, SENSITIVE_ACTIONS } from '../broker/lib/risk-score.js';

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

const TEST_NOW = new Date('2026-09-01T12:00:00Z');

// ============================================================
// unusual_ip (+30)
// ============================================================
section('unusual_ip');
{
  const r = calcRiskScore({
    source_ip: '8.8.8.8',
    client: { ip_whitelist: ['10.0.0.0/8'] },
    now: TEST_NOW,
  });
  ok('IP outside whitelist → unusual_ip +30', r.score === 30 && r.factors.includes('unusual_ip'));
}
{
  const r = calcRiskScore({
    source_ip: '10.1.2.3',
    client: { ip_whitelist: ['10.0.0.0/8'] },
    now: TEST_NOW,
  });
  ok('IP inside whitelist → no factor', r.score === 0 && !r.factors.includes('unusual_ip'));
}
{
  const r = calcRiskScore({ now: TEST_NOW }); // no IP / client
  ok('missing IP and client → 0', r.score === 0 && r.factors.length === 0);
}

// ============================================================
// stale_account
// ============================================================
section('stale_account');
{
  const old = TEST_NOW.getTime() - 40 * 86400_000; // 40 days ago
  const r = calcRiskScore({ last_login_at: old, now: TEST_NOW });
  ok('40 days stale → stale_account +20', r.score === 20 && r.factors.includes('stale_account'));
}
{
  const recent = TEST_NOW.getTime() - 3 * 86400_000; // 3 days
  const r = calcRiskScore({ last_login_at: recent, now: TEST_NOW });
  ok('< 7 days → no factor', r.score === 0);
}
{
  const ten = TEST_NOW.getTime() - 10 * 86400_000; // 10 days → stale_account_minor +10
  const r = calcRiskScore({ last_login_at: ten, now: TEST_NOW });
  ok(
    '10 days → stale_account_minor +10',
    r.score === 10 && r.factors.includes('stale_account_minor'),
  );
}
{
  const r = calcRiskScore({ last_login_at: 0, now: TEST_NOW }); // 0 → falsy
  ok('last_login_at=0 → ignored', r.score === 0);
}

// ============================================================
// sensitive_action
// ============================================================
section('sensitive_action');
{
  const r = calcRiskScore({ action: 'rotate-cert', now: TEST_NOW });
  ok(
    'rotate-cert in SENSITIVE_ACTIONS → +25',
    r.score === 25 && r.factors.includes('sensitive_action'),
  );
}
{
  const r = calcRiskScore({ action: 'unknown-action', now: TEST_NOW });
  ok('unknown action → no factor', r.score === 0);
}

// ============================================================
// unusual_hour
// ============================================================
section('unusual_hour');
{
  // local 3 AM
  const r = calcRiskScore({ now: new Date(2026, 8, 1, 3, 0, 0) });
  ok('3 AM local → unusual_hour +10', r.score === 10 && r.factors.includes('unusual_hour'));
}
{
  const r = calcRiskScore({ now: new Date(2026, 8, 1, 11, 0, 0) });
  ok('11 AM local → no factor', r.score === 0);
}
{
  const r = calcRiskScore({ now: new Date(2026, 8, 1, 23, 0, 0) });
  ok('23:00 local → unusual_hour', r.score === 10);
}

// ============================================================
// user_agent_changed
// ============================================================
section('user_agent_changed');
{
  const r = calcRiskScore({ user_agent: 'A', last_user_agent: 'B', now: TEST_NOW });
  ok('UA changed → +15', r.score === 15 && r.factors.includes('user_agent_changed'));
}
{
  const r = calcRiskScore({ user_agent: 'A', last_user_agent: 'A', now: TEST_NOW });
  ok('UA unchanged → no factor', r.score === 0);
}
{
  const r = calcRiskScore({ user_agent: 'A', now: TEST_NOW }); // no last_user_agent
  ok('missing last_user_agent → no factor', r.score === 0);
}

// ============================================================
// cap at 100
// ============================================================
section('cap at 100');
{
  // 30 + 20 + 25 + 10 + 15 = 100 (just at limit)
  const old = TEST_NOW.getTime() - 40 * 86400_000;
  const r = calcRiskScore({
    source_ip: '8.8.8.8',
    client: { ip_whitelist: ['10.0.0.0/8'] },
    last_login_at: old,
    action: 'rotate-cert',
    user_agent: 'A',
    last_user_agent: 'B',
    now: new Date(2026, 8, 1, 3, 0, 0), // 3 AM local
  });
  ok('all 5 factors at boundary → score=100', r.score === 100);
  ok('5 factors listed', r.factors.length === 5);
}
{
  // 30 + 20 + 25 + 10 + 15 = 100, but cap is 100 not more
  const r = calcRiskScore({
    source_ip: '8.8.8.8',
    client: { ip_whitelist: ['10.0.0.0/8'] },
    last_login_at: 0, // 故意无效以避免 stale_account
    action: 'rotate-cert',
    user_agent: 'A',
    last_user_agent: 'B',
    now: new Date(2026, 8, 1, 12, 0, 0), // noon
  });
  // 30 + 0 + 25 + 0 + 15 = 70
  ok('without stale + without unusual_hour → 70', r.score === 70);
}

// ============================================================
// SENSITIVE_ACTIONS set
// ============================================================
section('SENSITIVE_ACTIONS');
{
  ok('is Set', SENSITIVE_ACTIONS instanceof Set);
  ok('contains rotate-cert', SENSITIVE_ACTIONS.has('rotate-cert'));
  ok('contains delete-secret', SENSITIVE_ACTIONS.has('delete-secret'));
  ok('contains rotate-secret', SENSITIVE_ACTIONS.has('rotate-secret'));
  ok('contains change-password', SENSITIVE_ACTIONS.has('change-password'));
  ok('contains admin:reload', SENSITIVE_ACTIONS.has('admin:reload'));
  ok('contains revoke-api-key', SENSITIVE_ACTIONS.has('revoke-api-key'));
  ok('does not contain login', !SENSITIVE_ACTIONS.has('login'));
}

console.log(`\n=== Total: ${pass} passed, ${fail} failed ===`);
process.exit(fail > 0 ? 1 : 0);
