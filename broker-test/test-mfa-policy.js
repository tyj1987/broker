// broker-test/test-mfa-policy.js — V4 风险评分 + MFA 决策
// Run: node broker-test/test-mfa-policy.js
import {
  calcRiskScore,
  SENSITIVE_ACTIONS,
  decideMfaRequirement,
  checkMfaProgress,
  loadMfaPolicy,
  DEFAULT_MFA_POLICY as DEFAULT_POLICY,
} from '../broker/lib/index.js';

let pass = 0, fail = 0;
function ok(name, cond) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}`); }
}
function section(t) { console.log(`\n[${t}]`); }

// === calcRiskScore ===
section('calcRiskScore basics');
{
  const r = calcRiskScore({ client: { role: 'developer' } });
  ok('no context = 0', r.score === 0 && r.factors.length === 0);
}
{
  const r = calcRiskScore({ source_ip: '8.8.8.8', client: { ip_whitelist: ['10.0.0.0/8'] } });
  ok('unusual_ip = 30', r.score === 30 && r.factors.includes('unusual_ip'));
}
{
  const old = Date.now() - 40 * 86400_000;  // 40 days ago
  const r = calcRiskScore({ last_login_at: old });
  ok('stale_account >30d = 20', r.score === 20 && r.factors.includes('stale_account'));
}
{
  const old = Date.now() - 10 * 86400_000;  // 10 days ago
  const r = calcRiskScore({ last_login_at: old });
  ok('stale 7-30d = 10', r.score === 10);
}
{
  const r = calcRiskScore({ action: 'rotate-cert' });
  ok('sensitive_action = 25', r.score === 25 && r.factors.includes('sensitive_action'));
}
{
  // 3 AM local (use Date(year, month-1, day, hour) constructor for local)
  const r = calcRiskScore({ now: new Date(2026, 8, 1, 3, 0, 0) });
  ok('unusual_hour at 3 = 10', r.score === 10 && r.factors.includes('unusual_hour'));
}
{
  const r = calcRiskScore({ user_agent: 'A', last_user_agent: 'B' });
  ok('user_agent_changed = 15', r.score === 15 && r.factors.includes('user_agent_changed'));
}
{
  // all factors combined
  const old = Date.now() - 40 * 86400_000;
  const r = calcRiskScore({
    source_ip: '8.8.8.8',
    client: { ip_whitelist: ['10.0.0.0/8'] },
    last_login_at: old,
    action: 'rotate-cert',
    user_agent: 'A', last_user_agent: 'B',
    now: new Date(2026, 8, 1, 3, 0, 0),  // local 3 AM
  });
  ok('combined = 30+20+25+10+15 = 100 (capped)', r.score === 100 && r.factors.length === 5);
}
{
  // low-risk path (mid-day, no flags)
  const r = calcRiskScore({ now: new Date('2026-09-01T12:00:00Z') });
  ok('low risk = 0', r.score === 0);
}

// === SENSITIVE_ACTIONS ===
section('sensitive actions set');
ok('SENSITIVE_ACTIONS is Set', SENSITIVE_ACTIONS instanceof Set);
ok('SENSITIVE_ACTIONS has rotate-cert', SENSITIVE_ACTIONS.has('rotate-cert'));
ok('SENSITIVE_ACTIONS has admin:reload', SENSITIVE_ACTIONS.has('admin:reload'));
ok('SENSITIVE_ACTIONS has disable-totp', SENSITIVE_ACTIONS.has('disable-totp'));

// === decideMfaRequirement — loadMfaPolicy ===
section('loadMfaPolicy');
{
  const p = loadMfaPolicy(null);
  ok('null config = DEFAULT', p === DEFAULT_POLICY);
}
{
  const p = loadMfaPolicy({});
  ok('empty config = DEFAULT', p === DEFAULT_POLICY);
}
{
  const p = loadMfaPolicy({ mfa_policy: { default_policy: { admin: { secondary_required_when: ['always'] } } } });
  ok('partial config merged', p.default_policy.admin.secondary_required_when[0] === 'always');
  ok('developer default still present', !!p.default_policy.developer);
}

// === decideMfaRequirement — no client ===
section('no client');
{
  const d = decideMfaRequirement({});
  ok('no client -> mfa required', d.mfa_required === true && d.reason === 'no_client');
}

// === decideMfaRequirement — by role ===
section('role-based policy');
{
  const d = decideMfaRequirement({ client: { role: 'admin' } });
  ok('admin always needs mfa', d.mfa_required === true && d.reason === 'role_always');
}
{
  const d = decideMfaRequirement({ client: { role: 'ci' } });
  ok('ci never needs mfa', d.mfa_required === false);
}
{
  const d = decideMfaRequirement({ client: { role: 'developer' } });
  ok('developer default low risk = no mfa', d.mfa_required === false);
}

// === decideMfaRequirement — by risk ===
section('risk-based');
{
  // client 必须有 ip_whitelist,否则 unusual_ip 不触发(空白名单=放行)
  const d = decideMfaRequirement({
    client: { role: 'developer', ip_whitelist: ['10.0.0.0/8'] },
    source_ip: '8.8.8.8',  // unusual_ip = 30
  });
  ok('developer with unusual_ip = 1 factor', d.mfa_required && d.min_count === 1 && d.reason === 'trigger_match');
}
{
  // Build a high-risk scenario: unusual_ip + 40d stale + sensitive = 75 (medium) but we need 60+ for medium, 100 for high
  // 30 + 20 + 25 = 75 -> medium
  const d = decideMfaRequirement({
    client: { role: 'developer', ip_whitelist: ['10.0.0.0/8'] },
    source_ip: '8.8.8.8',
    last_login_at: Date.now() - 40 * 86400_000,
    action: 'rotate-cert',  // sensitive -> returns at min_count=1 (early)
  });
  ok('sensitive action overrides -> min 1', d.reason === 'sensitive_action' && d.min_count === 1);
}
{
  // high risk via score (no sensitive action), unusual_ip + stale + UA + hour (use LOCAL 3AM)
  // 30 + 20 + 15 + 10 = 75 -> > 60 -> high_risk -> min 2
  const d = decideMfaRequirement({
    client: { role: 'developer', ip_whitelist: ['10.0.0.0/8'] },
    source_ip: '8.8.8.8',
    last_login_at: Date.now() - 40 * 86400_000,
    user_agent: 'new', last_user_agent: 'old',
    now: new Date(2026, 8, 1, 3, 0, 0),  // local 3 AM
  });
  ok('high risk = 2 factors', d.reason === 'high_risk' && d.min_count === 2);
}

// === decideMfaRequirement — options ===
section('options');
{
  const d = decideMfaRequirement({
    client: { role: 'developer', ip_whitelist: ['10.0.0.0/8'] },
    source_ip: '8.8.8.8',
  });
  ok('options has totp', d.options.includes('totp'));
  ok('options has webauthn', d.options.includes('webauthn'));
  ok('options has sms', d.options.includes('sms'));
  ok('options has recovery', d.options.includes('recovery'));
}

// === checkMfaProgress ===
section('MFA progress');
{
  const decision = { mfa_required: true, min_count: 2, options: ['totp', 'webauthn', 'sms'] };
  const p1 = checkMfaProgress([], decision);
  ok('start: 0/2 verified', p1.satisfied === false && p1.remaining === 2);

  const p2 = checkMfaProgress(['totp'], decision);
  ok('after totp: 1/2 verified', p2.satisfied === false && p2.remaining === 1);
  ok('next_options excludes totp', !p2.next_options.includes('totp'));
  ok('next_options has webauthn', p2.next_options.includes('webauthn'));

  const p3 = checkMfaProgress(['totp', 'webauthn'], decision);
  ok('2/2 verified = satisfied', p3.satisfied === true && p3.remaining === 0);

  // not required
  const p4 = checkMfaProgress([], { mfa_required: false, min_count: 0 });
  ok('not required = satisfied', p4.satisfied === true);
}

// === performance sanity ===
section('performance');
{
  const start = Date.now();
  for (let i = 0; i < 10_000; i++) {
    calcRiskScore({
      source_ip: '1.2.3.4',
      client: { ip_whitelist: ['10.0.0.0/8'] },
      last_login_at: Date.now() - 86400_000,
      action: 'rotate-cert',
    });
  }
  const elapsed = Date.now() - start;
  ok(`10k calls in ${elapsed}ms (target < 1000ms)`, elapsed < 1000);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail > 0 ? 1 : 0);
