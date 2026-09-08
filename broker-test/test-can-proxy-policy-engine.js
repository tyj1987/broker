// broker-test/test-can-proxy-policy-engine.js — V4.1.1 tests for broker/can-proxy.js
//
// The proxy policy engine is security-critical (it gates every /api/v1/proxy/* call).
// We test 30+ cases covering string rules, regex rules, object rules, admin bypass,
// negative paths, edge cases.

import {
  canProxy,
  isServiceAllowed,
  clientNamesAllowedFor,
  matchProxyRule,
  checkPathAllowed,
} from '../broker/can-proxy.js';

let pass = 0, fail = 0;
function ok(name, cond, detail) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`); }
}
function section(t) { console.log(`\n[${t}]`); }

// ---------- helpers ----------

function ctx(clientOverrides = {}) {
  return { client: { role: 'developer', ...clientOverrides } };
}
function adminCtx() {
  return { client: { role: 'admin', allowed_proxy: [] } }; // empty — admin should still allow
}

// ---------- tests ----------

section('1. Wildcard rules');

ok('"*" allows any service', matchProxyRule('*', 'github', '/user'));
ok('".*" allows any service', matchProxyRule('.*', 'github', '/user'));

section('2. Exact string rules');

ok('exact match', matchProxyRule('github', 'github', '/user'));
ok('different service → false', !matchProxyRule('github', 'gitlab', '/user'));
ok('substring does NOT match (no implicit regex)', !matchProxyRule('git', 'github', '/user'));

section('3. Regex rules (only when meta chars present)');

ok('githu* matches github', matchProxyRule('githu*', 'github', '/user'));
ok('^github$ exact regex', matchProxyRule('^github$', 'github', '/user'));
ok('^github$ does not match gitlab', !matchProxyRule('^github$', 'gitlab', '/user'));
ok('aliyun.* matches aliyun_ecs', matchProxyRule('aliyun.*', 'aliyun_ecs', '/'));
ok('aliyun.* does not match github', !matchProxyRule('aliyun.*', 'github', '/'));

section('4. Object rules');

ok('object service match', matchProxyRule({ service: 'github' }, 'github', '/user'));
ok('object service mismatch', !matchProxyRule({ service: 'github' }, 'gitlab', '/user'));
ok('object regex service', matchProxyRule({ service: '^github' }, 'github_cn', '/user'));
ok('object with paths all match', matchProxyRule({ service: 'github', paths: ['^/user', '^/repos'] }, 'github', '/user'));
ok('object with paths none match', !matchProxyRule({ service: 'github', paths: ['^/admin'] }, 'github', '/user'));
ok('object with empty paths array → no path check (allow all)', matchProxyRule({ service: 'github', paths: [] }, 'github', '/anywhere'));
ok('object with no paths key → no path check', matchProxyRule({ service: 'github' }, 'github', '/anywhere'));

section('5. canProxy — admin bypass');

ok('admin allows github regardless of allowed_proxy',
   canProxy(adminCtx(), 'github', '/user'));
ok('admin allows any service',
   canProxy(adminCtx(), 'aliyun_ecs', '/anything'));

section('6. canProxy — developer with allowed_proxy');

{
  const c = ctx({ allowed_proxy: ['github'] });
  ok('allows matching service', canProxy(c, 'github', '/user'));
  ok('denies non-matching service', !canProxy(c, 'gitlab', '/user'));
}
{
  const c = ctx({ allowed_proxy: [{ service: 'github', paths: ['^/user$'] }] });
  ok('object rule with path match', canProxy(c, 'github', '/user'));
  ok('object rule with path mismatch', !canProxy(c, 'github', '/user/repos'));
}
{
  const c = ctx({ allowed_proxy: [] });
  ok('empty allow list → deny', !canProxy(c, 'github', '/user'));
}
{
  const c = ctx({ allowed_proxy: ['*'] });
  ok('wildcard in allow list', canProxy(c, 'github', '/user'));
}

section('7. canProxy — multiple rules (cumulative)');

{
  const c = ctx({ allowed_proxy: ['github', 'gitlab'] });
  ok('first rule matches', canProxy(c, 'github', '/user'));
  ok('second rule matches', canProxy(c, 'gitlab', '/user'));
  ok('third rule does not match', !canProxy(c, 'aws', '/'));
}

section('8. canProxy — edge cases');

ok('null ctx → false', !canProxy(null, 'github', '/'));
ok('ctx with no client → false', !canProxy({}, 'github', '/'));
ok('ctx.client null → false', !canProxy({ client: null }, 'github', '/'));

section('9. isServiceAllowed — admin');

ok('admin allowed for any service', isServiceAllowed(adminCtx(), 'github'));
ok('admin allowed for unknown service', isServiceAllowed(adminCtx(), 'no-such-service'));

section('10. isServiceAllowed — developer');

{
  const c = ctx({ allowed_proxy: ['github', { service: 'aliyun_ecs', paths: [] }] });
  ok('exact string → allowed', isServiceAllowed(c, 'github'));
  ok('object rule with empty paths → allowed', isServiceAllowed(c, 'aliyun_ecs'));
  ok('object rule with restrictive paths → NOT allowed (paths checked against "*")',
     !isServiceAllowed({ client: { role: 'developer', allowed_proxy: [{ service: 'aws', paths: ['^/specific'] }] } }, 'aws'));
  ok('non-matching → not allowed', !isServiceAllowed(c, 'aws'));
}

section('11. clientNamesAllowedFor — admin matrix');

{
  const clients = {
    'admin.alice': { role: 'admin' },
    'dev.bob': { role: 'developer', allowed_proxy: ['github'] },
    'dev.carol': { role: 'developer', allowed_proxy: ['gitlab'] },
    'dev.dan': { role: 'developer', allowed_proxy: ['*'] },
  };
  const r = clientNamesAllowedFor(clients, 'github');
  ok('admin always in list', r.includes('admin.alice'));
  ok('matching dev in list', r.includes('dev.bob'));
  ok('non-matching dev NOT in list', !r.includes('dev.carol'));
  ok('wildcard dev in list', r.includes('dev.dan'));
}

section('12. checkPathAllowed');

ok('null pattern → true', checkPathAllowed(null, '/x'));
ok('undefined pattern → true', checkPathAllowed(undefined, '/x'));
ok('exact string match', checkPathAllowed('^/user$', '/user'));
ok('string mismatch', !checkPathAllowed('^/user$', '/admin'));
ok('array with match', checkPathAllowed(['^/user$', '^/repos'], '/repos'));
ok('array without match', !checkPathAllowed(['^/user$', '^/repos'], '/admin'));
ok('invalid regex → false', !checkPathAllowed('[invalid(', '/x'));
ok('empty pattern → true (allows)', checkPathAllowed('', '/x'));

section('13. Security: regex injection guard');

{
  // The "no implicit regex" behavior means a user who passes "github.attacker"
  // doesn't accidentally match "github" (no dot-regex). Verify.
  ok('"github.attacker" does not match "github" service',
     !matchProxyRule('github.attacker', 'github', '/'));
}

section('14. Security: admin role cannot be downgraded by config');

{
  const c = { client: { role: 'admin', allowed_proxy: [] } };
  ok('admin with empty allow still allows everything',
     canProxy(c, 'github', '/'));
  ok('admin with explicit deny still allows (admin overrides)',
     canProxy({ client: { role: 'admin', allowed_proxy: ['nothing'] } }, 'github', '/'));
}

section('15. Realistic config — multi-service developer');

{
  const c = ctx({
    allowed_proxy: [
      'github',
      { service: 'aliyun_ecs', paths: ['^/DescribeInstances$', '^/DescribeRegions$'] },
      { service: 'cloudflare', paths: ['^/zones/.*'] },
    ],
  });
  ok('github any path', canProxy(c, 'github', '/user/repos'));
  ok('aliyun_ecs allowed path', canProxy(c, 'aliyun_ecs', '/DescribeInstances'));
  ok('aliyun_ecs denied path', !canProxy(c, 'aliyun_ecs', '/DeleteInstance'));
  ok('cloudflare zones allowed', canProxy(c, 'cloudflare', '/zones/abc'));
  ok('cloudflare root denied', !canProxy(c, 'cloudflare', '/'));
  ok('unknown service denied', !canProxy(c, 'aws', '/anything'));
}

// ---------- summary ----------

console.log(`\n=== ${pass} pass / ${fail} fail ===`);
process.exit(fail === 0 ? 0 : 1);
