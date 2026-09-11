// broker-test/test-config-validate.js — V4.9.x broker/lib/config-validate.js 单元测试
// 覆盖 validateBrokerConfig + preflightPaths

import { existsSync } from 'node:fs';
import { validateBrokerConfig, preflightPaths } from '../broker/lib/config-validate.js';

let pass = 0, fail = 0;
function ok(name, cond, detail) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`); }
}
function section(t) { console.log(`\n[${t}]`); }

// ============================================================
// validateBrokerConfig: top-level checks
// ============================================================
section('validateBrokerConfig: top-level');
{
  const r = validateBrokerConfig(null);
  ok('null config → ok=false, has error', r.ok === false && r.errors.length >= 1);
  ok('error mentions "must be an object"', r.errors.some(e => /object/i.test(e.message)));
}
{
  const r = validateBrokerConfig('not-an-object');
  ok('string config → ok=false', r.ok === false);
}
{
  const r = validateBrokerConfig({});
  ok('empty object → ok=false (clients required)', r.ok === false);
}

// ============================================================
// clients validation
// ============================================================
section('clients validation');
{
  const r = validateBrokerConfig({
    clients: {
      client_a: { role: 'admin' },
      client_b: { role: 'developer' },
      client_c: { role: 'readonly' },
    },
  });
  ok('valid clients → ok=true', r.ok === true);
  ok('no errors', r.errors.length === 0);
  ok('no "no admin" warning (admin present)', !r.warnings.some(w => /no client with role admin/.test(w.message)));
}
{
  const r = validateBrokerConfig({
    clients: {
      client_no_role: { /* missing role */ },
    },
  });
  ok('missing role → error', r.errors.some(e => /role is required/.test(e.message)));
}
{
  const r = validateBrokerConfig({
    clients: {
      client_unknown: { role: 'superhero' },
    },
  });
  ok('unknown role → warning (forward-compat)', r.warnings.some(w => /unrecognized role/.test(w.message)));
}
{
  const r = validateBrokerConfig({
    clients: {
      client_pw: { role: 'admin', allow_password_login: true /* no password */ },
    },
  });
  ok('allow_password_login=true without password → warning',
     r.warnings.some(w => /allow_password_login/.test(w.message)));
}
{
  const r = validateBrokerConfig({
    clients: {
      client_rl: { role: 'admin', rate_limit: '5/fortnight' },
    },
  });
  ok('unusual rate_limit format → warning',
     r.warnings.some(w => /rate_limit/.test(w.message)));
}
{
  const r = validateBrokerConfig({
    clients: {
      client_rl_ok: { role: 'admin', rate_limit: '5/minute' },
    },
  });
  ok('valid rate_limit (5/minute) → no warning',
     !r.warnings.some(w => /rate_limit/.test(w.message)));
}
{
  const r = validateBrokerConfig({
    clients: { 'invalid-name': 'not-an-object' },
  });
  ok('non-object client → error',
     r.errors.some(e => /must be object/.test(e.message)));
}

// ============================================================
// services validation
// ============================================================
section('services validation');
{
  const r = validateBrokerConfig({
    clients: { c: { role: 'admin' } },  // also need admin to satisfy warning rule
    services: {
      github: { base_url: 'https://api.github.com' },
      aliyun: { base_url: 'http://ecs.aliyuncs.com' },
    },
  });
  ok('valid services → ok=true', r.ok === true);
}
{
  const r = validateBrokerConfig({
    clients: { c: { role: 'admin' } },
    services: { bad: { base_url: 'not-a-url' } },
  });
  ok('invalid base_url → error',
     r.errors.some(e => /invalid URL/.test(e.message)));
}
{
  const r = validateBrokerConfig({
    clients: { c: { role: 'admin' } },
    services: 'should-be-object',
  });
  ok('services not object → error',
     r.errors.some(e => e.path === 'services' && /object/i.test(e.message)));
}

// ============================================================
// api_keys validation
// ============================================================
section('api_keys validation');
{
  const r = validateBrokerConfig({
    clients: { client_a: { role: 'admin' } },
    api_keys: 'not-an-object',
  });
  ok('api_keys not object → error',
     r.errors.some(e => e.path === 'api_keys' && /object/i.test(e.message)));
}

// ============================================================
// no admin warning
// ============================================================
section('no admin warning');
{
  const r = validateBrokerConfig({
    clients: { dev: { role: 'developer' } },
  });
  ok('non-empty clients without admin → warning',
     r.warnings.some(w => /no client with role admin/.test(w.message)));
}
{
  const r = validateBrokerConfig({});  // no clients
  ok('empty clients → no "no admin" warning', !r.warnings.some(w => /no client with role admin/.test(w.message)));
}

// ============================================================
// strict mode
// ============================================================
section('strict mode');
{
  const r = validateBrokerConfig({
    clients: { dev: { role: 'developer' } },
  }, { strict: true });
  ok('strict: warnings treated as errors → ok=false', r.ok === false);
}

// ============================================================
// preflightPaths
// ============================================================
section('preflightPaths');
{
  const r = preflightPaths({ configPath: 'E:/broker/broker/package.json' }, { existsSync });
  ok('existing config path → ok=true', r.ok === true);
}
{
  const r = preflightPaths({ configPath: 'E:/this/does/not/exist.json' }, { existsSync });
  ok('non-existing path → ok=false',
     r.ok === false && r.errors.some(e => /required path missing/.test(e.message)));
}
{
  const r = preflightPaths({}, { existsSync });
  ok('empty paths object → ok=true (no checks)', r.ok === true);
}

console.log(`\n=== Total: ${pass} passed, ${fail} failed ===`);
process.exit(fail > 0 ? 1 : 0);
