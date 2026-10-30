// broker-test/test-client-config.js — client config normalization and session-boundary tests

import { readFileSync } from 'node:fs';
import { normalizeClientConfig, clientSecurityConfigChanged } from '../broker/lib/client-config.js';
import { verifyPassword } from '../broker/totp.js';

let passed = 0;
let failed = 0;

function ok(name, condition) {
  if (condition) {
    passed += 1;
    console.log(`  PASS  ${name}`);
  } else {
    failed += 1;
    console.error(`  FAIL  ${name}`);
  }
}

function throwsWith(fn, pattern) {
  try {
    fn();
    return false;
  } catch (error) {
    return pattern.test(error.message);
  }
}

console.log('[password boundary]');
{
  const plaintext = 'correct horse battery staple';
  const cfg = normalizeClientConfig({ password: plaintext }, { now: 1_000 });
  ok('plaintext is never returned from normalizer', cfg.password !== plaintext);
  ok('password is immediately scrypt-hashed', cfg.password.startsWith('scrypt$'));
  ok('generated hash verifies the original password', verifyPassword(plaintext, cfg.password));
  ok(
    'generated hash rejects another password',
    !verifyPassword('wrong password value', cfg.password),
  );
  ok('password timestamp is recorded', cfg.password_set_at === new Date(1_000).toISOString());
  ok('password change timestamp matches', cfg.last_password_change === cfg.password_set_at);
  ok(
    'short password is rejected',
    throwsWith(() => normalizeClientConfig({ password: 'too-short' }), /at least 12/),
  );
  ok(
    'oversized password is rejected',
    throwsWith(() => normalizeClientConfig({ password: 'x'.repeat(1025) }), /too long/),
  );
  const cleared = normalizeClientConfig({ password: null });
  ok('explicit null produces a clear marker', cleared.password === null);
  const clearedEmpty = normalizeClientConfig({ password: '' });
  ok('explicit empty string produces a clear marker', clearedEmpty.password === null);
}

console.log('\n[field normalization]');
{
  const proxyRule = { service: '^github$', paths: ['^/repos/'] };
  const body = {
    role: 'developer',
    allow_password_login: 1,
    allowed_resolve: ['A', 42],
    allowed_proxy: [proxyRule],
    rate_limit: 100,
    description: 'x'.repeat(5000),
  };
  const cfg = normalizeClientConfig(body);
  ok('only literal true enables password login', cfg.allow_password_login === false);
  ok('allowed_resolve values are strings', cfg.allowed_resolve[1] === '42');
  ok('allowed_proxy is cloned', cfg.allowed_proxy[0] !== proxyRule);
  ok('rate limit is normalized to string', cfg.rate_limit === '100');
  ok('description is bounded', cfg.description.length === 4096);
  ok(
    'invalid role is rejected',
    throwsWith(() => normalizeClientConfig({ role: 'root' }), /Invalid role/),
  );
  ok('array body is rejected', normalizeClientConfig([]) === null);
}

console.log('\n[security-change detection]');
{
  const base = {
    role: 'developer',
    password: 'scrypt$old',
    allow_password_login: true,
    allowed_resolve: ['A'],
    allowed_proxy: ['github'],
    rate_limit: '100/hour',
    description: 'before',
  };
  ok(
    'description-only update preserves sessions',
    !clientSecurityConfigChanged(base, { ...base, description: 'after' }),
  );
  ok(
    'rate-limit-only update preserves sessions',
    !clientSecurityConfigChanged(base, { ...base, rate_limit: '10/minute' }),
  );
  ok('role change revokes sessions', clientSecurityConfigChanged(base, { ...base, role: 'admin' }));
  ok(
    'password change revokes sessions',
    clientSecurityConfigChanged(base, { ...base, password: 'scrypt$new' }),
  );
  ok(
    'password-login policy change revokes sessions',
    clientSecurityConfigChanged(base, { ...base, allow_password_login: false }),
  );
  ok(
    'secret ACL change revokes sessions',
    clientSecurityConfigChanged(base, { ...base, allowed_resolve: ['A', 'B'] }),
  );
  ok(
    'proxy ACL change revokes sessions',
    clientSecurityConfigChanged(base, { ...base, allowed_proxy: ['*'] }),
  );
}

console.log('\n[server wiring]');
{
  const source = readFileSync(new URL('../broker/server.js', import.meta.url), 'utf8');
  const dashboard = readFileSync(
    new URL('../broker/dashboard/admin/clients.js', import.meta.url),
    'utf8',
  );
  ok('server imports hardened normalizer', source.includes("from './lib/client-config.js'"));
  ok(
    'server no longer has duplicate normalizer',
    !source.includes('function normalizeClientConfig(body)'),
  );
  ok(
    'security-changing update revokes sessions',
    source.includes('securityChanged ? deleteSessionsForClient(name) : 0'),
  );
  ok('password clear removes stale timestamps', source.includes('delete next.password_set_at'));
  ok(
    'client creation requires a password when password login is enabled',
    source.includes('if (cfg.allow_password_login && !cfg.password)'),
  );
  ok(
    'client update cannot leave password login enabled without a password',
    source.includes('if (next.allow_password_login && !next.password)'),
  );
  ok(
    'client update reports reauthentication requirement',
    source.includes('reauthentication_required: sessionsRevoked > 0'),
  );
  for (const [action, marker] of [
    ['create', "requireStepUp(body.verify, 'admin_clients_create'"],
    ['security update', "requireStepUp(body.verify, 'admin_clients_update'"],
    ['delete', "requireStepUp(body.verify, 'admin_clients_delete'"],
    ['enroll', "requireStepUp(body.verify, 'admin_clients_enroll'"],
    ['rotate', "requireStepUp(body.verify, 'admin_clients_rotate'"],
    ['revoke', "requireStepUp(body.verify, 'admin_clients_revoke'"],
    ['compatibility bundle', "requireStepUp(body.verify, 'admin_clients_bundle'"],
  ]) {
    ok(`${action} uses unified step-up`, source.includes(marker));
  }
  ok('dashboard prompts for step-up', dashboard.includes('function promptVerification(action)'));
  ok(
    'dashboard sends verification for lifecycle actions',
    dashboard.split('JSON.stringify({ verify })').length - 1 === 4,
  );
  ok(
    'dashboard includes verification in create/update payload',
    dashboard.includes('cfg.verify = verify'),
  );
  ok(
    'dashboard never stores verification in localStorage',
    !dashboard.includes('localStorage.setItem') && !dashboard.includes('localStorage.verify'),
  );
  ok(
    'compatibility bundle has no duplicate verification implementation',
    source.split("requireStepUp(body.verify, 'admin_clients_bundle'").length - 1 === 1,
  );
}

console.log(`\n=== Total: ${passed} passed, ${failed} failed ===`);
process.exit(failed > 0 ? 1 : 0);
