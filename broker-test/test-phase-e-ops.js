// broker-test/test-phase-e-ops.js
import {
  validateBrokerConfig,
  formatValidationReport,
  preflightPaths,
} from '../broker/lib/config-validate.js';
import {
  installGracefulShutdown,
  rejectIfShuttingDown,
} from '../broker/lib/shutdown.js';
import { existsSync } from 'node:fs';
import { BROKER_VERSION } from '../broker/version.js';

let passed = 0, failed = 0;
function assert(c, m) {
  if (c) { passed++; console.log('  OK  ', m); }
  else { failed++; console.error('  FAIL', m); }
}

console.log('=== version ===');
assert(typeof BROKER_VERSION === 'string' && /^\d+\.\d+\.\d+/.test(BROKER_VERSION), `version=${BROKER_VERSION}`);

console.log('=== validateBrokerConfig ===');
{
  const bad = validateBrokerConfig(null);
  assert(bad.ok === false, 'null config');

  const emptyClients = validateBrokerConfig({ security_profile: 'controlled', clients: {} });
  assert(emptyClients.ok === true, 'empty clients ok');
  // empty map: no "no admin" warn (only when there are clients but none is admin)
  assert(!emptyClients.warnings.some((w) => /no client with role admin/i.test(w.message)), 'empty has no admin warn');

  const noAdmin = validateBrokerConfig({
    security_profile: 'controlled',
    clients: { ci: { role: 'ci' } },
  });
  assert(noAdmin.ok === true, 'no-admin config ok');
  assert(noAdmin.warnings.some((w) => /no client with role admin/i.test(w.message)), 'no admin warn');

  const good = validateBrokerConfig({
    security_profile: 'controlled',
    clients: {
      admin: { role: 'admin' },
      ci: { role: 'ci', rate_limit: '100/hour' },
    },
    services: {
      gh: { base_url: 'https://api.github.com' },
    },
  });
  assert(good.ok === true && good.errors.length === 0, 'good config');

  const strictWithoutOperations = validateBrokerConfig({
    security_profile: 'strict',
    webauthn: { rp_id: 'broker.example', origin: 'https://broker.example' },
    clients: { admin: { role: 'admin' } },
    services: { gh: { upstream: 'https://api.github.com' } },
  });
  assert(strictWithoutOperations.ok === false, 'strict requires typed operations');

  const strictWithoutWebAuthn = validateBrokerConfig({
    security_profile: 'strict',
    clients: {},
    services: {},
  });
  assert(strictWithoutWebAuthn.errors.some((e) => e.path === 'webauthn.rp_id'), 'strict requires WebAuthn RP ID');

  const badUrl = validateBrokerConfig({
    clients: { a: { role: 'admin' } },
    services: { x: { base_url: 'not-a-url' } },
  });
  assert(badUrl.ok === false, 'bad url');

  const report = formatValidationReport(badUrl);
  assert(report.includes('ERROR'), 'report');
}

console.log('=== preflightPaths ===');
{
  const r = preflightPaths(
    { configPath: '/nonexistent/config.yaml', ageKey: '/nonexistent/key' },
    { existsSync },
  );
  assert(r.ok === false && r.errors.length >= 1, 'missing paths');
}

console.log('=== rejectIfShuttingDown ===');
{
  const res = { headersSent: false, status: 0, body: null, writeHead(s) { this.status = s; }, end(b) { this.body = b; } };
  assert(rejectIfShuttingDown(() => false, res) === false, 'not shutting');
  assert(rejectIfShuttingDown(() => true, res, (r, s, m) => { r.status = s; r.body = m; }) === true, 'shutting');
  assert(res.status === 503, '503');
}

console.log('=== installGracefulShutdown (no exit) ===');
{
  const ctl = installGracefulShutdown({
    server: null,
    onShutdown: [],
    timeoutMs: 1000,
    logger: () => {},
  });
  assert(typeof ctl.shutdown === 'function', 'shutdown fn');
  assert(ctl.shuttingDown() === false, 'not yet');
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
