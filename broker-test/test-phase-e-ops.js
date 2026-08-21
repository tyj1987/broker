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
assert(BROKER_VERSION === '3.7.0', '3.7.0');

console.log('=== validateBrokerConfig ===');
{
  const bad = validateBrokerConfig(null);
  assert(bad.ok === false, 'null config');

  const emptyClients = validateBrokerConfig({ clients: {} });
  assert(emptyClients.ok === true, 'empty clients ok');
  assert(emptyClients.warnings.some((w) => w.message.includes('no client')), 'no admin warn');

  const good = validateBrokerConfig({
    clients: {
      admin: { role: 'admin' },
      ci: { role: 'ci', rate_limit: '100/hour' },
    },
    services: {
      gh: { base_url: 'https://api.github.com' },
    },
  });
  assert(good.ok === true && good.errors.length === 0, 'good config');

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
  // Only test that API returns functions; do not send signals in unit test
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
