// broker-test/test-phase-e-ops.js
import {
  validateBrokerConfig,
  requireValidBrokerConfig,
  formatValidationReport,
  preflightPaths,
} from '../broker/lib/config-validate.js';
import {
  installGracefulShutdown,
  rejectIfShuttingDown,
} from '../broker/lib/shutdown.js';
import { existsSync, readFileSync } from 'node:fs';
import YAML from '../broker/node_modules/yaml/dist/index.js';
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

  const emptyClients = validateBrokerConfig({ clients: {} });
  assert(emptyClients.ok === true, 'empty clients ok');
  // empty map: no "no admin" warn (only when there are clients but none is admin)
  assert(!emptyClients.warnings.some((w) => /no client with role admin/i.test(w.message)), 'empty has no admin warn');

  const noAdmin = validateBrokerConfig({
    clients: { ci: { role: 'ci' } },
  });
  assert(noAdmin.ok === true, 'no-admin config ok');
  assert(noAdmin.warnings.some((w) => /no client with role admin/i.test(w.message)), 'no admin warn');

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

  const providerAccounts = validateBrokerConfig({
    clients: {},
    provider_accounts: { github: {} },
  });
  assert(providerAccounts.ok === true, 'provider account metadata map accepted');
  const invalidProviderAccounts = validateBrokerConfig({
    clients: {},
    provider_accounts: [],
  });
  assert(invalidProviderAccounts.ok === false, 'provider account metadata fails closed on array');

  const badExecutionMode = validateBrokerConfig({
    clients: { admin: { role: 'admin' } },
    operation_policies: { aliyun: { 'billing.read': { execution_mode: 'arbitrary-shell' } } },
  });
  assert(badExecutionMode.ok === false, 'unknown operation execution mode fails closed');

  const externalMcpHealthcheck = validateBrokerConfig({
    clients: {},
    healthcheck: { upstream: 'mcp_server' },
  });
  assert(externalMcpHealthcheck.ok === false, 'external MCP healthcheck execution fails closed');

  const browserExecutionMode = validateBrokerConfig({
    clients: { admin: { role: 'admin' } },
    operation_policies: { aliyun: { 'billing.read': { execution_mode: 'browser' } } },
  });
  assert(browserExecutionMode.ok === true, 'browser operation execution mode is accepted');

  const unsupportedPolicySchema = validateBrokerConfig({
    clients: { admin: { role: 'admin' } },
    operation_policies: { aliyun: { 'billing.read': {
      parameter_schema: { type: 'object', properties: { resource_ref: { type: 'string', pattern: '.*' } } },
    } } },
  });
  assert(unsupportedPolicySchema.ok === false, 'unenforced policy schema keyword fails closed');
  let activeConfig = { marker: 'safe' };
  try {
    const candidate = {
      clients: { admin: { role: 'admin' } },
      operation_policies: { aliyun: { 'billing.read': {
        parameter_schema: { type: 'object', properties: { resource_ref: { type: 'string', pattern: '.*' } } },
      } } },
    };
    requireValidBrokerConfig(candidate);
    activeConfig = candidate;
  } catch (error) {
    assert(error.message.includes('parameter_schema_invalid'), 'reload validation reports the rejected policy path');
  }
  assert(activeConfig.marker === 'safe', 'invalid reload candidate cannot replace active configuration');

  const invalidPolicyConditions = validateBrokerConfig({
    clients: { admin: { role: 'admin' } },
    operation_policies: { github: { 'repo.read': { source_cidrs: ['not-a-cidr'] } } },
  });
  assert(invalidPolicyConditions.ok === false, 'invalid network policy condition fails closed');

  const validPolicyConditions = validateBrokerConfig({
    clients: { admin: { role: 'admin' } },
    operation_policies: { github: { 'repo.read': {
      source_cidrs: ['203.0.113.0/24', '2001:db8::/32'],
      not_before: '2026-09-09T00:00:00Z', not_after: '2026-09-10T00:00:00Z',
    } } },
  });
  assert(validPolicyConditions.ok === true, 'valid network and time policy conditions are accepted');

  const weakDeviceControl = validateBrokerConfig({
    clients: { admin: { role: 'admin' } },
    operation_policies: {
      broker: {
        'device.enroll': {
          approval_required: true, required_approvals: 1, roles: ['admin'],
          security_profiles: ['strict'], identity_methods: ['session'],
        },
      },
    },
  });
  assert(weakDeviceControl.ok === false, 'device control policy cannot reduce two-person approval');

  const weakEmergencyControl = validateBrokerConfig({
    clients: { admin: { role: 'admin' } },
    operation_policies: {
      broker: {
        'emergency.stop': {
          approval_required: true, required_approvals: 1, roles: ['admin'],
          security_profiles: ['strict'], identity_methods: ['session'],
        },
      },
    },
  });
  assert(weakEmergencyControl.ok === false, 'emergency stop policy cannot reduce two-person approval');

  const badUrl = validateBrokerConfig({
    clients: { a: { role: 'admin' } },
    services: { x: { base_url: 'not-a-url' } },
  });
  assert(badUrl.ok === false, 'bad url');

  const report = formatValidationReport(badUrl);
  assert(report.includes('ERROR'), 'report');

  const strictWithoutKeys = validateBrokerConfig({
    clients: { admin: { role: 'admin', security_profile: 'strict', factors: { webauthn: { credentials: [] } } } },
  });
  assert(strictWithoutKeys.ok === false, 'strict profile requires two hardware credentials');

  const strictWithKeys = validateBrokerConfig({
    clients: {
      admin: {
        role: 'admin', security_profile: 'strict',
        factors: { webauthn: { credentials: [
          { id: 'one', device_type: 'singleDevice', backed_up: false },
          { id: 'two', device_type: 'singleDevice', backed_up: false },
        ] } },
      },
    },
  });
  assert(strictWithKeys.ok === true, 'strict profile accepts two hardware credentials');

  const strictLegacy = validateBrokerConfig({
    clients: { admin: { role: 'admin', security_profile: 'strict', password: 'x', allowed_proxy: ['*'] } },
  }, { allowWebAuthnBootstrap: true });
  assert(strictLegacy.ok === false, 'strict profile rejects password and compatibility proxy');

  const example = YAML.parse(readFileSync(new URL('../secrets/broker.yaml.example', import.meta.url), 'utf8'));
  const exampleBootstrap = validateBrokerConfig(example, { allowWebAuthnBootstrap: true });
  assert(exampleBootstrap.ok === true, 'strict example is valid only with non-production bootstrap');
  assert(validateBrokerConfig(example).ok === false, 'strict example fails closed in production before two hardware keys');
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
