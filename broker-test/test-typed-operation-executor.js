import { executeTypedOperation } from '../broker/lib/typed-operation-executor.js';

let passed = 0;
let failed = 0;
function ok(name, condition) {
  if (condition) { passed++; console.log('  PASS ', name); }
  else { failed++; console.error('  FAIL ', name); }
}

const operation = {
  method: 'POST',
  path: '/fixed',
  allowed_parameters: ['ResourceId'],
  required_parameters: ['ResourceId'],
  resource_parameter: 'ResourceId',
  environment: 'production',
  allow_body: true,
  max_body_bytes: 32,
  provider_action: 'DescribeThing',
  api_version: '2026-01-01',
  service_code: 'thing',
  region: 'ap-test-1',
};
const config = {
  security_profile: 'strict',
  services: { provider: { type: 'test', allow_methods: ['POST'], operations: { describe: operation } } },
};
const ctx = {
  cn: 'client.test',
  fp: 'AA',
  client: {
    role: 'developer',
    allowed_operations: [{ service: 'provider', operations: ['describe'], environments: ['production'], resources: ['resource/*'] }],
  },
};
const base = {
  config, ctx, serviceName: 'provider', operationId: 'describe',
  payload: { parameters: { ResourceId: 'resource/123' }, body: { ok: true } },
  guardCredential: () => ({ allowed: true }),
};

{
  const calls = [];
  const events = [];
  const outcome = await executeTypedOperation({
    ...base,
    audit: event => events.push(event),
    callUpstream: async (...args) => {
      calls.push(args);
      return { status: 200, headers: { 'content-type': 'application/json' }, body: '{}', latency: 2 };
    },
  });
  ok('authorized operation reaches upstream', outcome.ok && outcome.result.status === 200 && calls.length === 1);
  ok('method path query and body are resolved from catalog', calls[0][1] === 'POST' && calls[0][2] === '/fixed' && calls[0][3].ResourceId === 'resource/123' && calls[0][5].ok === true);
  ok('fixed provider signing metadata propagated', calls[0][0].action === 'DescribeThing' && calls[0][0].api_version === '2026-01-01' && calls[0][0].service_code === 'thing' && calls[0][0].region === 'ap-test-1');
  ok('success is audited', events.at(-1).status === 'ok' && events.at(-1).upstream_status === 200);
}

{
  const outcome = await executeTypedOperation({ ...base, serviceName: 'missing', callUpstream: async () => ({}) });
  ok('unknown service denied', !outcome.ok && outcome.status === 404);
}
{
  const outcome = await executeTypedOperation({ ...base, payload: { parameters: {} }, callUpstream: async () => ({}) });
  ok('catalog parameter validation enforced', !outcome.ok && outcome.status === 400);
}
{
  const outcome = await executeTypedOperation({ ...base, ctx: { ...ctx, client: { role: 'admin' } }, callUpstream: async () => ({}) });
  ok('strict admin without operation grant denied', !outcome.ok && outcome.status === 403);
}
{
  const outcome = await executeTypedOperation({ ...base, config: { ...config, services: { provider: { ...config.services.provider, allow_methods: ['GET'] } } }, callUpstream: async () => ({}) });
  ok('service method boundary enforced', !outcome.ok && outcome.status === 403);
}
{
  const outcome = await executeTypedOperation({ ...base, guardCredential: () => ({ allowed: false }), callUpstream: async () => ({}) });
  ok('unhealthy credential fails closed', !outcome.ok && outcome.status === 503);
}
{
  const payload = { ...base.payload, body: { value: 'x'.repeat(64) } };
  const outcome = await executeTypedOperation({ ...base, payload, callUpstream: async () => ({}) });
  ok('body size limit enforced', !outcome.ok && outcome.status === 413);
}
{
  const noBodyConfig = { ...config, services: { provider: { ...config.services.provider, operations: { describe: { ...operation, allow_body: false } } } } };
  const outcome = await executeTypedOperation({ ...base, config: noBodyConfig, callUpstream: async () => ({}) });
  ok('body forbidden by operation rejected', !outcome.ok && outcome.status === 400);
}
{
  const events = [];
  const outcome = await executeTypedOperation({ ...base, audit: event => events.push(event), callUpstream: async () => { throw new Error('canary-internal'); } });
  ok('upstream exception becomes generic 502', !outcome.ok && outcome.status === 502 && !outcome.message.includes('canary'));
  ok('upstream exception audit records failure', events.at(-1).status === 'error');
}
{
  const apiKeyCtx = {
    ...ctx,
    apiKey: { scopes: ['services:proxy'], allowed_services: ['provider'], allowed_operations: ['provider:other'] },
  };
  const outcome = await executeTypedOperation({ ...base, ctx: apiKeyCtx, callUpstream: async () => ({}) });
  ok('API key operation grant cannot be bypassed by client grant', !outcome.ok && outcome.status === 403);
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
