import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { Readable } from 'node:stream';

import {
  commitDeepSeekRuntimeExecutors,
  DEEPSEEK_RUNTIME_CONTRACT,
  DeepSeekRuntimeConfigError,
  prepareDeepSeekRuntimeExecutors,
} from '../broker/adapters/deepseek-runtime.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const NOW = Date.parse('2026-09-11T02:00:00Z');
const EXECUTION_ID = '12345678-1234-4123-8123-123456789abc';
const REQUEST_BINDING = 'a'.repeat(43);
const basePolicy = {
  enabled: true,
  contract_verified: true,
  execution_mode: 'adapter',
  accounts: ['deepseek-primary'],
};
const validConfig = () => ({
  operation_policies: { deepseek: { 'models.list': { ...basePolicy } } },
  provider_accounts: { deepseek: { 'deepseek-primary': { environments: ['production'] } } },
});
const expectRuntimeError = (error) => error instanceof DeepSeekRuntimeConfigError;
let factoryCalls = 0;
let probeCalls = 0;
const leaseInputs = [];
const createCredentialClient = (options) => {
  factoryCalls += 1;
  assert.deepEqual(options, { provider: 'deepseek' });
  return {
    probe: async () => {
      probeCalls += 1;
      return true;
    },
    lease: async (input) => {
      leaseInputs.push(input);
      return {
        token: 'temporary-deepseek-token',
        expires_at: new Date(NOW + 60_000).toISOString(),
      };
    },
  };
};
const requests = [];
const requestImpl = (options, callback) => {
  const request = new EventEmitter();
  request.setTimeout = () => {};
  request.destroy = () => {};
  request.end = () => {
    requests.push(options);
    const response = Readable.from([
      JSON.stringify({
        object: 'list',
        data: [{ id: 'deepseek-v4-pro', object: 'model', owned_by: 'deepseek' }],
      }),
    ]);
    response.statusCode = 200;
    response.headers = { 'content-type': 'application/json' };
    queueMicrotask(() => callback(response));
  };
  return request;
};

assert.equal((await prepareDeepSeekRuntimeExecutors({ config: {} })).size, 0);
assert.equal(
  (
    await prepareDeepSeekRuntimeExecutors({
      config: {
        operation_policies: {
          deepseek: { 'models.list': { ...basePolicy, contract_verified: false } },
        },
      },
    })
  ).size,
  0,
);
const executors = await prepareDeepSeekRuntimeExecutors({
  config: validConfig(),
  createCredentialClient,
  resolveHost: async () => [{ address: '104.18.1.1', family: 4 }],
  requestImpl,
  now: () => NOW,
});
assert.deepEqual([...executors.keys()], ['deepseek.models.list@1.0.0']);
assert.equal(factoryCalls, 1);
assert.equal(probeCalls, 1);
const signal = new AbortController().signal;
const result = await executors.get('deepseek.models.list@1.0.0')(
  { resource_ref: 'model-catalog' },
  {
    accountRef: 'deepseek-primary',
    environment: 'production',
    signal,
    execution: {
      tool: 'deepseek.models.list@1.0.0',
      target: 'model-catalog',
      environment: 'production',
      execution_id: EXECUTION_ID,
      request_binding: REQUEST_BINDING,
    },
  },
);
assert.deepEqual(result, { models: [{ id: 'deepseek-v4-pro', owned_by: 'deepseek' }] });
assert.deepEqual(leaseInputs[0], {
  operation_id: 'models.list',
  account_ref: 'deepseek-primary',
  environment: 'production',
  resource_ref: 'model-catalog',
  execution_id: EXECUTION_ID,
  request_binding: REQUEST_BINDING,
  signal,
});
assert.equal(requests[0].hostname, 'api.deepseek.com');
assert.equal(JSON.stringify(result).includes('temporary-deepseek-token'), false);

await assert.rejects(
  executors.get('deepseek.models.list@1.0.0')(
    { resource_ref: 'model-catalog' },
    {
      accountRef: 'deepseek-primary',
      environment: 'staging',
      execution: {
        tool: 'deepseek.models.list@1.0.0',
        target: 'model-catalog',
        environment: 'staging',
        execution_id: EXECUTION_ID,
        request_binding: REQUEST_BINDING,
      },
    },
  ),
  (error) => error instanceof V2Error && error.code === 'deepseek_credential_unavailable',
);

for (const mutate of [
  (config) => {
    config.operation_policies.deepseek = [];
  },
  (config) => {
    config.operation_policies.deepseek['models.list'].execution_mode = 'browser';
  },
  (config) => {
    config.operation_policies.deepseek.unknown = { ...basePolicy };
  },
  (config) => {
    config.operation_policies.deepseek['models.list'].accounts = [];
  },
  (config) => {
    delete config.provider_accounts;
  },
  (config) => {
    config.provider_accounts.deepseek = [];
  },
  (config) => {
    config.provider_accounts.deepseek['deepseek-primary'].token = 'forbidden';
  },
  (config) => {
    config.provider_accounts.deepseek['deepseek-primary'].environments = [];
  },
  (config) => {
    config.provider_accounts.deepseek['deepseek-primary'].environments = ['Production'];
  },
  (config) => {
    config.provider_accounts.deepseek['deepseek-primary'].environments = [
      'production',
      'production',
    ];
  },
  (config) => {
    config.operation_policies.deepseek['models.list'].accounts = ['missing'];
  },
]) {
  const config = validConfig();
  mutate(config);
  await assert.rejects(
    prepareDeepSeekRuntimeExecutors({ config, createCredentialClient }),
    expectRuntimeError,
  );
}
const tooMany = validConfig();
tooMany.provider_accounts.deepseek = Object.fromEntries(
  Array.from({ length: 65 }, (_, index) => [`account-${index}`, { environments: ['production'] }]),
);
await assert.rejects(
  prepareDeepSeekRuntimeExecutors({ config: tooMany, createCredentialClient }),
  expectRuntimeError,
);
await assert.rejects(
  prepareDeepSeekRuntimeExecutors({ config: validConfig(), createCredentialClient: () => null }),
  expectRuntimeError,
);
await assert.rejects(
  prepareDeepSeekRuntimeExecutors({
    config: validConfig(),
    createCredentialClient: () => ({
      probe: async () => {
        throw new Error('canary-probe');
      },
      lease: async () => ({}),
    }),
  }),
  (error) => expectRuntimeError(error) && !error.message.includes('canary'),
);

const target = new Map([
  ['broker.tools.inspect@1.0.0', async () => ({})],
  ['deepseek.old@1.0.0', async () => ({})],
]);
assert.equal(commitDeepSeekRuntimeExecutors(target, executors), target);
assert.equal(target.has('broker.tools.inspect@1.0.0'), true);
assert.equal(target.has('deepseek.old@1.0.0'), false);
assert.equal(target.has('deepseek.models.list@1.0.0'), true);
assert.throws(() => commitDeepSeekRuntimeExecutors({}, executors), TypeError);
assert.throws(() => commitDeepSeekRuntimeExecutors(target, {}), TypeError);

assert.deepEqual(DEEPSEEK_RUNTIME_CONTRACT, {
  supported_operations: ['models.list'],
  account_binding_fields: ['environments'],
  maximum_accounts: 64,
  plaintext_token_configuration_supported: false,
  requires_contract_verified_policy: true,
  requires_isolated_credential_service: true,
});
const serverSource = readFileSync(new URL('../broker/server.js', import.meta.url), 'utf8');
assert.match(serverSource, /await prepareDeepSeekRuntimeExecutors\(\{ config: cfg \}\)/);
assert.match(
  serverSource,
  /commitDeepSeekRuntimeExecutors\(taskExecutors, prepared\.deepseekExecutors\)/,
);

console.log(
  'deepseek runtime: verified policy, account binding, credential probe and atomic commit passed',
);
