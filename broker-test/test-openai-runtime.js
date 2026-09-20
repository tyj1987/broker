import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { Readable } from 'node:stream';

import {
  commitOpenAIRuntimeExecutors,
  OPENAI_RUNTIME_CONTRACT,
  OpenAIRuntimeConfigError,
  prepareOpenAIRuntimeExecutors,
} from '../broker/adapters/openai-runtime.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const NOW = Date.parse('2026-09-11T07:00:00Z');
const PROJECT = 'proj_52trzProduction';
const EXECUTION_ID = '12345678-1234-4123-8123-123456789abc';
const REQUEST_BINDING = 'a'.repeat(43);
const basePolicy = {
  enabled: true,
  contract_verified: true,
  execution_mode: 'adapter',
  accounts: ['openai-52trz'],
};
const validConfig = () => ({
  operation_policies: { openai: { 'models.list': { ...basePolicy } } },
  provider_accounts: {
    openai: { 'openai-52trz': { project_id: PROJECT, environments: ['production'] } },
  },
});
const expectRuntimeError = (error) => error instanceof OpenAIRuntimeConfigError;
let probes = 0;
const leaseInputs = [];
const createCredentialClient = (options) => {
  assert.deepEqual(options, { provider: 'openai' });
  return {
    probe: async () => {
      probes += 1;
    },
    lease: async (input) => {
      leaseInputs.push(input);
      return { token: 'temporary-openai-token', expires_at: new Date(NOW + 60_000).toISOString() };
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
        data: [{ id: 'gpt-6-astra', object: 'model', owned_by: 'openai' }],
      }),
    ]);
    response.statusCode = 200;
    response.headers = { 'content-type': 'application/json' };
    queueMicrotask(() => callback(response));
  };
  return request;
};

assert.equal((await prepareOpenAIRuntimeExecutors({ config: {} })).size, 0);
assert.equal(
  (
    await prepareOpenAIRuntimeExecutors({
      config: {
        operation_policies: {
          openai: { 'models.list': { ...basePolicy, contract_verified: false } },
        },
      },
    })
  ).size,
  0,
);
const executors = await prepareOpenAIRuntimeExecutors({
  config: validConfig(),
  createCredentialClient,
  resolveHost: async () => [{ address: '104.18.1.1', family: 4 }],
  requestImpl,
  now: () => NOW,
});
assert.deepEqual([...executors.keys()], ['openai.models.list@1.0.0']);
assert.equal(probes, 1);
const signal = new AbortController().signal;
const result = await executors.get('openai.models.list@1.0.0')(
  { resource_ref: PROJECT },
  {
    accountRef: 'openai-52trz',
    environment: 'production',
    signal,
    execution: {
      tool: 'openai.models.list@1.0.0',
      target: PROJECT,
      environment: 'production',
      execution_id: EXECUTION_ID,
      request_binding: REQUEST_BINDING,
    },
  },
);
assert.deepEqual(result, { models: [{ id: 'gpt-6-astra' }] });
assert.deepEqual(leaseInputs[0], {
  operation_id: 'models.list',
  account_ref: 'openai-52trz',
  environment: 'production',
  resource_ref: PROJECT,
  execution_id: EXECUTION_ID,
  request_binding: REQUEST_BINDING,
  signal,
});
assert.equal(requests[0].hostname, 'api.openai.com');
assert.equal(requests[0].path, '/v1/models');

await assert.rejects(
  executors.get('openai.models.list@1.0.0')(
    { resource_ref: PROJECT },
    {
      accountRef: 'openai-52trz',
      environment: 'staging',
      execution: {
        tool: 'openai.models.list@1.0.0',
        target: PROJECT,
        environment: 'staging',
        execution_id: EXECUTION_ID,
        request_binding: REQUEST_BINDING,
      },
    },
  ),
  (error) => error instanceof V2Error && error.code === 'openai_credential_unavailable',
);
for (const mutate of [
  (config) => {
    config.operation_policies.openai = [];
  },
  (config) => {
    config.operation_policies.openai['models.list'].execution_mode = 'browser';
  },
  (config) => {
    config.operation_policies.openai.unknown = { ...basePolicy };
  },
  (config) => {
    config.operation_policies.openai['models.list'].accounts = [];
  },
  (config) => {
    delete config.provider_accounts;
  },
  (config) => {
    config.provider_accounts.openai = [];
  },
  (config) => {
    config.provider_accounts.openai['openai-52trz'].token = 'forbidden';
  },
  (config) => {
    config.provider_accounts.openai['openai-52trz'].project_id = '..';
  },
  (config) => {
    config.provider_accounts.openai['openai-52trz'].environments = [];
  },
  (config) => {
    config.provider_accounts.openai['openai-52trz'].environments = ['Production'];
  },
  (config) => {
    config.provider_accounts.openai['openai-52trz'].environments = ['production', 'production'];
  },
  (config) => {
    config.operation_policies.openai['models.list'].accounts = ['missing'];
  },
]) {
  const config = validConfig();
  mutate(config);
  await assert.rejects(
    prepareOpenAIRuntimeExecutors({ config, createCredentialClient }),
    expectRuntimeError,
  );
}
const tooMany = validConfig();
tooMany.provider_accounts.openai = Object.fromEntries(
  Array.from({ length: 65 }, (_, index) => [
    `account-${index}`,
    { project_id: `project-${index}`, environments: ['production'] },
  ]),
);
await assert.rejects(
  prepareOpenAIRuntimeExecutors({ config: tooMany, createCredentialClient }),
  expectRuntimeError,
);
await assert.rejects(
  prepareOpenAIRuntimeExecutors({ config: validConfig(), createCredentialClient: () => null }),
  expectRuntimeError,
);
await assert.rejects(
  prepareOpenAIRuntimeExecutors({
    config: validConfig(),
    createCredentialClient: () => ({
      probe: async () => {
        throw new Error('canary');
      },
      lease: async () => ({}),
    }),
  }),
  (error) => expectRuntimeError(error) && !error.message.includes('canary'),
);

const target = new Map([
  ['broker.tools.inspect@1.0.0', async () => ({})],
  ['openai.old@1.0.0', async () => ({})],
]);
assert.equal(commitOpenAIRuntimeExecutors(target, executors), target);
assert.equal(target.has('openai.old@1.0.0'), false);
assert.equal(target.has('openai.models.list@1.0.0'), true);
assert.throws(() => commitOpenAIRuntimeExecutors({}, executors), TypeError);
assert.throws(() => commitOpenAIRuntimeExecutors(target, {}), TypeError);
assert.deepEqual(OPENAI_RUNTIME_CONTRACT, {
  supported_operations: ['models.list'],
  account_binding_fields: ['project_id', 'environments'],
  maximum_accounts: 64,
  plaintext_token_configuration_supported: false,
  requires_contract_verified_policy: true,
  requires_isolated_credential_service: true,
  preferred_identity: 'workload_identity_federation',
});
const serverSource = readFileSync(new URL('../broker/server.js', import.meta.url), 'utf8');
assert.match(serverSource, /await prepareOpenAIRuntimeExecutors\(\{ config: cfg \}\)/);
assert.match(
  serverSource,
  /commitOpenAIRuntimeExecutors\(taskExecutors, prepared\.openaiExecutors\)/,
);

console.log(
  'openai runtime: verified policy, project binding, credential probe and atomic commit passed',
);
