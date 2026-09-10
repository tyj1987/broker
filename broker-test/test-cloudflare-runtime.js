import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { Readable } from 'node:stream';

import {
  CLOUDFLARE_RUNTIME_CONTRACT,
  CloudflareRuntimeConfigError,
  commitCloudflareRuntimeExecutors,
  prepareCloudflareRuntimeExecutors,
} from '../broker/adapters/cloudflare-runtime.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const NOW = 2_000_000_000_000;
const ACCOUNT_ID = '0123456789abcdef0123456789abcdef';
const EXECUTION_ID = '12345678-1234-4123-8123-123456789abc';
const REQUEST_BINDING = 'a'.repeat(43);
const basePolicy = {
  enabled: true,
  contract_verified: true,
  execution_mode: 'adapter',
  accounts: ['cloudflare-primary'],
};
const validConfig = () => ({
  operation_policies: { cloudflare: { 'zones.list': { ...basePolicy } } },
  provider_accounts: {
    cloudflare: {
      'cloudflare-primary': {
        account_id: ACCOUNT_ID,
        environments: ['production'],
      },
    },
  },
});
const expectRuntimeError = (error) => error instanceof CloudflareRuntimeConfigError;

let factoryCalls = 0;
let probeCalls = 0;
const leaseInputs = [];
const createCredentialClient = (options) => {
  factoryCalls += 1;
  assert.deepEqual(options, { provider: 'cloudflare' });
  return {
    probe: async () => {
      probeCalls += 1;
      return true;
    },
    lease: async (input) => {
      leaseInputs.push(input);
      return {
        token: 'runtime-cloudflare-token',
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
    const body = {
      success: true,
      result: [
        {
          id: 'abcdef0123456789abcdef0123456789',
          account: { id: ACCOUNT_ID },
          name: 'example.com',
          status: 'active',
          type: 'full',
          paused: false,
        },
      ],
      result_info: { page: 1, per_page: 20, count: 1, total_count: 1, total_pages: 1 },
    };
    const response = Readable.from([JSON.stringify(body)]);
    response.statusCode = 200;
    response.headers = { 'content-type': 'application/json' };
    queueMicrotask(() => callback(response));
  };
  return request;
};

const empty = await prepareCloudflareRuntimeExecutors({
  config: {},
  createCredentialClient: () => {
    throw new Error('unused credential client');
  },
});
assert.equal(empty.size, 0);
const unverified = await prepareCloudflareRuntimeExecutors({
  config: {
    operation_policies: {
      cloudflare: { 'zones.list': { ...basePolicy, contract_verified: false } },
    },
  },
  createCredentialClient: () => {
    throw new Error('unused credential client');
  },
});
assert.equal(unverified.size, 0);

const executors = await prepareCloudflareRuntimeExecutors({
  config: validConfig(),
  createCredentialClient,
  resolveHost: async () => [{ address: '104.16.132.229', family: 4 }],
  requestImpl,
});
assert.deepEqual([...executors.keys()], ['cloudflare.zones.list@1.0.0']);
assert.equal(factoryCalls, 1);
assert.equal(probeCalls, 1);
const signal = new AbortController().signal;
const result = await executors.get('cloudflare.zones.list@1.0.0')(
  { resource_ref: ACCOUNT_ID },
  {
    accountRef: 'cloudflare-primary',
    environment: 'production',
    signal,
    execution: {
      tool: 'cloudflare.zones.list@1.0.0',
      target: ACCOUNT_ID,
      environment: 'production',
      execution_id: EXECUTION_ID,
      request_binding: REQUEST_BINDING,
    },
  },
);
assert.equal(result.zones[0].name, 'example.com');
assert.deepEqual(leaseInputs[0], {
  operation_id: 'zones.list',
  account_ref: 'cloudflare-primary',
  environment: 'production',
  resource_ref: ACCOUNT_ID,
  execution_id: EXECUTION_ID,
  request_binding: REQUEST_BINDING,
  signal,
});
assert.equal(requests[0].headers.authorization, 'Bearer runtime-cloudflare-token');
assert.equal(JSON.stringify(result).includes('runtime-cloudflare-token'), false);

await assert.rejects(
  executors.get('cloudflare.zones.list@1.0.0')(
    { resource_ref: 'a'.repeat(32) },
    {
      accountRef: 'cloudflare-primary',
      environment: 'production',
      execution: {
        tool: 'cloudflare.zones.list@1.0.0',
        target: 'a'.repeat(32),
        environment: 'production',
        execution_id: EXECUTION_ID,
        request_binding: REQUEST_BINDING,
      },
    },
  ),
  (error) => error instanceof V2Error && error.code === 'cloudflare_credential_unavailable',
);

for (const mutate of [
  (config) => {
    config.operation_policies.cloudflare['zones.list'].execution_mode = 'browser';
  },
  (config) => {
    config.operation_policies.cloudflare['unknown.list'] = { ...basePolicy };
  },
  (config) => {
    config.operation_policies.cloudflare['zones.list'].accounts = [];
  },
  (config) => {
    delete config.provider_accounts;
  },
  (config) => {
    config.provider_accounts.cloudflare = [];
  },
  (config) => {
    config.provider_accounts.cloudflare['cloudflare-primary'].token = 'forbidden';
  },
  (config) => {
    config.provider_accounts.cloudflare['cloudflare-primary'].account_id = 'bad';
  },
  (config) => {
    config.provider_accounts.cloudflare['cloudflare-primary'].environments = [];
  },
  (config) => {
    config.provider_accounts.cloudflare['cloudflare-primary'].environments = ['Production'];
  },
  (config) => {
    config.provider_accounts.cloudflare['cloudflare-primary'].environments = [
      'production',
      'production',
    ];
  },
  (config) => {
    config.operation_policies.cloudflare['zones.list'].accounts = ['missing'];
  },
]) {
  const config = validConfig();
  mutate(config);
  await assert.rejects(
    prepareCloudflareRuntimeExecutors({ config, createCredentialClient }),
    expectRuntimeError,
  );
}

const tooMany = validConfig();
tooMany.provider_accounts.cloudflare = Object.fromEntries(
  Array.from({ length: 65 }, (_, index) => [
    `account-${index}`,
    {
      account_id: index.toString(16).padStart(32, '0'),
      environments: ['production'],
    },
  ]),
);
await assert.rejects(
  prepareCloudflareRuntimeExecutors({ config: tooMany, createCredentialClient }),
  expectRuntimeError,
);
await assert.rejects(
  prepareCloudflareRuntimeExecutors({
    config: validConfig(),
    createCredentialClient: () => null,
  }),
  expectRuntimeError,
);
await assert.rejects(
  prepareCloudflareRuntimeExecutors({
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
  ['cloudflare.old@1.0.0', async () => ({})],
]);
assert.equal(commitCloudflareRuntimeExecutors(target, executors), target);
assert.equal(target.has('broker.tools.inspect@1.0.0'), true);
assert.equal(target.has('cloudflare.old@1.0.0'), false);
assert.equal(target.has('cloudflare.zones.list@1.0.0'), true);
assert.throws(() => commitCloudflareRuntimeExecutors({}, executors), TypeError);
assert.throws(() => commitCloudflareRuntimeExecutors(target, {}), TypeError);

assert.deepEqual(CLOUDFLARE_RUNTIME_CONTRACT, {
  supported_operations: ['zones.list'],
  account_binding_fields: ['account_id', 'environments'],
  maximum_accounts: 64,
  plaintext_token_configuration_supported: false,
  requires_contract_verified_policy: true,
  requires_isolated_credential_service: true,
});
const serverSource = readFileSync(new URL('../broker/server.js', import.meta.url), 'utf8');
assert.match(serverSource, /await prepareCloudflareRuntimeExecutors\(\{ config: cfg \}\)/);
assert.match(
  serverSource,
  /commitCloudflareRuntimeExecutors\(taskExecutors, prepared\.cloudflareExecutors\)/,
);

console.log(
  'cloudflare runtime: verified policy, exact account binding, credential probe and atomic commit passed',
);
