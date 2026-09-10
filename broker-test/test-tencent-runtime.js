import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { Readable } from 'node:stream';

import {
  commitTencentRuntimeExecutors,
  prepareTencentRuntimeExecutors,
  TENCENT_RUNTIME_CONTRACT,
  TencentRuntimeConfigError,
} from '../broker/adapters/tencent-runtime.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const NOW = Date.parse('2026-09-11T02:03:04Z');
const REGION = 'ap-singapore';
const RESOURCE = 'primary-cvm-inventory';
const EXECUTION_ID = '12345678-1234-4123-8123-123456789abc';
const REQUEST_BINDING = 'a'.repeat(43);
const basePolicy = {
  enabled: true,
  contract_verified: true,
  execution_mode: 'adapter',
  accounts: ['tencent-primary'],
};
const validConfig = () => ({
  operation_policies: { tencent: { 'cvm.instances.list': { ...basePolicy } } },
  provider_accounts: {
    tencent: {
      'tencent-primary': {
        environments: ['production'],
        regions: [REGION],
        resources: [RESOURCE],
      },
    },
  },
});
const expectRuntimeError = (error) => error instanceof TencentRuntimeConfigError;
let probeCalls = 0;
const signInputs = [];
const createSignerClient = () => ({
  probe: async () => {
    probeCalls += 1;
    return true;
  },
  sign: async (input) => {
    signInputs.push(input);
    return {
      account_ref: input.account_ref,
      environment: input.environment,
      resource_ref: input.resource_ref,
      region: input.region,
      execution_id: input.execution_id,
      request_binding: input.request_binding,
      payload_sha256: input.payload_sha256,
      headers: {
        Authorization:
          'TC3-HMAC-SHA256 Credential=AKIDEXAMPLE/2026-09-11/cvm/tc3_request, ' +
          `SignedHeaders=content-type;host, Signature=${'a'.repeat(64)}`,
        'content-type': 'application/json; charset=utf-8',
        host: 'cvm.tencentcloudapi.com',
        'x-tc-action': 'DescribeInstances',
        'x-tc-region': REGION,
        'x-tc-timestamp': String(Math.floor(NOW / 1000)),
        'x-tc-token': 'temporary-session-token',
        'x-tc-version': '2017-03-12',
      },
    };
  },
});
const requests = [];
const requestImpl = (options, callback) => {
  const request = new EventEmitter();
  request.setTimeout = () => {};
  request.destroy = () => {};
  request.write = () => {};
  request.end = () => {
    requests.push(options);
    const response = Readable.from([
      JSON.stringify({
        Response: {
          InstanceSet: [
            {
              InstanceId: 'ins-xlsyru2j',
              InstanceName: 'broker-recovery',
              InstanceState: 'RUNNING',
              InstanceType: 'S2.SMALL2',
              Placement: { Zone: 'ap-singapore-1' },
            },
          ],
          TotalCount: 1,
        },
      }),
    ]);
    response.statusCode = 200;
    response.headers = { 'content-type': 'application/json' };
    queueMicrotask(() => callback(response));
  };
  return request;
};

assert.equal((await prepareTencentRuntimeExecutors({ config: {} })).size, 0);
assert.equal(
  (
    await prepareTencentRuntimeExecutors({
      config: {
        operation_policies: {
          tencent: { 'cvm.instances.list': { ...basePolicy, contract_verified: false } },
        },
      },
    })
  ).size,
  0,
);
const executors = await prepareTencentRuntimeExecutors({
  config: validConfig(),
  createSignerClient,
  resolveHost: async () => [{ address: '43.129.0.1', family: 4 }],
  requestImpl,
  now: () => NOW,
});
assert.deepEqual([...executors.keys()], ['tencent.cvm.instances.list@1.0.0']);
assert.equal(probeCalls, 1);
const signal = new AbortController().signal;
const result = await executors.get('tencent.cvm.instances.list@1.0.0')(
  { resource_ref: RESOURCE, region: REGION, limit: 20 },
  {
    accountRef: 'tencent-primary',
    environment: 'production',
    signal,
    execution: {
      tool: 'tencent.cvm.instances.list@1.0.0',
      target: RESOURCE,
      environment: 'production',
      execution_id: EXECUTION_ID,
      request_binding: REQUEST_BINDING,
    },
  },
);
assert.equal(result.instances[0].instance_id, 'ins-xlsyru2j');
assert.equal(signInputs[0].execution_id, EXECUTION_ID);
assert.equal(signInputs[0].request_binding, REQUEST_BINDING);
assert.equal(signInputs[0].region, REGION);
assert.equal(signInputs[0].signal, signal);
assert.equal(requests[0].hostname, 'cvm.tencentcloudapi.com');

for (const [parameters, changedContext] of [
  [{ resource_ref: RESOURCE, region: 'ap-guangzhou' }, {}],
  [
    { resource_ref: 'other-inventory', region: REGION },
    {
      execution: {
        tool: 'tencent.cvm.instances.list@1.0.0',
        target: 'other-inventory',
        environment: 'production',
        execution_id: EXECUTION_ID,
        request_binding: REQUEST_BINDING,
      },
    },
  ],
  [
    { resource_ref: RESOURCE, region: REGION },
    {
      environment: 'staging',
      execution: {
        tool: 'tencent.cvm.instances.list@1.0.0',
        target: RESOURCE,
        environment: 'staging',
        execution_id: EXECUTION_ID,
        request_binding: REQUEST_BINDING,
      },
    },
  ],
]) {
  await assert.rejects(
    executors.get('tencent.cvm.instances.list@1.0.0')(parameters, {
      accountRef: 'tencent-primary',
      environment: 'production',
      execution: {
        tool: 'tencent.cvm.instances.list@1.0.0',
        target: parameters.resource_ref,
        environment: 'production',
        execution_id: EXECUTION_ID,
        request_binding: REQUEST_BINDING,
      },
      ...changedContext,
    }),
    (error) => error instanceof V2Error && error.code === 'tencent_signer_unavailable',
  );
}

for (const mutate of [
  (config) => {
    config.operation_policies.tencent = [];
  },
  (config) => {
    config.operation_policies.tencent['cvm.instances.list'].execution_mode = 'browser';
  },
  (config) => {
    config.operation_policies.tencent.unknown = { ...basePolicy };
  },
  (config) => {
    config.operation_policies.tencent['cvm.instances.list'].accounts = [];
  },
  (config) => {
    delete config.provider_accounts;
  },
  (config) => {
    config.provider_accounts.tencent = [];
  },
  (config) => {
    config.provider_accounts.tencent['tencent-primary'].secret_key = 'forbidden';
  },
  (config) => {
    config.provider_accounts.tencent['tencent-primary'].environments = [];
  },
  (config) => {
    config.provider_accounts.tencent['tencent-primary'].regions = ['https://attacker.example'];
  },
  (config) => {
    config.provider_accounts.tencent['tencent-primary'].resources = ['../inventory'];
  },
  (config) => {
    config.provider_accounts.tencent['tencent-primary'].regions = [REGION, REGION];
  },
  (config) => {
    config.operation_policies.tencent['cvm.instances.list'].accounts = ['missing'];
  },
]) {
  const config = validConfig();
  mutate(config);
  await assert.rejects(
    prepareTencentRuntimeExecutors({ config, createSignerClient }),
    expectRuntimeError,
  );
}
const tooManyAccounts = validConfig();
tooManyAccounts.provider_accounts.tencent = Object.fromEntries(
  Array.from({ length: 65 }, (_, index) => [
    `account-${index}`,
    { environments: ['production'], regions: [REGION], resources: [`inventory-${index}`] },
  ]),
);
await assert.rejects(
  prepareTencentRuntimeExecutors({ config: tooManyAccounts, createSignerClient }),
  expectRuntimeError,
);
await assert.rejects(
  prepareTencentRuntimeExecutors({ config: validConfig(), createSignerClient: () => null }),
  expectRuntimeError,
);
await assert.rejects(
  prepareTencentRuntimeExecutors({
    config: validConfig(),
    createSignerClient: () => ({
      probe: async () => {
        throw new Error('canary-probe');
      },
      sign: async () => ({}),
    }),
  }),
  (error) => expectRuntimeError(error) && !error.message.includes('canary'),
);

const target = new Map([
  ['broker.tools.inspect@1.0.0', async () => ({})],
  ['tencent.old@1.0.0', async () => ({})],
]);
assert.equal(commitTencentRuntimeExecutors(target, executors), target);
assert.equal(target.has('broker.tools.inspect@1.0.0'), true);
assert.equal(target.has('tencent.old@1.0.0'), false);
assert.equal(target.has('tencent.cvm.instances.list@1.0.0'), true);
assert.throws(() => commitTencentRuntimeExecutors({}, executors), TypeError);
assert.throws(() => commitTencentRuntimeExecutors(target, {}), TypeError);

assert.deepEqual(TENCENT_RUNTIME_CONTRACT, {
  supported_operations: ['cvm.instances.list'],
  account_binding_fields: ['environments', 'regions', 'resources'],
  maximum_accounts: 64,
  maximum_regions_per_account: 32,
  maximum_resources_per_account: 64,
  plaintext_secret_key_configuration_supported: false,
  requires_contract_verified_policy: true,
  requires_isolated_signer: true,
});
const serverSource = readFileSync(new URL('../broker/server.js', import.meta.url), 'utf8');
assert.match(serverSource, /await prepareTencentRuntimeExecutors\(\{ config: cfg \}\)/);
assert.match(
  serverSource,
  /commitTencentRuntimeExecutors\(taskExecutors, prepared\.tencentExecutors\)/,
);

console.log('tencent runtime: verified policy, signer boundary and atomic commit passed');
