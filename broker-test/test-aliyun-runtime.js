import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { Readable } from 'node:stream';

import {
  ALIYUN_RUNTIME_CONTRACT,
  AliyunRuntimeConfigError,
  commitAliyunRuntimeExecutors,
  prepareAliyunRuntimeExecutors,
} from '../broker/adapters/aliyun-runtime.js';
import { createAliyunEcsInstancesListExecutor } from '../broker/adapters/aliyun-ecs-instances-list-executor.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const NOW = Date.parse('2026-09-11T01:02:03Z');
const REGION = 'cn-hangzhou';
const RESOURCE = 'primary-ecs-inventory';
const CREDENTIAL_BINDING = 'b'.repeat(43);
const basePolicy = {
  enabled: true,
  contract_verified: true,
  execution_mode: 'adapter',
  accounts: ['aliyun-primary'],
};
const validConfig = () => ({
  operation_policies: { aliyun: { 'ecs.instances.list': { ...basePolicy } } },
  provider_accounts: {
    aliyun: {
      'aliyun-primary': {
        environments: ['production'],
        regions: [REGION],
        resources: [RESOURCE],
      },
    },
  },
});
const expectRuntimeError = (error) => error instanceof AliyunRuntimeConfigError;
let factoryCalls = 0;
let probeCalls = 0;
const signInputs = [];
const createSignerClient = () => {
  factoryCalls += 1;
  return {
    probe: async () => {
      probeCalls += 1;
      return true;
    },
    sign: async (input) => {
      signInputs.push(input);
      const authority = input.operation_id === 'sts.caller-identity.read';
      return {
        account_ref: input.account_ref,
        environment: input.environment,
        resource_ref: input.resource_ref,
        region_id: input.region_id,
        credential_binding: CREDENTIAL_BINDING,
        headers: {
          Authorization:
            'ACS3-HMAC-SHA256 Credential=STS.TEST,' +
            'SignedHeaders=host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-security-token;x-acs-signature-nonce;x-acs-version,' +
            `Signature=${'a'.repeat(64)}`,
          host: authority ? 'sts.aliyuncs.com' : `ecs.${REGION}.aliyuncs.com`,
          'x-acs-action': authority ? 'GetCallerIdentity' : 'DescribeInstances',
          'x-acs-content-sha256':
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          'x-acs-date': '2026-09-11T01:02:03Z',
          'x-acs-security-token': 'temporary-security-token',
          'x-acs-signature-nonce': 'nonce-12345678',
          'x-acs-version': authority ? '2015-04-01' : '2014-05-26',
        },
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
    const authority = options.hostname === 'sts.aliyuncs.com';
    const response = Readable.from([
      JSON.stringify(
        authority
          ? {
              IdentityType: 'AssumedRoleUser',
              AccountId: '1234567890123456',
              PrincipalId: '1234567890123456:broker-contract',
              Arn: 'acs:ram::1234567890123456:role/broker-contract',
            }
          : {
              TotalCount: 1,
              Instances: {
                Instance: [
                  {
                    InstanceId: 'i-bp1234567890',
                    InstanceName: 'broker-production',
                    Status: 'Running',
                    RegionId: REGION,
                    ZoneId: 'cn-hangzhou-h',
                    InstanceType: 'ecs.c8i.large',
                  },
                ],
              },
            },
      ),
    ]);
    response.statusCode = 200;
    response.headers = { 'content-type': 'application/json' };
    queueMicrotask(() => callback(response));
  };
  return request;
};

assert.equal((await prepareAliyunRuntimeExecutors({ config: {} })).size, 0);
assert.equal(
  (
    await prepareAliyunRuntimeExecutors({
      config: {
        operation_policies: {
          aliyun: { 'ecs.instances.list': { ...basePolicy, contract_verified: false } },
        },
      },
    })
  ).size,
  0,
);

const executors = await prepareAliyunRuntimeExecutors({
  config: validConfig(),
  createSignerClient,
  resolveHost: async () => [{ address: '47.111.0.1', family: 4 }],
  requestImpl,
  now: () => NOW,
});
assert.deepEqual([...executors.keys()], ['aliyun.ecs.instances.list@1.0.0']);
assert.equal(factoryCalls, 1);
assert.equal(probeCalls, 1);
const signal = new AbortController().signal;
const result = await executors.get('aliyun.ecs.instances.list@1.0.0')(
  { resource_ref: RESOURCE, region_id: REGION, max_results: 20 },
  {
    accountRef: 'aliyun-primary',
    environment: 'production',
    signal,
    execution: {
      tool: 'aliyun.ecs.instances.list@1.0.0',
      target: RESOURCE,
      environment: 'production',
    },
  },
);
assert.equal(result.instances[0].instance_id, 'i-bp1234567890');
assert.match(result.authority.account_id_sha256, /^[a-f0-9]{64}$/);
assert.equal(result.authority.identity_type, 'AssumedRoleUser');
assert.equal(signInputs[0].account_ref, 'aliyun-primary');
assert.equal(signInputs[0].region_id, REGION);
assert.equal(signInputs[0].resource_ref, RESOURCE);
assert.equal(signInputs[0].signal, signal);
assert.equal(signInputs[0].operation_id, 'sts.caller-identity.read');
assert.equal(signInputs[1].operation_id, 'ecs.instances.list');
assert.equal(requests[0].hostname, 'sts.aliyuncs.com');
assert.equal(requests[1].hostname, `ecs.${REGION}.aliyuncs.com`);
assert.equal(JSON.stringify(result).includes('temporary-security-token'), false);

const signedFor = (input, credentialBinding) => {
  const authority = input.operation_id === 'sts.caller-identity.read';
  return {
    account_ref: input.account_ref,
    environment: input.environment,
    resource_ref: input.resource_ref,
    region_id: input.region_id,
    credential_binding: credentialBinding,
    headers: {
      Authorization:
        'ACS3-HMAC-SHA256 Credential=STS.TEST,' +
        'SignedHeaders=host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-security-token;x-acs-signature-nonce;x-acs-version,' +
        `Signature=${'a'.repeat(64)}`,
      host: authority ? 'sts.aliyuncs.com' : `ecs.${REGION}.aliyuncs.com`,
      'x-acs-action': authority ? 'GetCallerIdentity' : 'DescribeInstances',
      'x-acs-content-sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      'x-acs-date': '2026-09-11T01:02:03Z',
      'x-acs-security-token': 'temporary-security-token',
      'x-acs-signature-nonce': 'nonce-12345678',
      'x-acs-version': authority ? '2015-04-01' : '2014-05-26',
    },
  };
};
let driftSigns = 0;
let driftOutbound = 0;
const driftExecutor = createAliyunEcsInstancesListExecutor({
  signRequest: async (input) =>
    signedFor(input, ++driftSigns === 1 ? 'i'.repeat(43) : 'b'.repeat(43)),
  resolveHost: async () => [{ address: '47.111.0.1', family: 4 }],
  requestImpl: (options, callback) => {
    driftOutbound += 1;
    return requestImpl(options, callback);
  },
  now: () => NOW,
});
const executionContext = {
  accountRef: 'aliyun-primary',
  environment: 'production',
  execution: {
    tool: 'aliyun.ecs.instances.list@1.0.0',
    target: RESOURCE,
    environment: 'production',
  },
};
await assert.rejects(
  driftExecutor({ resource_ref: RESOURCE, region_id: REGION, max_results: 20 }, executionContext),
  (error) => error instanceof V2Error && error.code === 'aliyun_credential_binding_mismatch',
);
assert.equal(driftSigns, 2);
assert.equal(driftOutbound, 1);

let invalidSigns = 0;
let invalidOutbound = 0;
const invalidExecutor = createAliyunEcsInstancesListExecutor({
  signRequest: async (input) => {
    invalidSigns += 1;
    return signedFor(input, CREDENTIAL_BINDING);
  },
  requestImpl: () => {
    invalidOutbound += 1;
    throw new Error('must not run');
  },
  now: () => NOW,
});
for (const invalidParameters of [
  { resource_ref: RESOURCE, region_id: REGION, max_results: 0 },
  { resource_ref: RESOURCE, region_id: REGION, next_token: '../bad' },
  { resource_ref: RESOURCE, region_id: REGION, extra: true },
])
  await assert.rejects(invalidExecutor(invalidParameters, executionContext), V2Error);
assert.equal(invalidSigns, 0);
assert.equal(invalidOutbound, 0);

for (const [parameters, changedContext] of [
  [{ resource_ref: RESOURCE, region_id: 'cn-shanghai' }, {}],
  [
    { resource_ref: 'other-inventory', region_id: REGION },
    {
      execution: {
        tool: 'aliyun.ecs.instances.list@1.0.0',
        target: 'other-inventory',
        environment: 'production',
      },
    },
  ],
  [
    { resource_ref: RESOURCE, region_id: REGION },
    {
      environment: 'staging',
      execution: {
        tool: 'aliyun.ecs.instances.list@1.0.0',
        target: RESOURCE,
        environment: 'staging',
      },
    },
  ],
]) {
  await assert.rejects(
    executors.get('aliyun.ecs.instances.list@1.0.0')(parameters, {
      accountRef: 'aliyun-primary',
      environment: 'production',
      execution: {
        tool: 'aliyun.ecs.instances.list@1.0.0',
        target: parameters.resource_ref,
        environment: 'production',
      },
      ...changedContext,
    }),
    (error) => error instanceof V2Error && error.code === 'aliyun_authority_signer_unavailable',
  );
}

for (const mutate of [
  (config) => {
    config.operation_policies.aliyun = [];
  },
  (config) => {
    config.operation_policies.aliyun['ecs.instances.list'].execution_mode = 'browser';
  },
  (config) => {
    config.operation_policies.aliyun.unknown = { ...basePolicy };
  },
  (config) => {
    config.operation_policies.aliyun['ecs.instances.list'].accounts = [];
  },
  (config) => {
    delete config.provider_accounts;
  },
  (config) => {
    config.provider_accounts.aliyun = [];
  },
  (config) => {
    config.provider_accounts.aliyun['aliyun-primary'].access_key_secret = 'forbidden';
  },
  (config) => {
    config.provider_accounts.aliyun['aliyun-primary'].environments = [];
  },
  (config) => {
    config.provider_accounts.aliyun['aliyun-primary'].regions = ['https://attacker.example'];
  },
  (config) => {
    config.provider_accounts.aliyun['aliyun-primary'].resources = ['../inventory'];
  },
  (config) => {
    config.provider_accounts.aliyun['aliyun-primary'].regions = [REGION, REGION];
  },
  (config) => {
    config.operation_policies.aliyun['ecs.instances.list'].accounts = ['missing'];
  },
]) {
  const config = validConfig();
  mutate(config);
  await assert.rejects(
    prepareAliyunRuntimeExecutors({ config, createSignerClient }),
    expectRuntimeError,
  );
}
const tooManyAccounts = validConfig();
tooManyAccounts.provider_accounts.aliyun = Object.fromEntries(
  Array.from({ length: 65 }, (_, index) => [
    `account-${index}`,
    { environments: ['production'], regions: [REGION], resources: [`inventory-${index}`] },
  ]),
);
await assert.rejects(
  prepareAliyunRuntimeExecutors({ config: tooManyAccounts, createSignerClient }),
  expectRuntimeError,
);
await assert.rejects(
  prepareAliyunRuntimeExecutors({ config: validConfig(), createSignerClient: () => null }),
  expectRuntimeError,
);
await assert.rejects(
  prepareAliyunRuntimeExecutors({
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
  ['aliyun.old@1.0.0', async () => ({})],
]);
assert.equal(commitAliyunRuntimeExecutors(target, executors), target);
assert.equal(target.has('broker.tools.inspect@1.0.0'), true);
assert.equal(target.has('aliyun.old@1.0.0'), false);
assert.equal(target.has('aliyun.ecs.instances.list@1.0.0'), true);
assert.throws(() => commitAliyunRuntimeExecutors({}, executors), TypeError);
assert.throws(() => commitAliyunRuntimeExecutors(target, {}), TypeError);

assert.deepEqual(ALIYUN_RUNTIME_CONTRACT, {
  supported_operations: ['ecs.instances.list'],
  account_binding_fields: ['environments', 'regions', 'resources'],
  maximum_accounts: 64,
  maximum_regions_per_account: 32,
  maximum_resources_per_account: 64,
  plaintext_access_key_configuration_supported: false,
  requires_contract_verified_policy: true,
  requires_isolated_signer: true,
});
const serverSource = readFileSync(new URL('../broker/server.js', import.meta.url), 'utf8');
assert.match(serverSource, /await prepareAliyunRuntimeExecutors\(\{ config: cfg \}\)/);
assert.match(
  serverSource,
  /commitAliyunRuntimeExecutors\(taskExecutors, prepared\.aliyunExecutors\)/,
);

console.log(
  'aliyun runtime: verified policy, account bindings, signer probe and atomic commit passed',
);
