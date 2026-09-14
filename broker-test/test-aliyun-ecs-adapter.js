import assert from 'node:assert/strict';
import { resolve } from 'node:path';

import {
  ALIYUN_ECS_INSTANCES_LIST_CONTRACT,
  createAliyunEcsInstancesListAdapter,
} from '../broker/adapters/aliyun-ecs-instances-list.js';
import { ApprovalBroker } from '../broker/lib/approvals-v2.js';
import { AutomationTaskBroker } from '../broker/lib/automation-tasks.js';
import { loadToolRegistry } from '../broker/lib/tool-registry.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const NOW = Date.parse('2026-09-11T01:02:03Z');
const REGION = 'cn-hangzhou';
const RESOURCE = 'primary-ecs-inventory';
const EXECUTION_ID = '12345678-1234-4123-8123-123456789abc';
const REQUEST_BINDING = 'a'.repeat(43);
const parameters = { resource_ref: RESOURCE, region_id: REGION, max_results: 20 };
const context = {
  accountRef: 'aliyun-primary',
  environment: 'production',
  execution: {
    tool: 'aliyun.ecs.instances.list@1.0.0',
    target: RESOURCE,
    environment: 'production',
    execution_id: EXECUTION_ID,
    request_binding: REQUEST_BINDING,
  },
  signal: new AbortController().signal,
};
const expectCode = (code) => (error) => error instanceof V2Error && error.code === code;
const CREDENTIAL_BINDING = 'b'.repeat(43);

function signedResult(change = {}) {
  return {
    account_ref: context.accountRef,
    environment: context.environment,
    resource_ref: RESOURCE,
    region_id: REGION,
    execution_id: EXECUTION_ID,
    request_binding: REQUEST_BINDING,
    credential_binding: CREDENTIAL_BINDING,
    headers: {
      Authorization:
        'ACS3-HMAC-SHA256 Credential=STS.TEST,' +
        'SignedHeaders=host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-security-token;x-acs-signature-nonce;x-acs-version,' +
        `Signature=${'a'.repeat(64)}`,
      host: 'ecs.cn-hangzhou.aliyuncs.com',
      'x-acs-action': 'DescribeInstances',
      'x-acs-content-sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      'x-acs-date': '2026-09-11T01:02:03Z',
      'x-acs-security-token': 'temporary-security-token',
      'x-acs-signature-nonce': 'nonce-12345678',
      'x-acs-version': '2014-05-26',
    },
    ...change,
  };
}

function responseBody(change = {}) {
  return {
    PageNumber: 1,
    PageSize: 20,
    TotalCount: 1,
    NextToken: 'next-page-token',
    Instances: {
      Instance: [
        {
          InstanceId: 'i-bp1234567890',
          InstanceName: 'broker-production',
          Status: 'Running',
          RegionId: REGION,
          ZoneId: 'cn-hangzhou-h',
          InstanceType: 'ecs.c8i.large',
          PublicIpAddress: { IpAddress: ['198.51.100.8'] },
        },
      ],
    },
    RequestId: 'request-id-not-released',
    ...change,
  };
}

let signerInput;
let requestInput;
const adapter = createAliyunEcsInstancesListAdapter({
  signRequest: async (input) => {
    signerInput = input;
    return signedResult();
  },
  request: async (input) => {
    requestInput = input;
    return { status: 200, body: JSON.stringify(responseBody()) };
  },
  now: () => NOW,
});
const result = await adapter(parameters, context);
assert.deepEqual(result, {
  instances: [
    {
      instance_id: 'i-bp1234567890',
      instance_name: 'broker-production',
      status: 'Running',
      region_id: REGION,
      zone_id: 'cn-hangzhou-h',
      instance_type: 'ecs.c8i.large',
    },
  ],
  total_count: 1,
  next_token: 'next-page-token',
});
assert.deepEqual(signerInput, {
  operation_id: 'ecs.instances.list',
  account_ref: 'aliyun-primary',
  environment: 'production',
  resource_ref: RESOURCE,
  region_id: REGION,
  execution_id: EXECUTION_ID,
  request_binding: REQUEST_BINDING,
  method: 'POST',
  path: '/',
  query: { MaxResults: 20, RegionId: REGION },
  signal: context.signal,
});
assert.equal(requestInput.origin, 'https://ecs.cn-hangzhou.aliyuncs.com');
assert.equal(requestInput.method, 'POST');
assert.equal(requestInput.path, '/?MaxResults=20&RegionId=cn-hangzhou');
assert.equal(requestInput.redirect, 'manual');
assert.equal(requestInput.max_response_bytes, 2 * 1024 * 1024);
assert.equal(requestInput.headers.Authorization, signedResult().headers.Authorization);
assert.equal(Object.hasOwn(requestInput.headers, 'host'), false);
assert.equal(JSON.stringify(result).includes('198.51.100.8'), false);
assert.equal(JSON.stringify(result).includes('RequestId'), false);
assert.equal(Object.hasOwn(signerInput, 'access_key_secret'), false);
assert.equal(Object.hasOwn(signerInput, 'security_token'), false);

assert.throws(() => createAliyunEcsInstancesListAdapter(), TypeError);
assert.throws(() => createAliyunEcsInstancesListAdapter({ request: async () => {} }), TypeError);
assert.throws(
  () =>
    createAliyunEcsInstancesListAdapter({
      request: async () => {},
      signRequest: async () => {},
      now: 1,
    }),
  TypeError,
);
for (const changed of [
  null,
  [],
  {},
  { ...parameters, resource_ref: '../inventory' },
  { ...parameters, region_id: 'https://attacker.example' },
  { ...parameters, next_token: '../token' },
  { ...parameters, max_results: 0 },
  { ...parameters, max_results: 101 },
  { ...parameters, arbitrary_url: 'https://attacker.example' },
]) {
  await assert.rejects(adapter(changed, context), (error) => error instanceof V2Error);
}
for (const execution of [
  { ...context.execution, tool: 'aliyun.ecs.instance.delete@1.0.0' },
  { ...context.execution, target: 'other-inventory' },
  { ...context.execution, environment: 'staging' },
  { ...context.execution, execution_id: 'wrong' },
  { ...context.execution, request_binding: 'wrong' },
]) {
  await assert.rejects(
    adapter(parameters, { ...context, execution }),
    expectCode('aliyun_execution_binding_mismatch'),
  );
}
await assert.rejects(
  adapter(parameters, { ...context, accountRef: '' }),
  expectCode('aliyun_account_unavailable'),
);

const withSigner = (value) =>
  createAliyunEcsInstancesListAdapter({
    request: async () => ({ status: 200, body: responseBody() }),
    signRequest: async () => value,
    now: () => NOW,
  });
for (const invalid of [
  null,
  signedResult({ account_ref: 'other' }),
  signedResult({ environment: 'staging' }),
  signedResult({ resource_ref: 'other' }),
  signedResult({ region_id: 'cn-shanghai' }),
  signedResult({ execution_id: '87654321-1234-4123-8123-123456789abc' }),
  signedResult({ request_binding: 'c'.repeat(43) }),
  signedResult({ headers: { ...signedResult().headers, host: 'ecs.cn-shanghai.aliyuncs.com' } }),
  signedResult({ headers: { ...signedResult().headers, 'x-acs-date': '2026-09-11T00:00:00Z' } }),
  signedResult({ headers: { ...signedResult().headers, unexpected: 'canary-secret' } }),
]) {
  await assert.rejects(
    withSigner(invalid)(parameters, context),
    (error) =>
      error instanceof V2Error &&
      ['aliyun_signer_scope_mismatch', 'aliyun_signer_response_invalid'].includes(error.code) &&
      !error.message.includes('canary'),
  );
}
await assert.rejects(
  createAliyunEcsInstancesListAdapter({
    request: async () => ({ status: 200, body: responseBody() }),
    signRequest: async () => {
      throw new Error('AccessKeySecret=canary-secret');
    },
    now: () => NOW,
  })(parameters, context),
  (error) => expectCode('aliyun_signer_unavailable')(error) && !error.message.includes('canary'),
);

const withResponse = (response) =>
  createAliyunEcsInstancesListAdapter({
    request: async () => response,
    signRequest: async () => signedResult(),
    now: () => NOW,
  });
for (const [status, code] of [
  [302, 'aliyun_redirect_denied'],
  [401, 'aliyun_credential_rejected'],
  [403, 'aliyun_forbidden'],
  [429, 'aliyun_rate_limited'],
  [500, 'aliyun_upstream_error'],
]) {
  await assert.rejects(withResponse({ status, body: '{}' })(parameters, context), expectCode(code));
}
await assert.rejects(
  createAliyunEcsInstancesListAdapter({
    request: async () => {
      throw new Error('SecurityToken=canary-secret');
    },
    signRequest: async () => signedResult(),
    now: () => NOW,
  })(parameters, context),
  (error) => expectCode('aliyun_unavailable')(error) && !error.message.includes('canary'),
);
for (const body of [
  '{bad-json',
  responseBody({ TotalCount: 0 }),
  responseBody({ NextToken: {} }),
  responseBody({
    Instances: { Instance: [{ ...responseBody().Instances.Instance[0], RegionId: 'cn-shanghai' }] },
  }),
  responseBody({
    Instances: { Instance: [{ ...responseBody().Instances.Instance[0], InstanceId: '../bad' }] },
  }),
]) {
  await assert.rejects(
    withResponse({ status: 200, body })(parameters, context),
    (error) =>
      error instanceof V2Error &&
      ['aliyun_invalid_response', 'aliyun_scope_mismatch'].includes(error.code),
  );
}

const registry = loadToolRegistry(resolve(import.meta.dirname, '../tools/registry.json'));
let calls = 0;
const events = [];
const taskBroker = new AutomationTaskBroker({
  toolRegistry: registry,
  authorize: async (operation) => ({
    allow:
      operation.provider === 'aliyun' &&
      operation.operationId === 'ecs.instances.list' &&
      operation.accountRef === 'aliyun-primary' &&
      operation.environment === 'production' &&
      operation.typedParameters?.resource_ref === RESOURCE &&
      operation.typedParameters?.region_id === REGION,
    ttlMs: 60_000,
  }),
  approvalBroker: new ApprovalBroker(),
  executors: new Map([
    [
      'aliyun.ecs.instances.list@1.0.0',
      async (...arguments_) => ({
        ...(await createAliyunEcsInstancesListAdapter({
          signRequest: async (input) =>
            signedResult({
              execution_id: input.execution_id,
              request_binding: input.request_binding,
            }),
          request: async () => {
            calls += 1;
            return { status: 200, body: responseBody({ NextToken: undefined }) };
          },
          now: () => NOW,
        })(...arguments_)),
        authority: {
          identity_type: 'AssumedRoleUser',
          account_id_sha256: '1'.repeat(64),
          principal_id_sha256: '2'.repeat(64),
          arn_sha256: '3'.repeat(64),
        },
      }),
    ],
  ]),
  onEvent: (event) => events.push(event),
});
const actor = {
  name: 'aliyun-inventory-agent',
  context: {
    via: 'workload_identity',
    client: { role: 'operator', principal_type: 'workload', security_profile: 'strict' },
  },
};
const task = await taskBroker.create(actor, {
  tool: 'aliyun.ecs.instances.list',
  tool_version: '1.0.0',
  account_ref: 'aliyun-primary',
  environment: 'production',
  idempotency_key: 'aliyun-ecs-inventory-task-0001',
  parameters,
});
assert.equal(task.state, 'READY');
const completed = await taskBroker.run(actor, task.id);
assert.equal(completed.state, 'SUCCEEDED');
assert.equal(completed.result.instances.length, 1);
assert.equal(calls, 1);
assert.deepEqual(
  taskBroker.eventsFor(actor, task.id).map((event) => event.state),
  ['REQUESTED', 'READY', 'EXECUTING', 'SUCCEEDED'],
);
for (const event of events) {
  const encoded = JSON.stringify(event);
  assert.equal(encoded.includes('temporary-security-token'), false);
  assert.equal(encoded.includes('Authorization'), false);
  assert.equal(encoded.includes('PublicIpAddress'), false);
}
await assert.rejects(taskBroker.run(actor, task.id), expectCode('invalid_state'));
assert.equal(calls, 1);

assert.deepEqual(ALIYUN_ECS_INSTANCES_LIST_CONTRACT, {
  tool: 'aliyun.ecs.instances.list@1.0.0',
  operation_id: 'ecs.instances.list',
  endpoint_template: 'https://ecs.{region_id}.aliyuncs.com',
  method: 'POST',
  path: '/',
  api_action: 'DescribeInstances',
  api_version: '2014-05-26',
  required_permission: 'ecs:DescribeInstances',
  maximum_response_bytes: 2 * 1024 * 1024,
  maximum_page_size: 100,
  arbitrary_url: false,
  credential_export: false,
  requires_isolated_signer: true,
});

console.log(
  'aliyun ECS adapter: typed request, isolated signing, regional scope and task loop passed',
);
