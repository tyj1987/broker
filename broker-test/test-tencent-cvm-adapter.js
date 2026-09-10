import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
  createTencentCvmInstancesListAdapter,
  TENCENT_CVM_INSTANCES_LIST_CONTRACT,
} from '../broker/adapters/tencent-cvm-instances-list.js';
import { createTencentCvmInstancesListExecutor } from '../broker/adapters/tencent-cvm-instances-list-executor.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const NOW = Date.parse('2026-09-11T02:03:04Z');
const TIMESTAMP = Math.floor(NOW / 1000);
const REGION = 'ap-singapore';
const RESOURCE = 'primary-cvm-inventory';
const EXECUTION_ID = '12345678-1234-4123-8123-123456789abc';
const REQUEST_BINDING = 'a'.repeat(43);
const parameters = { resource_ref: RESOURCE, region: REGION, offset: 0, limit: 20 };
const context = {
  accountRef: 'tencent-primary',
  environment: 'production',
  execution: {
    tool: 'tencent.cvm.instances.list@1.0.0',
    target: RESOURCE,
    environment: 'production',
    execution_id: EXECUTION_ID,
    request_binding: REQUEST_BINDING,
  },
  signal: new AbortController().signal,
};
const expectCode = (code) => (error) => error instanceof V2Error && error.code === code;

function responseBody(change = {}) {
  return {
    Response: {
      InstanceSet: [
        {
          InstanceId: 'ins-xlsyru2j',
          InstanceName: 'broker-recovery',
          InstanceState: 'RUNNING',
          InstanceType: 'S2.SMALL2',
          Placement: { Zone: 'ap-singapore-1', ProjectId: 12345 },
          PrivateIpAddresses: ['10.0.0.8'],
          PublicIpAddresses: ['198.51.100.8'],
          LoginSettings: { KeyIds: ['skey-secret-not-released'] },
        },
      ],
      TotalCount: 1,
      RequestId: 'request-id-not-released',
      ...change,
    },
  };
}

function signedResult(input, change = {}) {
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
      'x-tc-timestamp': String(TIMESTAMP),
      'x-tc-token': 'temporary-session-token',
      'x-tc-version': '2017-03-12',
    },
    ...change,
  };
}

let signerInput;
let requestInput;
const adapter = createTencentCvmInstancesListAdapter({
  signRequest: async (input) => {
    signerInput = input;
    return signedResult(input);
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
      instance_id: 'ins-xlsyru2j',
      instance_name: 'broker-recovery',
      state: 'RUNNING',
      instance_type: 'S2.SMALL2',
      region: REGION,
      zone: 'ap-singapore-1',
    },
  ],
  total_count: 1,
  offset: 0,
  limit: 20,
});
assert.equal(requestInput.origin, 'https://cvm.tencentcloudapi.com');
assert.equal(requestInput.method, 'POST');
assert.equal(requestInput.path, '/');
assert.equal(requestInput.redirect, 'manual');
assert.equal(requestInput.max_response_bytes, 2 * 1024 * 1024);
assert.equal(Object.hasOwn(requestInput.headers, 'host'), false);
assert.deepEqual(JSON.parse(requestInput.body), { Limit: 20, Offset: 0 });
assert.equal(signerInput.payload, requestInput.body);
assert.equal(
  signerInput.payload_sha256,
  createHash('sha256').update(requestInput.body).digest('hex'),
);
assert.equal(signerInput.execution_id, EXECUTION_ID);
assert.equal(signerInput.request_binding, REQUEST_BINDING);
assert.equal(JSON.stringify(result).includes('198.51.100.8'), false);
assert.equal(JSON.stringify(result).includes('10.0.0.8'), false);
assert.equal(JSON.stringify(result).includes('skey-secret'), false);
assert.equal(JSON.stringify(result).includes('RequestId'), false);
assert.equal(Object.hasOwn(signerInput, 'secret_key'), false);
assert.equal(Object.hasOwn(signerInput, 'security_token'), false);

assert.throws(() => createTencentCvmInstancesListAdapter(), TypeError);
assert.throws(() => createTencentCvmInstancesListAdapter({ request: async () => {} }), TypeError);
assert.throws(
  () =>
    createTencentCvmInstancesListAdapter({
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
  { ...parameters, region: 'https://attacker.example' },
  { ...parameters, offset: -1 },
  { ...parameters, offset: 10_001 },
  { ...parameters, limit: 0 },
  { ...parameters, limit: 101 },
  { ...parameters, arbitrary_url: 'https://attacker.example' },
]) {
  await assert.rejects(adapter(changed, context), (error) => error instanceof V2Error);
}
for (const execution of [
  { ...context.execution, tool: 'tencent.cvm.instances.terminate@1.0.0' },
  { ...context.execution, target: 'other-inventory' },
  { ...context.execution, environment: 'staging' },
  { ...context.execution, execution_id: 'not-an-id' },
  { ...context.execution, request_binding: 'short' },
]) {
  await assert.rejects(
    adapter(parameters, { ...context, execution }),
    expectCode('tencent_execution_binding_mismatch'),
  );
}
await assert.rejects(
  adapter(parameters, { ...context, accountRef: '' }),
  expectCode('tencent_account_unavailable'),
);

const withSigner = (mutate) =>
  createTencentCvmInstancesListAdapter({
    request: async () => ({ status: 200, body: responseBody() }),
    signRequest: async (input) => mutate(signedResult(input)),
    now: () => NOW,
  });
for (const [mutate, code] of [
  [() => null, 'tencent_signer_scope_mismatch'],
  [(value) => ({ ...value, account_ref: 'other' }), 'tencent_signer_scope_mismatch'],
  [
    (value) => ({ ...value, execution_id: '87654321-1234-4123-8123-123456789abc' }),
    'tencent_signer_scope_mismatch',
  ],
  [(value) => ({ ...value, payload_sha256: 'b'.repeat(64) }), 'tencent_signer_scope_mismatch'],
  [
    (value) => ({ ...value, headers: { ...value.headers, host: 'sts.tencentcloudapi.com' } }),
    'tencent_signer_response_invalid',
  ],
  [
    (value) => ({ ...value, headers: { ...value.headers, 'x-tc-region': 'ap-guangzhou' } }),
    'tencent_signer_response_invalid',
  ],
  [
    (value) => ({
      ...value,
      headers: { ...value.headers, 'x-tc-timestamp': String(TIMESTAMP - 301) },
    }),
    'tencent_signer_response_invalid',
  ],
  [
    (value) => ({ ...value, headers: { ...value.headers, unexpected: 'canary-secret' } }),
    'tencent_signer_response_invalid',
  ],
]) {
  await assert.rejects(
    withSigner(mutate)(parameters, context),
    (error) => expectCode(code)(error) && !error.message.includes('canary'),
  );
}
await assert.rejects(
  createTencentCvmInstancesListAdapter({
    request: async () => ({ status: 200, body: responseBody() }),
    signRequest: async () => {
      throw new Error('SecretKey=canary-secret');
    },
    now: () => NOW,
  })(parameters, context),
  (error) => expectCode('tencent_signer_unavailable')(error) && !error.message.includes('canary'),
);

const withResponse = (response) =>
  createTencentCvmInstancesListAdapter({
    request: async () => response,
    signRequest: async (input) => signedResult(input),
    now: () => NOW,
  });
for (const [status, code] of [
  [302, 'tencent_redirect_denied'],
  [401, 'tencent_credential_rejected'],
  [403, 'tencent_forbidden'],
  [429, 'tencent_rate_limited'],
  [500, 'tencent_upstream_error'],
]) {
  await assert.rejects(withResponse({ status, body: '{}' })(parameters, context), expectCode(code));
}
for (const body of [
  '{bad-json',
  responseBody({ TotalCount: 0 }),
  responseBody({ Error: { Code: 'InternalError', Message: 'canary-secret' } }),
  responseBody({
    InstanceSet: [{ ...responseBody().Response.InstanceSet[0], InstanceId: '../bad' }],
  }),
  responseBody({ InstanceSet: [{ ...responseBody().Response.InstanceSet[0], Placement: {} }] }),
]) {
  await assert.rejects(
    withResponse({ status: 200, body })(parameters, context),
    (error) =>
      error instanceof V2Error &&
      ['tencent_invalid_response', 'tencent_upstream_error'].includes(error.code) &&
      !error.message.includes('canary'),
  );
}
await assert.rejects(
  createTencentCvmInstancesListAdapter({
    request: async () => {
      throw new Error('X-TC-Token=canary-secret');
    },
    signRequest: async (input) => signedResult(input),
    now: () => NOW,
  })(parameters, context),
  (error) => expectCode('tencent_unavailable')(error) && !error.message.includes('canary'),
);

const executor = createTencentCvmInstancesListExecutor({
  signRequest: async (input) => signedResult(input),
  resolveHost: async () => ['203.0.113.10'],
  requestImpl: async () => ({ status: 200, body: JSON.stringify(responseBody()) }),
  now: () => NOW,
});
assert.equal(typeof executor, 'function');

assert.deepEqual(TENCENT_CVM_INSTANCES_LIST_CONTRACT, {
  tool: 'tencent.cvm.instances.list@1.0.0',
  operation_id: 'cvm.instances.list',
  origin: 'https://cvm.tencentcloudapi.com',
  method: 'POST',
  path: '/',
  api_action: 'DescribeInstances',
  api_version: '2017-03-12',
  required_permission: 'cvm:DescribeInstances',
  maximum_response_bytes: 2 * 1024 * 1024,
  maximum_page_size: 100,
  releases_network_addresses: false,
  arbitrary_url: false,
  credential_export: false,
  requires_isolated_signer: true,
});

console.log(
  'tencent CVM adapter: fixed request, execution-bound signing and safe projection passed',
);
