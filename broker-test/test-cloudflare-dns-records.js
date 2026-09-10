import assert from 'node:assert/strict';
import { resolve } from 'node:path';

import {
  CLOUDFLARE_DNS_RECORDS_LIST_CONTRACT,
  createCloudflareDnsRecordsListAdapter,
} from '../broker/adapters/cloudflare-dns-records-list.js';
import { V2Error } from '../broker/lib/operations-v2.js';
import { ApprovalBroker } from '../broker/lib/approvals-v2.js';
import { AutomationTaskBroker } from '../broker/lib/automation-tasks.js';
import { loadToolRegistry } from '../broker/lib/tool-registry.js';

const ZONE_ID = '0123456789abcdef0123456789abcdef';
const EXECUTION_ID = '12345678-1234-4123-8123-123456789abc';
const REQUEST_BINDING = 'a'.repeat(43);
const parameters = {
  resource_ref: ZONE_ID,
  zone_id: ZONE_ID,
  type: 'A',
  name: 'www.example.com',
  proxied: true,
  page: 2,
  per_page: 25,
};
const context = {
  accountRef: 'cloudflare-primary',
  environment: 'production',
  execution: {
    tool: 'cloudflare.dns.records.list@1.0.0',
    target: ZONE_ID,
    environment: 'production',
    execution_id: EXECUTION_ID,
    request_binding: REQUEST_BINDING,
  },
  signal: new AbortController().signal,
};
const body = (change = {}) => ({
  success: true,
  result: [
    {
      id: 'abcdef0123456789abcdef0123456789',
      type: 'A',
      name: 'www.example.com',
      content: '198.51.100.9',
      comment: 'must not be released',
      ttl: 300,
      proxied: true,
    },
  ],
  result_info: { page: 2, per_page: 25, count: 1, total_count: 1, total_pages: 1 },
  ...change,
});
const lease = { token: 'temporary-dns-token', zone_id: ZONE_ID };
const expectCode = (code) => (error) => error instanceof V2Error && error.code === code;

let tokenInput;
let requestInput;
const adapter = createCloudflareDnsRecordsListAdapter({
  tokenProvider: async (input) => {
    tokenInput = input;
    return lease;
  },
  request: async (input) => {
    requestInput = input;
    return { status: 200, body: JSON.stringify(body()) };
  },
});
const result = await adapter(parameters, context);
assert.deepEqual(result, {
  records: [
    {
      id: 'abcdef0123456789abcdef0123456789',
      type: 'A',
      name: 'www.example.com',
      ttl: 300,
      proxied: true,
    },
  ],
  result_info: { page: 2, per_page: 25, count: 1, total_count: 1, total_pages: 1 },
});
assert.deepEqual(tokenInput, {
  account_ref: 'cloudflare-primary',
  environment: 'production',
  zone_id: ZONE_ID,
  execution_id: EXECUTION_ID,
  request_binding: REQUEST_BINDING,
  signal: context.signal,
});
assert.equal(requestInput.origin, 'https://api.cloudflare.com');
assert.equal(requestInput.method, 'GET');
assert.equal(requestInput.redirect, 'manual');
assert.equal(
  requestInput.path,
  `/client/v4/zones/${ZONE_ID}/dns_records?page=2&per_page=25&type=A&name.exact=www.example.com&proxied=true`,
);
assert.equal(requestInput.headers.Authorization, 'Bearer temporary-dns-token');
assert.equal(JSON.stringify(result).includes('198.51.100.9'), false);
assert.equal(JSON.stringify(result).includes('must not be released'), false);

assert.throws(() => createCloudflareDnsRecordsListAdapter(), TypeError);
assert.throws(() => createCloudflareDnsRecordsListAdapter({ request: async () => {} }), TypeError);
for (const invalid of [
  { ...parameters, zone_id: 'bad' },
  { ...parameters, resource_ref: 'a'.repeat(32) },
  { ...parameters, type: 'ANY' },
  { ...parameters, name: '../example.com' },
  { ...parameters, proxied: 'true' },
  { ...parameters, page: 0 },
  { ...parameters, per_page: 101 },
]) {
  await assert.rejects(adapter(invalid, context), (error) => error instanceof V2Error);
}
for (const execution of [
  { ...context.execution, tool: 'cloudflare.zones.list@1.0.0' },
  { ...context.execution, target: 'b'.repeat(32) },
  { ...context.execution, environment: 'staging' },
  { ...context.execution, execution_id: 'wrong' },
  { ...context.execution, request_binding: 'wrong' },
]) {
  await assert.rejects(
    adapter(parameters, { ...context, execution }),
    expectCode('cloudflare_dns_execution_binding_mismatch'),
  );
}
await assert.rejects(
  adapter(parameters, { ...context, accountRef: '' }),
  expectCode('cloudflare_dns_account_unavailable'),
);

for (const invalidLease of [null, { ...lease, token: '' }, { ...lease, zone_id: 'b'.repeat(32) }]) {
  await assert.rejects(
    createCloudflareDnsRecordsListAdapter({
      tokenProvider: async () => invalidLease,
      request: async () => ({ status: 200, body: body() }),
    })(parameters, context),
    expectCode('cloudflare_dns_credential_unavailable'),
  );
}
await assert.rejects(
  createCloudflareDnsRecordsListAdapter({
    tokenProvider: async () => {
      throw new Error('canary-secret');
    },
    request: async () => ({ status: 200, body: body() }),
  })(parameters, context),
  (error) =>
    expectCode('cloudflare_dns_credential_unavailable')(error) && !error.message.includes('canary'),
);

const withResponse = (response) =>
  createCloudflareDnsRecordsListAdapter({
    tokenProvider: async () => lease,
    request: async () => response,
  });
for (const status of [301, 302, 303, 307, 308]) {
  await assert.rejects(
    withResponse({ status })(parameters, context),
    expectCode('cloudflare_dns_redirect_denied'),
  );
}
for (const [status, code] of [
  [401, 'cloudflare_dns_credential_rejected'],
  [403, 'cloudflare_dns_forbidden'],
  [429, 'cloudflare_dns_rate_limited'],
  [500, 'cloudflare_dns_upstream_error'],
]) {
  await assert.rejects(withResponse({ status })(parameters, context), expectCode(code));
}
for (const invalidBody of [
  '{bad-json',
  'x'.repeat(2 * 1024 * 1024 + 1),
  null,
  undefined,
  body({ success: false }),
  body({ result: [null] }),
  body({ result: [{ ...body().result[0], content: 'hidden', type: 'ANY' }] }),
  body({ result_info: { ...body().result_info, count: 2 } }),
]) {
  await assert.rejects(
    withResponse({ status: 200, body: invalidBody })(parameters, context),
    (error) => error instanceof V2Error && !error.message.includes('content'),
  );
}
await assert.rejects(
  createCloudflareDnsRecordsListAdapter({
    tokenProvider: async () => lease,
    request: async () => {
      throw new Error('canary-upstream-secret');
    },
  })(parameters, context),
  (error) => expectCode('cloudflare_dns_unavailable')(error) && !error.message.includes('canary'),
);

const registry = loadToolRegistry(resolve(import.meta.dirname, '../tools/registry.json'));
let taskCalls = 0;
const taskBroker = new AutomationTaskBroker({
  toolRegistry: registry,
  authorize: async (operation) => ({
    allow:
      operation.provider === 'cloudflare' &&
      operation.operationId === 'dns.records.list' &&
      operation.accountRef === 'cloudflare-primary' &&
      operation.environment === 'production' &&
      operation.typedParameters?.resource_ref === ZONE_ID,
    ttlMs: 60_000,
  }),
  approvalBroker: new ApprovalBroker(),
  executors: new Map([
    [
      'cloudflare.dns.records.list@1.0.0',
      createCloudflareDnsRecordsListAdapter({
        tokenProvider: async () => lease,
        request: async () => {
          taskCalls += 1;
          return {
            status: 200,
            body: body({
              result_info: { page: 1, per_page: 50, count: 1, total_count: 1, total_pages: 1 },
            }),
          };
        },
      }),
    ],
  ]),
});
const actor = {
  name: 'cloudflare-inventory-agent',
  context: {
    via: 'workload_identity',
    client: {
      role: 'operator',
      principal_type: 'workload',
      security_profile: 'strict',
    },
  },
};
const task = await taskBroker.create(actor, {
  tool: 'cloudflare.dns.records.list',
  tool_version: '1.0.0',
  account_ref: 'cloudflare-primary',
  environment: 'production',
  idempotency_key: 'cloudflare-dns-records-list-0001',
  parameters: { resource_ref: ZONE_ID, zone_id: ZONE_ID },
});
assert.equal(task.state, 'READY');
const completed = await taskBroker.run(actor, task.id);
assert.equal(completed.state, 'SUCCEEDED');
assert.equal(completed.result.records.length, 1);
assert.equal(taskCalls, 1);
assert.equal(JSON.stringify(completed).includes('temporary-dns-token'), false);
await assert.rejects(taskBroker.run(actor, task.id), expectCode('invalid_state'));

assert.deepEqual(CLOUDFLARE_DNS_RECORDS_LIST_CONTRACT, {
  tool: 'cloudflare.dns.records.list@1.0.0',
  origin: 'https://api.cloudflare.com',
  method: 'GET',
  path_template: '/client/v4/zones/{zone_id}/dns_records',
  required_permission: 'DNS Read',
  maximum_response_bytes: 2 * 1024 * 1024,
  maximum_per_page: 100,
  releases_record_content: false,
});

console.log(
  'cloudflare dns records adapter: zone binding, metadata projection and safe failures passed',
);
