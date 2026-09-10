import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';

import {
  CLOUDFLARE_ZONES_LIST_CONTRACT,
  createCloudflareZonesListAdapter,
} from '../broker/adapters/cloudflare-zones-list.js';
import { createCloudflareZonesListExecutor } from '../broker/adapters/cloudflare-zones-list-executor.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const ACCOUNT_ID = '0123456789abcdef0123456789abcdef';
const parameters = { resource_ref: ACCOUNT_ID, name: 'example.com', page: 2, per_page: 10 };
const context = {
  accountRef: 'cloudflare-primary',
  environment: 'production',
  execution: { tool: 'cloudflare.zones.list@1.0.0', target: ACCOUNT_ID, environment: 'production' },
  signal: new AbortController().signal,
};
const validBody = () => ({
  success: true,
  errors: [],
  messages: [],
  result: [
    {
      id: 'abcdef0123456789abcdef0123456789',
      account: { id: ACCOUNT_ID, name: 'not projected' },
      name: 'example.com',
      status: 'active',
      type: 'full',
      paused: false,
      name_servers: ['must-not-be-returned.example'],
    },
  ],
  result_info: { page: 2, per_page: 10, count: 1, total_count: 1, total_pages: 1 },
});
const validLease = () => ({ token: 'unit-cloudflare-token', account_id: ACCOUNT_ID });
const expectCode = (code) => (error) => error instanceof V2Error && error.code === code;

let tokenInput;
let requestInput;
const adapter = createCloudflareZonesListAdapter({
  tokenProvider: async (input) => {
    tokenInput = input;
    return validLease();
  },
  request: async (input) => {
    requestInput = input;
    return { status: 200, body: JSON.stringify(validBody()) };
  },
});
const result = await adapter(parameters, context);
assert.deepEqual(result, {
  zones: [
    {
      id: 'abcdef0123456789abcdef0123456789',
      name: 'example.com',
      status: 'active',
      type: 'full',
      paused: false,
    },
  ],
  result_info: { page: 2, per_page: 10, count: 1, total_count: 1, total_pages: 1 },
});
assert.deepEqual(tokenInput, {
  account_ref: 'cloudflare-primary',
  environment: 'production',
  account_id: ACCOUNT_ID,
  signal: context.signal,
});
const requestUrl = new URL(requestInput.path, requestInput.origin);
assert.equal(requestUrl.origin, 'https://api.cloudflare.com');
assert.equal(requestUrl.pathname, '/client/v4/zones');
assert.equal(requestUrl.searchParams.get('account.id'), ACCOUNT_ID);
assert.equal(requestUrl.searchParams.get('name'), 'example.com');
assert.equal(requestUrl.searchParams.get('page'), '2');
assert.equal(requestUrl.searchParams.get('per_page'), '10');
assert.equal(requestInput.method, 'GET');
assert.equal(requestInput.redirect, 'manual');
assert.equal(requestInput.max_response_bytes, 2 * 1024 * 1024);
assert.equal(requestInput.headers.Authorization, 'Bearer unit-cloudflare-token');
assert.equal(JSON.stringify(result).includes('unit-cloudflare-token'), false);
assert.equal(JSON.stringify(result).includes('name_servers'), false);

assert.throws(() => createCloudflareZonesListAdapter(), TypeError);
assert.throws(() => createCloudflareZonesListAdapter({ request: async () => {} }), TypeError);
for (const [changed, code] of [
  [{ resource_ref: 'bad' }, 'cloudflare_invalid_account'],
  [{ resource_ref: 123 }, 'cloudflare_invalid_account'],
  [{ name: 'bad/name' }, 'cloudflare_invalid_zone_name'],
  [{ page: 0 }, 'cloudflare_invalid_pagination'],
  [{ per_page: 4 }, 'cloudflare_invalid_pagination'],
  [{ per_page: 51 }, 'cloudflare_invalid_pagination'],
])
  await assert.rejects(adapter({ ...parameters, ...changed }, context), expectCode(code));
await assert.rejects(
  adapter(parameters, { ...context, accountRef: '' }),
  expectCode('cloudflare_account_unavailable'),
);
for (const execution of [
  { ...context.execution, tool: 'cloudflare.dns.list@1.0.0' },
  { ...context.execution, target: 'abcdef0123456789abcdef0123456789' },
  { ...context.execution, target: 123 },
  { ...context.execution, environment: 'staging' },
])
  await assert.rejects(
    adapter(parameters, { ...context, execution }),
    expectCode('cloudflare_execution_binding_mismatch'),
  );

const withLease = (lease) =>
  createCloudflareZonesListAdapter({
    tokenProvider: async () => lease,
    request: async () => ({ status: 200, body: validBody() }),
  });
await assert.rejects(
  withLease(null)(parameters, context),
  expectCode('cloudflare_credential_unavailable'),
);
await assert.rejects(
  withLease({ ...validLease(), token: '' })(parameters, context),
  expectCode('cloudflare_credential_unavailable'),
);
await assert.rejects(
  withLease({ ...validLease(), account_id: 'abcdef0123456789abcdef0123456789' })(
    parameters,
    context,
  ),
  expectCode('cloudflare_credential_scope_mismatch'),
);
await assert.rejects(
  createCloudflareZonesListAdapter({
    tokenProvider: async () => {
      throw new V2Error('secret', 'canary-cloudflare-secret', 500);
    },
    request: async () => ({ status: 200, body: validBody() }),
  })(parameters, context),
  (error) =>
    expectCode('cloudflare_credential_unavailable')(error) && !error.message.includes('canary'),
);

const withResponse = (response) =>
  createCloudflareZonesListAdapter({
    tokenProvider: async () => validLease(),
    request: async () => response,
  });
for (const [status, code] of [
  [301, 'cloudflare_redirect_denied'],
  [401, 'cloudflare_credential_rejected'],
  [403, 'cloudflare_forbidden'],
  [429, 'cloudflare_rate_limited'],
  [500, 'cloudflare_upstream_error'],
])
  await assert.rejects(withResponse({ status, body: '{}' })(parameters, context), expectCode(code));
await assert.rejects(
  withResponse({ status: 200, body: 'not-json' })(parameters, context),
  expectCode('cloudflare_invalid_response'),
);
await assert.rejects(
  withResponse({ status: 200, body: 'x'.repeat(2 * 1024 * 1024 + 1) })(parameters, context),
  expectCode('cloudflare_response_too_large'),
);
await assert.rejects(
  withResponse({ status: 200, body: { ...validBody(), success: false } })(parameters, context),
  expectCode('cloudflare_invalid_response'),
);
await assert.rejects(
  withResponse({
    status: 200,
    body: {
      ...validBody(),
      result: [{ ...validBody().result[0], account: { id: 'abcdef0123456789abcdef0123456789' } }],
    },
  })(parameters, context),
  expectCode('cloudflare_scope_mismatch'),
);
await assert.rejects(
  withResponse({
    status: 200,
    body: { ...validBody(), result: [{ ...validBody().result[0], name: '../example.com' }] },
  })(parameters, context),
  expectCode('cloudflare_scope_mismatch'),
);
await assert.rejects(
  withResponse({
    status: 200,
    body: { ...validBody(), result_info: { ...validBody().result_info, count: -1 } },
  })(parameters, context),
  expectCode('cloudflare_invalid_response'),
);
await assert.rejects(
  withResponse({
    status: 200,
    body: { ...validBody(), result_info: { ...validBody().result_info, page: 3 } },
  })(parameters, context),
  expectCode('cloudflare_invalid_response'),
);
await assert.rejects(
  withResponse({
    status: 200,
    body: { ...validBody(), result_info: { ...validBody().result_info, count: 0 } },
  })(parameters, context),
  expectCode('cloudflare_invalid_response'),
);
await assert.rejects(
  createCloudflareZonesListAdapter({
    tokenProvider: async () => validLease(),
    request: async () => {
      throw new Error('network detail');
    },
  })(parameters, context),
  (error) => expectCode('cloudflare_unavailable')(error) && !error.message.includes('detail'),
);
await assert.rejects(
  createCloudflareZonesListAdapter({
    tokenProvider: async () => validLease(),
    request: async () => {
      throw new V2Error('transport_policy_denied', 'safe', 403);
    },
  })(parameters, context),
  expectCode('transport_policy_denied'),
);

let defaultsInput;
await createCloudflareZonesListAdapter({
  tokenProvider: async () => validLease(),
  request: async (input) => {
    defaultsInput = input;
    return {
      status: 200,
      body: {
        ...validBody(),
        result_info: { ...validBody().result_info, page: 1, per_page: 20 },
      },
    };
  },
})({ resource_ref: ACCOUNT_ID }, context);
const defaultsUrl = new URL(defaultsInput.path, defaultsInput.origin);
assert.equal(defaultsUrl.searchParams.get('page'), '1');
assert.equal(defaultsUrl.searchParams.get('per_page'), '20');
assert.equal(defaultsUrl.searchParams.has('name'), false);

assert.deepEqual(CLOUDFLARE_ZONES_LIST_CONTRACT, {
  tool: 'cloudflare.zones.list@1.0.0',
  origin: 'https://api.cloudflare.com',
  method: 'GET',
  path: '/client/v4/zones',
  maximum_response_bytes: 2 * 1024 * 1024,
  required_permission: 'Zone Zone Read',
  pagination: { minimum_per_page: 5, maximum_per_page: 50 },
});

const transportCalls = [];
const executor = createCloudflareZonesListExecutor({
  tokenProvider: async () => validLease(),
  resolveHost: async () => [{ address: '104.16.132.229', family: 4 }],
  requestImpl: (options, callback) => {
    const request = new EventEmitter();
    request.setTimeout = () => {};
    request.destroy = () => {};
    request.end = () => {
      transportCalls.push(options);
      const response = Readable.from([JSON.stringify(validBody())]);
      response.statusCode = 200;
      response.headers = { 'content-type': 'application/json' };
      queueMicrotask(() => callback(response));
    };
    return request;
  },
});
const executorResult = await executor(parameters, context);
assert.equal(executorResult.zones[0].name, 'example.com');
assert.equal(transportCalls.length, 1);
assert.equal(transportCalls[0].hostname, 'api.cloudflare.com');
assert.equal(transportCalls[0].rejectUnauthorized, true);

console.log(
  'cloudflare zones adapter: account binding, projection, safe failures and pinned transport passed',
);
