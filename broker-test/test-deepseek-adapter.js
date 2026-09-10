import assert from 'node:assert/strict';
import { resolve } from 'node:path';

import {
  createDeepSeekModelsListAdapter,
  DEEPSEEK_MODELS_LIST_CONTRACT,
} from '../broker/adapters/deepseek-models-list.js';
import { ApprovalBroker } from '../broker/lib/approvals-v2.js';
import { AutomationTaskBroker } from '../broker/lib/automation-tasks.js';
import { loadToolRegistry } from '../broker/lib/tool-registry.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const NOW = Date.parse('2026-09-11T02:00:00Z');
const parameters = { resource_ref: 'model-catalog' };
const context = {
  accountRef: 'deepseek-primary',
  environment: 'production',
  execution: {
    tool: 'deepseek.models.list@1.0.0',
    target: 'model-catalog',
    environment: 'production',
  },
  signal: new AbortController().signal,
};
const lease = (change = {}) => ({
  token: 'temporary-deepseek-token',
  expires_at: new Date(NOW + 60_000).toISOString(),
  account_ref: context.accountRef,
  environment: context.environment,
  resource_ref: 'model-catalog',
  ...change,
});
const responseBody = (change = {}) => ({
  object: 'list',
  data: [
    { id: 'deepseek-v4-flash', object: 'model', owned_by: 'deepseek' },
    { id: 'deepseek-v4-pro', object: 'model', owned_by: 'deepseek' },
  ],
  ...change,
});
const expectCode = (code) => (error) => error instanceof V2Error && error.code === code;

let tokenInput;
let requestInput;
const adapter = createDeepSeekModelsListAdapter({
  tokenProvider: async (input) => {
    tokenInput = input;
    return lease();
  },
  request: async (input) => {
    requestInput = input;
    return { status: 200, body: responseBody() };
  },
  now: () => NOW,
});
assert.deepEqual(await adapter(parameters, context), {
  models: [
    { id: 'deepseek-v4-flash', owned_by: 'deepseek' },
    { id: 'deepseek-v4-pro', owned_by: 'deepseek' },
  ],
});
assert.deepEqual(tokenInput, {
  account_ref: 'deepseek-primary',
  environment: 'production',
  resource_ref: 'model-catalog',
  signal: context.signal,
});
assert.equal(requestInput.origin, 'https://api.deepseek.com');
assert.equal(requestInput.method, 'GET');
assert.equal(requestInput.path, '/models');
assert.equal(requestInput.redirect, 'manual');
assert.equal(requestInput.headers.Authorization, 'Bearer temporary-deepseek-token');

assert.throws(() => createDeepSeekModelsListAdapter(), TypeError);
assert.throws(() => createDeepSeekModelsListAdapter({ request: async () => {} }), TypeError);
assert.throws(
  () =>
    createDeepSeekModelsListAdapter({
      request: async () => {},
      tokenProvider: async () => {},
      now: 1,
    }),
  TypeError,
);
for (const changed of [
  null,
  [],
  {},
  { resource_ref: 'other' },
  { ...parameters, url: 'https://attacker.example' },
]) {
  await assert.rejects(adapter(changed, context), expectCode('deepseek_invalid_request'));
}
for (const execution of [
  { ...context.execution, tool: 'deepseek.responses.create@1.0.0' },
  { ...context.execution, target: 'other' },
  { ...context.execution, environment: 'staging' },
]) {
  await assert.rejects(
    adapter(parameters, { ...context, execution }),
    expectCode('deepseek_execution_binding_mismatch'),
  );
}
await assert.rejects(
  adapter(parameters, { ...context, accountRef: '' }),
  expectCode('deepseek_account_unavailable'),
);

const withLease = (value) =>
  createDeepSeekModelsListAdapter({
    tokenProvider: async () => value,
    request: async () => ({ status: 200, body: responseBody() }),
    now: () => NOW,
  });
for (const invalid of [
  null,
  lease({ token: '' }),
  lease({ account_ref: 'other' }),
  lease({ environment: 'staging' }),
  lease({ resource_ref: 'other' }),
  lease({ expires_at: new Date(NOW - 1).toISOString() }),
  lease({ expires_at: new Date(NOW + 6 * 60_000).toISOString() }),
]) {
  await assert.rejects(
    withLease(invalid)(parameters, context),
    expectCode('deepseek_credential_unavailable'),
  );
}
await assert.rejects(
  createDeepSeekModelsListAdapter({
    tokenProvider: async () => {
      throw new Error('sk-canary-secret');
    },
    request: async () => ({ status: 200, body: responseBody() }),
    now: () => NOW,
  })(parameters, context),
  (error) =>
    expectCode('deepseek_credential_unavailable')(error) && !error.message.includes('canary'),
);

const withResponse = (response) =>
  createDeepSeekModelsListAdapter({
    tokenProvider: async () => lease(),
    request: async () => response,
    now: () => NOW,
  });
for (const [status, code] of [
  [302, 'deepseek_redirect_denied'],
  [401, 'deepseek_credential_rejected'],
  [403, 'deepseek_forbidden'],
  [429, 'deepseek_rate_limited'],
  [500, 'deepseek_upstream_error'],
]) {
  await assert.rejects(withResponse({ status, body: '{}' })(parameters, context), expectCode(code));
}
await assert.rejects(
  createDeepSeekModelsListAdapter({
    tokenProvider: async () => lease(),
    request: async () => {
      throw new Error('Bearer sk-canary-secret');
    },
    now: () => NOW,
  })(parameters, context),
  (error) => expectCode('deepseek_unavailable')(error) && !error.message.includes('canary'),
);
for (const body of [
  '{bad-json',
  responseBody({ object: 'model' }),
  responseBody({
    data: Array.from({ length: 101 }, (_, index) => ({
      id: `model-${index}`,
      object: 'model',
      owned_by: 'deepseek',
    })),
  }),
  responseBody({ data: [{ id: '../bad', object: 'model', owned_by: 'deepseek' }] }),
  responseBody({ data: [{ id: 'valid', object: 'other', owned_by: 'deepseek' }] }),
  responseBody({
    data: [
      { id: 'same', object: 'model', owned_by: 'deepseek' },
      { id: 'same', object: 'model', owned_by: 'deepseek' },
    ],
  }),
]) {
  await assert.rejects(
    withResponse({ status: 200, body })(parameters, context),
    expectCode('deepseek_invalid_response'),
  );
}

const registry = loadToolRegistry(resolve(import.meta.dirname, '../tools/registry.json'));
const events = [];
let calls = 0;
const taskBroker = new AutomationTaskBroker({
  toolRegistry: registry,
  authorize: async (operation) => ({
    allow:
      operation.provider === 'deepseek' &&
      operation.operationId === 'models.list' &&
      operation.accountRef === 'deepseek-primary' &&
      operation.environment === 'production' &&
      operation.typedParameters?.resource_ref === 'model-catalog',
    ttlMs: 60_000,
  }),
  approvalBroker: new ApprovalBroker(),
  executors: new Map([
    [
      'deepseek.models.list@1.0.0',
      createDeepSeekModelsListAdapter({
        tokenProvider: async () => lease(),
        request: async () => {
          calls += 1;
          return { status: 200, body: responseBody() };
        },
        now: () => NOW,
      }),
    ],
  ]),
  onEvent: (event) => events.push(event),
});
const actor = {
  name: 'model-catalog-agent',
  context: {
    via: 'workload_identity',
    client: { role: 'developer', principal_type: 'workload', security_profile: 'strict' },
  },
};
const task = await taskBroker.create(actor, {
  tool: 'deepseek.models.list',
  tool_version: '1.0.0',
  account_ref: 'deepseek-primary',
  environment: 'production',
  idempotency_key: 'deepseek-model-list-task-0001',
  parameters,
});
assert.equal(task.state, 'READY');
const completed = await taskBroker.run(actor, task.id);
assert.equal(completed.state, 'SUCCEEDED');
assert.equal(completed.result.models.length, 2);
assert.equal(calls, 1);
assert.deepEqual(
  taskBroker.eventsFor(actor, task.id).map((event) => event.state),
  ['REQUESTED', 'READY', 'EXECUTING', 'SUCCEEDED'],
);
for (const event of events) {
  const encoded = JSON.stringify(event);
  assert.equal(encoded.includes('temporary-deepseek-token'), false);
  assert.equal(encoded.includes('Authorization'), false);
}

assert.deepEqual(DEEPSEEK_MODELS_LIST_CONTRACT, {
  tool: 'deepseek.models.list@1.0.0',
  origin: 'https://api.deepseek.com',
  method: 'GET',
  path: '/models',
  resource_ref: 'model-catalog',
  maximum_response_bytes: 256 * 1024,
  maximum_token_ttl_seconds: 300,
  arbitrary_url: false,
  credential_export: false,
});

console.log(
  'deepseek models adapter: fixed endpoint, scoped lease, projection and task loop passed',
);
