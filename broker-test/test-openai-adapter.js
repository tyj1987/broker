import assert from 'node:assert/strict';
import { resolve } from 'node:path';

import {
  createOpenAIModelsListAdapter,
  OPENAI_MODELS_LIST_CONTRACT,
} from '../broker/adapters/openai-models-list.js';
import { ApprovalBroker } from '../broker/lib/approvals-v2.js';
import { AutomationTaskBroker } from '../broker/lib/automation-tasks.js';
import { V2Error } from '../broker/lib/operations-v2.js';
import { loadToolRegistry } from '../broker/lib/tool-registry.js';

const NOW = Date.parse('2026-09-11T07:00:00Z');
const PROJECT = 'proj_52trzProduction';
const EXECUTION_ID = '12345678-1234-4123-8123-123456789abc';
const REQUEST_BINDING = 'a'.repeat(43);
const parameters = { resource_ref: PROJECT };
const context = {
  accountRef: 'openai-52trz',
  environment: 'production',
  execution: {
    tool: 'openai.models.list@1.0.0',
    target: PROJECT,
    environment: 'production',
    execution_id: EXECUTION_ID,
    request_binding: REQUEST_BINDING,
  },
  signal: new AbortController().signal,
};
const lease = (change = {}) => ({
  token: 'temporary-openai-access-token',
  expires_at: new Date(NOW + 60_000).toISOString(),
  account_ref: context.accountRef,
  environment: context.environment,
  resource_ref: PROJECT,
  ...change,
});
const responseBody = (change = {}) => ({
  object: 'list',
  data: [
    { id: 'gpt-6-astra', object: 'model', created: 1, owned_by: 'openai' },
    { id: 'gpt-5.6-terra', object: 'model', created: 2, owned_by: 'openai' },
  ],
  ...change,
});
const expectCode = (code) => (error) => error instanceof V2Error && error.code === code;

let tokenInput;
let requestInput;
const adapter = createOpenAIModelsListAdapter({
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
  models: [{ id: 'gpt-6-astra' }, { id: 'gpt-5.6-terra' }],
});
assert.deepEqual(tokenInput, {
  account_ref: 'openai-52trz',
  environment: 'production',
  resource_ref: PROJECT,
  execution_id: EXECUTION_ID,
  request_binding: REQUEST_BINDING,
  signal: context.signal,
});
assert.equal(requestInput.origin, 'https://api.openai.com');
assert.equal(requestInput.path, '/v1/models');
assert.equal(requestInput.method, 'GET');
assert.equal(requestInput.redirect, 'manual');
assert.equal(requestInput.headers.Authorization, 'Bearer temporary-openai-access-token');
assert.equal(JSON.stringify(await adapter(parameters, context)).includes('owned_by'), false);

assert.throws(() => createOpenAIModelsListAdapter(), TypeError);
assert.throws(() => createOpenAIModelsListAdapter({ request: async () => {} }), TypeError);
assert.throws(
  () =>
    createOpenAIModelsListAdapter({
      request: async () => {},
      tokenProvider: async () => {},
      now: 1,
    }),
  TypeError,
);
for (const changed of [null, [], {}, { resource_ref: '..' }, { ...parameters, url: 'https://x' }]) {
  await assert.rejects(adapter(changed, context), expectCode('openai_invalid_request'));
}
for (const execution of [
  { ...context.execution, tool: 'openai.responses.create@1.0.0' },
  { ...context.execution, target: 'proj_other' },
  { ...context.execution, environment: 'staging' },
  { ...context.execution, execution_id: 'wrong' },
  { ...context.execution, request_binding: 'wrong' },
]) {
  await assert.rejects(
    adapter(parameters, { ...context, execution }),
    expectCode('openai_execution_binding_mismatch'),
  );
}
await assert.rejects(
  adapter(parameters, { ...context, accountRef: '' }),
  expectCode('openai_account_unavailable'),
);

const withLease = (value) =>
  createOpenAIModelsListAdapter({
    tokenProvider: async () => value,
    request: async () => ({ status: 200, body: responseBody() }),
    now: () => NOW,
  });
for (const invalid of [
  null,
  lease({ token: '' }),
  lease({ account_ref: 'other' }),
  lease({ environment: 'staging' }),
  lease({ resource_ref: 'proj_other' }),
  lease({ expires_at: new Date(NOW - 1).toISOString() }),
  lease({ expires_at: new Date(NOW + 6 * 60_000).toISOString() }),
]) {
  await assert.rejects(
    withLease(invalid)(parameters, context),
    expectCode('openai_credential_unavailable'),
  );
}
await assert.rejects(
  createOpenAIModelsListAdapter({
    tokenProvider: async () => {
      throw new Error('sk-canary-secret');
    },
    request: async () => ({ status: 200, body: responseBody() }),
    now: () => NOW,
  })(parameters, context),
  (error) =>
    expectCode('openai_credential_unavailable')(error) && !error.message.includes('canary'),
);

const withResponse = (response) =>
  createOpenAIModelsListAdapter({
    tokenProvider: async () => lease(),
    request: async () => response,
    now: () => NOW,
  });
for (const [status, code] of [
  [302, 'openai_redirect_denied'],
  [401, 'openai_credential_rejected'],
  [403, 'openai_forbidden'],
  [429, 'openai_rate_limited'],
  [500, 'openai_upstream_error'],
]) {
  await assert.rejects(withResponse({ status, body: '{}' })(parameters, context), expectCode(code));
}
for (const body of [
  '{bad-json',
  responseBody({ object: 'model' }),
  responseBody({
    data: Array.from({ length: 1001 }, (_, index) => ({ id: `model-${index}`, object: 'model' })),
  }),
  responseBody({ data: [{ id: '../bad', object: 'model' }] }),
  responseBody({ data: [{ id: 'valid', object: 'other' }] }),
  responseBody({
    data: [
      { id: 'same', object: 'model' },
      { id: 'same', object: 'model' },
    ],
  }),
]) {
  await assert.rejects(
    withResponse({ status: 200, body })(parameters, context),
    expectCode('openai_invalid_response'),
  );
}
await assert.rejects(
  createOpenAIModelsListAdapter({
    tokenProvider: async () => lease(),
    request: async () => {
      throw new Error('Bearer sk-canary-secret');
    },
    now: () => NOW,
  })(parameters, context),
  (error) => expectCode('openai_unavailable')(error) && !error.message.includes('canary'),
);

const registry = loadToolRegistry(resolve(import.meta.dirname, '../tools/registry.json'));
let calls = 0;
const taskBroker = new AutomationTaskBroker({
  toolRegistry: registry,
  authorize: async (operation) => ({
    allow: operation.typedParameters?.resource_ref === PROJECT,
    ttlMs: 60_000,
  }),
  approvalBroker: new ApprovalBroker(),
  executors: new Map([
    [
      'openai.models.list@1.0.0',
      createOpenAIModelsListAdapter({
        tokenProvider: async () => lease(),
        request: async () => {
          calls += 1;
          return { status: 200, body: responseBody() };
        },
        now: () => NOW,
      }),
    ],
  ]),
});
const actor = {
  name: 'openai-catalog-agent',
  context: {
    via: 'workload_identity',
    client: { role: 'developer', principal_type: 'workload', security_profile: 'strict' },
  },
};
const task = await taskBroker.create(actor, {
  tool: 'openai.models.list',
  tool_version: '1.0.0',
  account_ref: 'openai-52trz',
  environment: 'production',
  idempotency_key: 'openai-model-list-task-0001',
  parameters,
});
assert.equal(task.state, 'READY');
const completed = await taskBroker.run(actor, task.id);
assert.equal(completed.state, 'SUCCEEDED');
assert.equal(calls, 1);
assert.equal(JSON.stringify(completed).includes('temporary-openai-access-token'), false);

assert.deepEqual(OPENAI_MODELS_LIST_CONTRACT, {
  tool: 'openai.models.list@1.0.0',
  origin: 'https://api.openai.com',
  method: 'GET',
  path: '/v1/models',
  maximum_response_bytes: 2 * 1024 * 1024,
  maximum_models: 1000,
  maximum_token_ttl_seconds: 300,
  releases_model_owner: false,
  arbitrary_url: false,
  credential_export: false,
});

console.log(
  'openai models adapter: project binding, scoped lease, projection and task loop passed',
);
