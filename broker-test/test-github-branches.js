import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { resolve } from 'node:path';
import { Readable } from 'node:stream';

import {
  createGitHubBranchesListAdapter,
  GITHUB_BRANCHES_LIST_CONTRACT,
} from '../broker/adapters/github-branches-list.js';
import { createGitHubBranchesListExecutor } from '../broker/adapters/github-branches-list-executor.js';
import { ApprovalBroker } from '../broker/lib/approvals-v2.js';
import { AutomationTaskBroker } from '../broker/lib/automation-tasks.js';
import { loadToolRegistry } from '../broker/lib/tool-registry.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const NOW = 2_000_000_000_000;
const SHA = 'a'.repeat(40);
const EXECUTION_ID = '12345678-1234-4123-8123-123456789abc';
const REQUEST_BINDING = 'a'.repeat(43);
const expectCode = (code) => (error) => error instanceof V2Error && error.code === code;
const parameters = {
  resource_ref: 'tyj1987/broker',
  owner: 'tyj1987',
  repo: 'broker',
  protected: true,
  per_page: 2,
  page: 3,
};
const context = {
  accountRef: 'github-primary',
  environment: 'production',
  execution: {
    tool: 'github.branches.list@1.0.0',
    target: 'tyj1987/broker',
    environment: 'production',
    execution_id: EXECUTION_ID,
    request_binding: REQUEST_BINDING,
  },
  signal: new AbortController().signal,
};
const validLease = () => ({
  token: 'unit-token',
  repository: 'tyj1987/broker',
  expires_at: new Date(NOW + 60_000).toISOString(),
  permissions: { contents: 'read' },
});
const validBody = () => [
  { name: 'master', commit: { sha: SHA, url: 'not-returned' }, protected: true },
  { name: 'release/v1', commit: { sha: 'b'.repeat(64) }, protected: false },
];

let requestInput;
let tokenInput;
const adapter = createGitHubBranchesListAdapter({
  now: () => NOW,
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
  branches: [
    { name: 'master', sha: SHA, protected: true },
    { name: 'release/v1', sha: 'b'.repeat(64), protected: false },
  ],
  page: 3,
  per_page: 2,
  has_more: true,
});
assert.deepEqual(
  {
    account: tokenInput.account_ref,
    environment: tokenInput.environment,
    repository: tokenInput.repository,
    signal: tokenInput.signal,
    execution_id: tokenInput.execution_id,
    request_binding: tokenInput.request_binding,
    origin: requestInput.origin,
    method: requestInput.method,
    path: requestInput.path,
    redirect: requestInput.redirect,
    maxBytes: requestInput.max_response_bytes,
  },
  {
    account: 'github-primary',
    environment: 'production',
    repository: 'tyj1987/broker',
    signal: context.signal,
    execution_id: EXECUTION_ID,
    request_binding: REQUEST_BINDING,
    origin: 'https://api.github.com',
    method: 'GET',
    path: '/repos/tyj1987/broker/branches?per_page=2&page=3&protected=true',
    redirect: 'manual',
    maxBytes: 1024 * 1024,
  },
);
assert.equal(requestInput.headers.Authorization, 'Bearer unit-token');
assert.equal(JSON.stringify(result).includes('unit-token'), false);

const defaultResult = await createGitHubBranchesListAdapter({
  tokenProvider: async () => ({
    ...validLease(),
    expires_at: new Date(Date.now() + 60_000).toISOString(),
  }),
  request: async (input) => {
    assert.equal(input.path, '/repos/tyj1987/broker/branches?per_page=30&page=1');
    return { status: 200, body: [] };
  },
})({ resource_ref: 'tyj1987/broker', owner: 'tyj1987', repo: 'broker' }, context);
assert.deepEqual(defaultResult, { branches: [], page: 1, per_page: 30, has_more: false });

assert.throws(() => createGitHubBranchesListAdapter(), TypeError);
assert.throws(() => createGitHubBranchesListAdapter({ request: async () => {} }), TypeError);
for (const invalid of [
  { ...parameters, owner: '../admin' },
  { ...parameters, repo: '..' },
])
  await assert.rejects(adapter(invalid, context), expectCode('github_invalid_repository'));
await assert.rejects(
  adapter({ ...parameters, resource_ref: 'other/repo' }, context),
  expectCode('github_target_mismatch'),
);
await assert.rejects(
  adapter({ ...parameters, protected: 'true' }, context),
  expectCode('github_invalid_filter'),
);
for (const invalid of [0, 101, 1.5]) {
  await assert.rejects(
    adapter({ ...parameters, per_page: invalid }, context),
    expectCode('github_invalid_pagination'),
  );
}
for (const invalid of [0, 10_001, 1.5]) {
  await assert.rejects(
    adapter({ ...parameters, page: invalid }, context),
    expectCode('github_invalid_pagination'),
  );
}
await assert.rejects(
  adapter(parameters, {
    ...context,
    execution: { ...context.execution, tool: 'github.repository.read@1.0.0' },
  }),
  expectCode('github_execution_binding_mismatch'),
);
await assert.rejects(
  adapter(parameters, { ...context, execution: { ...context.execution, target: 'other/repo' } }),
  expectCode('github_execution_binding_mismatch'),
);
await assert.rejects(
  adapter(parameters, { ...context, execution: { ...context.execution, environment: 'staging' } }),
  expectCode('github_execution_binding_mismatch'),
);
for (const execution of [
  { ...context.execution, execution_id: 'wrong' },
  { ...context.execution, request_binding: 'wrong' },
]) {
  await assert.rejects(
    adapter(parameters, { ...context, execution }),
    expectCode('github_execution_binding_mismatch'),
  );
}
await assert.rejects(
  adapter(parameters, { ...context, accountRef: '' }),
  expectCode('github_account_unavailable'),
);

const withLease = (lease) =>
  createGitHubBranchesListAdapter({
    now: () => NOW,
    tokenProvider: async () => lease,
    request: async () => ({ status: 200, body: validBody() }),
  });
await assert.rejects(
  withLease(null)(parameters, context),
  expectCode('github_credential_unavailable'),
);
await assert.rejects(
  withLease({ ...validLease(), token: '' })(parameters, context),
  expectCode('github_credential_unavailable'),
);
await assert.rejects(
  withLease({ ...validLease(), repository: 'other/repo' })(parameters, context),
  expectCode('github_credential_scope_mismatch'),
);
await assert.rejects(
  withLease({ ...validLease(), permissions: { metadata: 'read' } })(parameters, context),
  expectCode('github_credential_scope_mismatch'),
);
await assert.rejects(
  withLease({ ...validLease(), expires_at: new Date(NOW).toISOString() })(parameters, context),
  expectCode('github_credential_expired'),
);
await assert.rejects(
  withLease({ ...validLease(), expires_at: new Date(NOW + 3_700_000).toISOString() })(
    parameters,
    context,
  ),
  expectCode('github_credential_expired'),
);
await assert.rejects(
  createGitHubBranchesListAdapter({
    now: () => NOW,
    tokenProvider: async () => {
      throw new Error('canary-token-detail');
    },
    request: async () => ({ status: 200, body: validBody() }),
  })(parameters, context),
  (error) =>
    expectCode('github_credential_unavailable')(error) && !error.message.includes('canary'),
);

const withResponse = (response) =>
  createGitHubBranchesListAdapter({
    now: () => NOW,
    tokenProvider: async () => validLease(),
    request: async () => response,
  });
assert.equal(
  (
    await withResponse({ status: 200, body: Buffer.from(JSON.stringify(validBody())) })(
      parameters,
      context,
    )
  ).branches.length,
  2,
);
for (const [status, code] of [
  [301, 'github_redirect_denied'],
  [401, 'github_credential_rejected'],
  [403, 'github_forbidden'],
  [404, 'github_not_found'],
  [429, 'github_upstream_error'],
])
  await assert.rejects(withResponse({ status, body: '{}' })(parameters, context), expectCode(code));
await assert.rejects(
  withResponse({ status: 200, body: 'not-json' })(parameters, context),
  expectCode('github_invalid_response'),
);
await assert.rejects(
  withResponse({ status: 200, body: 'x'.repeat(1024 * 1024 + 1) })(parameters, context),
  expectCode('github_response_too_large'),
);
await assert.rejects(
  withResponse({ status: 200, body: {} })(parameters, context),
  expectCode('github_invalid_response'),
);
await assert.rejects(
  withResponse({ status: 200, body: [...validBody(), validBody()[0]] })(parameters, context),
  expectCode('github_invalid_response'),
);
for (const branch of [
  { name: '', commit: { sha: SHA }, protected: true },
  { name: 'bad\nname', commit: { sha: SHA }, protected: true },
  { name: 'master', commit: { sha: 'bad' }, protected: true },
  { name: 'master', commit: { sha: SHA }, protected: 'true' },
])
  await assert.rejects(
    withResponse({ status: 200, body: [branch] })(parameters, context),
    expectCode('github_invalid_response'),
  );
await assert.rejects(
  createGitHubBranchesListAdapter({
    now: () => NOW,
    tokenProvider: async () => validLease(),
    request: async () => {
      throw new Error('canary-network-detail');
    },
  })(parameters, context),
  (error) => expectCode('github_unavailable')(error) && !error.message.includes('canary'),
);
await assert.rejects(
  createGitHubBranchesListAdapter({
    now: () => NOW,
    tokenProvider: async () => validLease(),
    request: async () => {
      throw new V2Error('transport_policy_denied', 'safe', 403);
    },
  })(parameters, context),
  expectCode('transport_policy_denied'),
);

assert.deepEqual(GITHUB_BRANCHES_LIST_CONTRACT, {
  tool: 'github.branches.list@1.0.0',
  origin: 'https://api.github.com',
  method: 'GET',
  path_template: '/repos/{owner}/{repo}/branches',
  api_version: '2026-03-10',
  maximum_response_bytes: 1024 * 1024,
  maximum_page_size: 100,
  credential_maximum_ttl_seconds: 3600,
  required_permission: 'contents:read',
});

const calls = [];
const requestImpl = (options, callback) => {
  const request = new EventEmitter();
  request.setTimeout = () => {};
  request.destroy = () => {};
  request.end = (body) => {
    calls.push({ options, body: body?.toString() });
    const tokenRequest = options.path.includes('/access_tokens');
    const responseBody = tokenRequest
      ? {
          token: 'short-lived-installation-token',
          expires_at: new Date(NOW + 60 * 60_000).toISOString(),
          permissions: { contents: 'read' },
          repositories: [{ full_name: 'tyj1987/broker' }],
        }
      : validBody();
    const response = Readable.from([JSON.stringify(responseBody)]);
    response.statusCode = tokenRequest ? 201 : 200;
    response.headers = { 'content-type': 'application/json' };
    queueMicrotask(() => callback(response));
  };
  return request;
};
const executor = createGitHubBranchesListExecutor({
  now: () => NOW,
  resolveHost: async () => [{ address: '93.184.216.34', family: 4 }],
  requestImpl,
  accountResolver: async ({ account_ref, environment }) => ({
    account_ref,
    environment,
    client_id: 'Iv1.integration-test',
    installation_id: 12345,
    repositories: ['tyj1987/broker'],
  }),
  signer: async () => Buffer.alloc(256, 9),
});
const executorResult = await executor(parameters, context);
assert.equal(executorResult.branches.length, 2);
assert.equal(calls.length, 2);
assert.deepEqual(JSON.parse(calls[0].body), {
  repositories: ['broker'],
  permissions: { contents: 'read' },
});
assert.equal(
  calls[1].options.path,
  '/repos/tyj1987/broker/branches?per_page=2&page=3&protected=true',
);
assert.equal(calls[1].options.headers.authorization, 'Bearer short-lived-installation-token');
assert.equal(JSON.stringify(executorResult).includes('short-lived-installation-token'), false);

const registry = loadToolRegistry(resolve(import.meta.dirname, '../tools/registry.json'));
const taskEvents = [];
const taskBroker = new AutomationTaskBroker({
  toolRegistry: registry,
  authorize: async (operation) => ({
    allow:
      operation.provider === 'github' &&
      operation.operationId === 'branches.list' &&
      operation.accountRef === 'github-primary' &&
      operation.environment === 'production' &&
      operation.typedParameters?.resource_ref === 'tyj1987/broker',
    ttlMs: 60_000,
  }),
  approvalBroker: new ApprovalBroker(),
  executors: new Map([['github.branches.list@1.0.0', executor]]),
  onEvent: (event) => taskEvents.push(event),
});
const actor = {
  name: 'github-read-agent',
  context: {
    via: 'workload_identity',
    client: { role: 'developer', principal_type: 'workload', security_profile: 'strict' },
  },
};
const task = await taskBroker.create(actor, {
  tool: 'github.branches.list',
  tool_version: '1.0.0',
  account_ref: 'github-primary',
  environment: 'production',
  idempotency_key: 'github-branches-list-0001',
  parameters,
});
assert.equal(task.state, 'READY');
assert.equal(task.risk_level, 'LOW');
const completed = await taskBroker.run(actor, task.id);
assert.equal(completed.state, 'SUCCEEDED');
assert.equal(completed.result.branches.length, 2);
assert.deepEqual(
  taskBroker.eventsFor(actor, task.id).map((event) => event.state),
  ['REQUESTED', 'READY', 'EXECUTING', 'SUCCEEDED'],
);
assert.ok(
  taskEvents.every((event) => !JSON.stringify(event).includes('short-lived-installation-token')),
);
await assert.rejects(taskBroker.run(actor, task.id), expectCode('invalid_state'));
assert.equal(calls.length, 4, 'a terminal task cannot replay its GitHub capability');
await assert.rejects(
  taskBroker.create(actor, {
    tool: 'github.branches.list',
    tool_version: '1.0.0',
    account_ref: 'github-primary',
    environment: 'production',
    idempotency_key: 'github-branches-injection-0001',
    parameters: { ...parameters, url: 'https://example.invalid/steal' },
  }),
  expectCode('schema_mismatch'),
);
assert.equal(calls.length, 4, 'schema rejection occurs before token minting or transport');

console.log(
  'github branches adapter: exact permission, target, pagination and projection checks passed',
);
