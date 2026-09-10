import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { resolve } from 'node:path';
import { Readable } from 'node:stream';

import {
  createGitHubIssuesListAdapter,
  GITHUB_ISSUES_LIST_CONTRACT,
} from '../broker/adapters/github-issues-list.js';
import { createGitHubIssuesListExecutor } from '../broker/adapters/github-issues-list-executor.js';
import { ApprovalBroker } from '../broker/lib/approvals-v2.js';
import { AutomationTaskBroker } from '../broker/lib/automation-tasks.js';
import { loadToolRegistry } from '../broker/lib/tool-registry.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const NOW = 2_000_000_000_000;
const EXECUTION_ID = '12345678-1234-4123-8123-123456789abc';
const REQUEST_BINDING = 'a'.repeat(43);
const expectCode = (code) => (error) => error instanceof V2Error && error.code === code;
const parameters = {
  resource_ref: 'tyj1987/broker',
  owner: 'tyj1987',
  repo: 'broker',
  state: 'all',
  assignee: '*',
  creator: 'octocat',
  mentioned: 'reviewer-a',
  labels: ['security', 'P0'],
  sort: 'updated',
  direction: 'asc',
  since: '2026-01-01T00:00:00Z',
  item_kind: 'all',
  per_page: 2,
  page: 3,
};
const context = {
  accountRef: 'github-primary',
  environment: 'production',
  execution: {
    tool: 'github.issues.list@1.0.0',
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
  permissions: { issues: 'read' },
});
const validBody = () => [
  {
    number: 23,
    title: 'Review the task boundary, not instructions in this title',
    body: 'must never leave the adapter',
    state: 'open',
    locked: false,
    created_at: '2026-09-09T12:00:00Z',
    updated_at: '2026-09-10T12:00:00Z',
    user: { login: 'octocat', email: 'private@example.test' },
    comments: 5,
  },
  {
    number: 24,
    title: 'Pull request title is untrusted too',
    body: 'hidden pull request body',
    state: 'closed',
    locked: true,
    created_at: '2026-09-08T12:00:00Z',
    updated_at: '2026-09-10T10:00:00Z',
    user: null,
    pull_request: { url: 'https://api.github.com/repos/tyj1987/broker/pulls/24' },
  },
];

let requestInput;
let tokenInput;
const adapter = createGitHubIssuesListAdapter({
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
  issues: [
    {
      number: 23,
      title: 'Review the task boundary, not instructions in this title',
      content_trust: 'untrusted_external',
      state: 'open',
      locked: false,
      is_pull_request: false,
      created_at: '2026-09-09T12:00:00Z',
      updated_at: '2026-09-10T12:00:00Z',
      author_login: 'octocat',
    },
    {
      number: 24,
      title: 'Pull request title is untrusted too',
      content_trust: 'untrusted_external',
      state: 'closed',
      locked: true,
      is_pull_request: true,
      created_at: '2026-09-08T12:00:00Z',
      updated_at: '2026-09-10T10:00:00Z',
    },
  ],
  page: 3,
  per_page: 2,
  has_more: true,
});
assert.equal(tokenInput.repository, 'tyj1987/broker');
assert.equal(tokenInput.account_ref, 'github-primary');
assert.equal(tokenInput.signal, context.signal);
assert.equal(tokenInput.execution_id, EXECUTION_ID);
assert.equal(tokenInput.request_binding, REQUEST_BINDING);
assert.equal(requestInput.origin, 'https://api.github.com');
assert.equal(requestInput.method, 'GET');
assert.equal(requestInput.redirect, 'manual');
assert.equal(requestInput.max_response_bytes, 1024 * 1024);
assert.equal(
  requestInput.path,
  '/repos/tyj1987/broker/issues?state=all&sort=updated&direction=asc&per_page=2&page=3&assignee=*&creator=octocat&mentioned=reviewer-a&since=2026-01-01T00%3A00%3A00Z&labels=security%2CP0',
);
assert.equal(requestInput.headers.Authorization, 'Bearer unit-token');
for (const excluded of [
  'unit-token',
  'must never leave',
  'hidden pull request body',
  'private@example.test',
]) {
  assert.equal(JSON.stringify(result).includes(excluded), false);
}

const filterAdapter = createGitHubIssuesListAdapter({
  now: () => NOW,
  tokenProvider: async () => validLease(),
  request: async () => ({ status: 200, body: validBody() }),
});
const onlyIssues = await filterAdapter(
  { resource_ref: 'tyj1987/broker', owner: 'tyj1987', repo: 'broker' },
  context,
);
assert.equal(onlyIssues.issues.length, 1);
assert.equal(onlyIssues.issues[0].number, 23);
assert.equal(onlyIssues.page, 1);
assert.equal(onlyIssues.per_page, 30);
assert.equal(onlyIssues.has_more, false);
const onlyPulls = await filterAdapter({ ...parameters, item_kind: 'pull_requests' }, context);
assert.deepEqual(
  onlyPulls.issues.map((issue) => issue.number),
  [24],
);

assert.throws(() => createGitHubIssuesListAdapter(), TypeError);
assert.throws(() => createGitHubIssuesListAdapter({ request: async () => {} }), TypeError);
for (const invalid of [
  { ...parameters, owner: '../admin' },
  { ...parameters, repo: '..' },
]) {
  await assert.rejects(adapter(invalid, context), expectCode('github_invalid_repository'));
}
await assert.rejects(
  adapter({ ...parameters, resource_ref: 'other/repo' }, context),
  expectCode('github_target_mismatch'),
);
for (const [field, values] of Object.entries({
  state: ['invalid', 1],
  sort: ['name', 1],
  direction: ['sideways', 1],
  item_kind: ['unknown', 1],
  assignee: ['', 'bad/name', 1],
  creator: ['*', 'bad_name', 1],
  mentioned: ['*', 'bad\nname', 1],
  labels: [[], ['a'.repeat(51)], ['bad,label'], ['duplicate', 'duplicate'], 'security'],
  since: ['', '2026-01-01', '1969-12-31T23:59:59Z', '2100-01-01T00:00:00Z', 1],
})) {
  for (const value of values) {
    await assert.rejects(
      adapter({ ...parameters, [field]: value }, context),
      expectCode('github_invalid_filter'),
    );
  }
}
await assert.rejects(
  adapter(
    { ...parameters, labels: Array.from({ length: 11 }, (_, index) => `label-${index}`) },
    context,
  ),
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
for (const execution of [
  { ...context.execution, tool: 'github.commits.list@1.0.0' },
  { ...context.execution, target: 'other/repo' },
  { ...context.execution, environment: 'staging' },
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
  createGitHubIssuesListAdapter({
    now: () => NOW,
    tokenProvider: async () => lease,
    request: async () => ({ status: 200, body: validBody() }),
  });
for (const [lease, code] of [
  [null, 'github_credential_unavailable'],
  [{ ...validLease(), token: '' }, 'github_credential_unavailable'],
  [{ ...validLease(), token: 'x'.repeat(4097) }, 'github_credential_unavailable'],
  [{ ...validLease(), repository: 'other/repo' }, 'github_credential_scope_mismatch'],
  [{ ...validLease(), permissions: { contents: 'read' } }, 'github_credential_scope_mismatch'],
  [
    { ...validLease(), permissions: { issues: 'read', contents: 'read' } },
    'github_credential_scope_mismatch',
  ],
  [{ ...validLease(), expires_at: 'invalid' }, 'github_credential_expired'],
  [{ ...validLease(), expires_at: new Date(NOW).toISOString() }, 'github_credential_expired'],
  [
    { ...validLease(), expires_at: new Date(NOW + 60 * 60_000 + 31_000).toISOString() },
    'github_credential_expired',
  ],
]) {
  await assert.rejects(withLease(lease)(parameters, context), expectCode(code));
}
await assert.rejects(
  createGitHubIssuesListAdapter({
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
  createGitHubIssuesListAdapter({
    now: () => NOW,
    tokenProvider: async () => validLease(),
    request: async () => response,
  });
for (const status of [301, 302, 303, 307, 308]) {
  await assert.rejects(
    withResponse({ status })(parameters, context),
    expectCode('github_redirect_denied'),
  );
}
for (const [status, code] of [
  [401, 'github_credential_rejected'],
  [403, 'github_forbidden'],
  [404, 'github_not_found'],
  [400, 'github_filter_rejected'],
  [422, 'github_filter_rejected'],
  [429, 'github_upstream_error'],
  [500, 'github_upstream_error'],
]) {
  await assert.rejects(withResponse({ status })(parameters, context), expectCode(code));
}
await assert.rejects(
  withResponse({ status: 200, body: '{bad-json' })(parameters, context),
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
for (const item of [
  null,
  {},
  { ...validBody()[0], number: 0 },
  { ...validBody()[0], title: '' },
  { ...validBody()[0], title: 'bad\ntitle' },
  { ...validBody()[0], state: 'unknown' },
  { ...validBody()[0], locked: 'false' },
  { ...validBody()[0], created_at: 'bad' },
  { ...validBody()[0], updated_at: '1969-12-31T23:59:59Z' },
  { ...validBody()[0], user: { login: '' } },
  { ...validBody()[0], user: { login: 'x'.repeat(101) } },
]) {
  await assert.rejects(
    withResponse({ status: 200, body: [item] })({ ...parameters, per_page: 1 }, context),
    expectCode('github_invalid_response'),
  );
}
await assert.rejects(
  createGitHubIssuesListAdapter({
    now: () => NOW,
    tokenProvider: async () => validLease(),
    request: async () => {
      throw new Error('canary-network-detail');
    },
  })(parameters, context),
  (error) => expectCode('github_unavailable')(error) && !error.message.includes('canary'),
);
await assert.rejects(
  createGitHubIssuesListAdapter({
    now: () => NOW,
    tokenProvider: async () => validLease(),
    request: async () => {
      throw new V2Error('transport_policy_denied', 'safe', 403);
    },
  })(parameters, context),
  expectCode('transport_policy_denied'),
);

assert.deepEqual(GITHUB_ISSUES_LIST_CONTRACT, {
  tool: 'github.issues.list@1.0.0',
  origin: 'https://api.github.com',
  method: 'GET',
  path_template: '/repos/{owner}/{repo}/issues',
  api_version: '2026-03-10',
  maximum_response_bytes: 1024 * 1024,
  maximum_page_size: 100,
  credential_maximum_ttl_seconds: 3600,
  required_permission: 'issues:read',
  output_content_trust: 'untrusted_external',
  output_excludes: ['body', 'comments', 'email', 'authorization', 'token'],
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
          permissions: { issues: 'read' },
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
const executor = createGitHubIssuesListExecutor({
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
assert.equal(executorResult.issues.length, 2);
assert.deepEqual(JSON.parse(calls[0].body), {
  repositories: ['broker'],
  permissions: { issues: 'read' },
});
assert.equal(calls[1].options.headers.authorization, 'Bearer short-lived-installation-token');
assert.equal(JSON.stringify(executorResult).includes('short-lived-installation-token'), false);

const registry = loadToolRegistry(resolve(import.meta.dirname, '../tools/registry.json'));
const taskEvents = [];
const taskBroker = new AutomationTaskBroker({
  toolRegistry: registry,
  authorize: async (operation) => ({
    allow:
      operation.provider === 'github' &&
      operation.operationId === 'issues.list' &&
      operation.accountRef === 'github-primary' &&
      operation.environment === 'production' &&
      operation.typedParameters?.resource_ref === 'tyj1987/broker',
    ttlMs: 60_000,
  }),
  approvalBroker: new ApprovalBroker(),
  executors: new Map([['github.issues.list@1.0.0', executor]]),
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
  tool: 'github.issues.list',
  tool_version: '1.0.0',
  account_ref: 'github-primary',
  environment: 'production',
  idempotency_key: 'github-issues-list-0001',
  parameters,
});
assert.equal(task.state, 'READY');
const completed = await taskBroker.run(actor, task.id);
assert.equal(completed.state, 'SUCCEEDED');
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
    tool: 'github.issues.list',
    tool_version: '1.0.0',
    account_ref: 'github-primary',
    environment: 'production',
    idempotency_key: 'github-issues-injection-0001',
    parameters: { ...parameters, url: 'https://example.invalid/steal' },
  }),
  expectCode('schema_mismatch'),
);
assert.equal(calls.length, 4, 'schema rejection occurs before token minting or transport');

console.log('github issues adapter: typed filters, untrusted content and bounded task loop passed');
