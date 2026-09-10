import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { resolve } from 'node:path';
import { Readable } from 'node:stream';

import {
  createGitHubCommitsListAdapter,
  GITHUB_COMMITS_LIST_CONTRACT,
} from '../broker/adapters/github-commits-list.js';
import { createGitHubCommitsListExecutor } from '../broker/adapters/github-commits-list-executor.js';
import { ApprovalBroker } from '../broker/lib/approvals-v2.js';
import { AutomationTaskBroker } from '../broker/lib/automation-tasks.js';
import { loadToolRegistry } from '../broker/lib/tool-registry.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const NOW = 2_000_000_000_000;
const SHA = 'a'.repeat(40);
const SHA_256 = 'b'.repeat(64);
const expectCode = (code) => (error) => error instanceof V2Error && error.code === code;
const parameters = {
  resource_ref: 'tyj1987/broker',
  owner: 'tyj1987',
  repo: 'broker',
  sha: 'master',
  path: 'broker/server.js',
  author: 'octocat@example.test',
  committer: 'github-actions[bot]',
  since: '2026-01-01T00:00:00Z',
  until: '2026-09-10T23:59:59Z',
  per_page: 2,
  page: 3,
};
const context = {
  accountRef: 'github-primary',
  environment: 'production',
  execution: {
    tool: 'github.commits.list@1.0.0',
    target: 'tyj1987/broker',
    environment: 'production',
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
  {
    sha: SHA,
    commit: {
      message: 'must not leave the adapter',
      committer: { name: 'Example', email: 'private@example.test', date: '2026-09-10T12:00:00Z' },
      verification: { verified: true, signature: 'secret-signature', payload: 'secret-payload' },
    },
    author: { login: 'octocat' },
    committer: { login: 'github-actions[bot]' },
  },
  {
    sha: SHA_256,
    commit: {
      committer: { date: '2026-09-09T12:00:00Z' },
      verification: { verified: false },
    },
    author: null,
    committer: null,
  },
];

let requestInput;
let tokenInput;
const adapter = createGitHubCommitsListAdapter({
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
  commits: [
    {
      sha: SHA,
      committed_at: '2026-09-10T12:00:00Z',
      verified: true,
      author_login: 'octocat',
      committer_login: 'github-actions[bot]',
    },
    { sha: SHA_256, committed_at: '2026-09-09T12:00:00Z', verified: false },
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
    origin: 'https://api.github.com',
    method: 'GET',
    path: '/repos/tyj1987/broker/commits?per_page=2&page=3&sha=master&path=broker%2Fserver.js&author=octocat%40example.test&committer=github-actions%5Bbot%5D&since=2026-01-01T00%3A00%3A00Z&until=2026-09-10T23%3A59%3A59Z',
    redirect: 'manual',
    maxBytes: 1024 * 1024,
  },
);
assert.equal(requestInput.headers.Authorization, 'Bearer unit-token');
for (const excluded of [
  'unit-token',
  'message',
  'email',
  'signature',
  'payload',
  'private@example.test',
]) {
  assert.equal(JSON.stringify(result).includes(excluded), false);
}

const defaultResult = await createGitHubCommitsListAdapter({
  tokenProvider: async () => ({
    ...validLease(),
    expires_at: new Date(Date.now() + 60_000).toISOString(),
  }),
  request: async (input) => {
    assert.equal(input.path, '/repos/tyj1987/broker/commits?per_page=30&page=1');
    return { status: 200, body: [] };
  },
})({ resource_ref: 'tyj1987/broker', owner: 'tyj1987', repo: 'broker' }, context);
assert.deepEqual(defaultResult, { commits: [], page: 1, per_page: 30, has_more: false });

assert.throws(() => createGitHubCommitsListAdapter(), TypeError);
assert.throws(() => createGitHubCommitsListAdapter({ request: async () => {} }), TypeError);
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
  sha: ['', 'bad\nbranch', 'x'.repeat(256), 1],
  path: ['', 'bad\0path', 'x'.repeat(1025), 1],
  author: ['', 'bad\rauthor', 'x'.repeat(255), 1],
  committer: ['', 'bad\tcommitter', 'x'.repeat(255), 1],
  since: [
    '',
    '2026-09-10',
    '2026-02-30T00:00:00Z',
    '1969-12-31T23:59:59Z',
    '2100-01-01T00:00:00Z',
    1,
  ],
  until: ['', '2026-09-10T00:00:00+00:00', '2100-01-01T00:00:00Z', 1],
})) {
  for (const value of values) {
    await assert.rejects(
      adapter({ ...parameters, [field]: value }, context),
      expectCode('github_invalid_filter'),
    );
  }
}
await assert.rejects(
  adapter({ ...parameters, since: '2026-09-11T00:00:00Z', until: '2026-09-10T00:00:00Z' }, context),
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
  { ...context.execution, tool: 'github.repository.read@1.0.0' },
  { ...context.execution, target: 'other/repo' },
  { ...context.execution, environment: 'staging' },
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
  createGitHubCommitsListAdapter({
    now: () => NOW,
    tokenProvider: async () => lease,
    request: async () => ({ status: 200, body: validBody() }),
  });
for (const [lease, code] of [
  [null, 'github_credential_unavailable'],
  [{ ...validLease(), token: '' }, 'github_credential_unavailable'],
  [{ ...validLease(), token: 'x'.repeat(4097) }, 'github_credential_unavailable'],
  [{ ...validLease(), repository: 'other/repo' }, 'github_credential_scope_mismatch'],
  [{ ...validLease(), permissions: { metadata: 'read' } }, 'github_credential_scope_mismatch'],
  [
    { ...validLease(), permissions: { contents: 'read', issues: 'read' } },
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
  createGitHubCommitsListAdapter({
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
  createGitHubCommitsListAdapter({
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
  [409, 'github_conflict'],
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
  { ...validBody()[0], sha: 'bad' },
  { ...validBody()[0], commit: { ...validBody()[0].commit, committer: { date: 'bad' } } },
  {
    ...validBody()[0],
    commit: { ...validBody()[0].commit, committer: { date: '1969-12-31T23:59:59Z' } },
  },
  { ...validBody()[0], commit: { ...validBody()[0].commit, verification: { verified: 'true' } } },
  { ...validBody()[0], author: { login: 'bad\nlogin' } },
  { ...validBody()[0], committer: { login: 'x'.repeat(101) } },
]) {
  await assert.rejects(
    withResponse({ status: 200, body: [item] })({ ...parameters, per_page: 1 }, context),
    expectCode('github_invalid_response'),
  );
}
await assert.rejects(
  createGitHubCommitsListAdapter({
    now: () => NOW,
    tokenProvider: async () => validLease(),
    request: async () => {
      throw new Error('canary-network-detail');
    },
  })(parameters, context),
  (error) => expectCode('github_unavailable')(error) && !error.message.includes('canary'),
);
await assert.rejects(
  createGitHubCommitsListAdapter({
    now: () => NOW,
    tokenProvider: async () => validLease(),
    request: async () => {
      throw new V2Error('transport_policy_denied', 'safe', 403);
    },
  })(parameters, context),
  expectCode('transport_policy_denied'),
);

assert.deepEqual(GITHUB_COMMITS_LIST_CONTRACT, {
  tool: 'github.commits.list@1.0.0',
  origin: 'https://api.github.com',
  method: 'GET',
  path_template: '/repos/{owner}/{repo}/commits',
  api_version: '2026-03-10',
  maximum_response_bytes: 1024 * 1024,
  maximum_page_size: 100,
  credential_maximum_ttl_seconds: 3600,
  required_permission: 'contents:read',
  output_excludes: ['message', 'email', 'signature', 'payload'],
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
const executor = createGitHubCommitsListExecutor({
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
assert.equal(executorResult.commits.length, 2);
assert.equal(calls.length, 2);
assert.deepEqual(JSON.parse(calls[0].body), {
  repositories: ['broker'],
  permissions: { contents: 'read' },
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
      operation.operationId === 'commits.list' &&
      operation.accountRef === 'github-primary' &&
      operation.environment === 'production' &&
      operation.typedParameters?.resource_ref === 'tyj1987/broker',
    ttlMs: 60_000,
  }),
  approvalBroker: new ApprovalBroker(),
  executors: new Map([['github.commits.list@1.0.0', executor]]),
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
  tool: 'github.commits.list',
  tool_version: '1.0.0',
  account_ref: 'github-primary',
  environment: 'production',
  idempotency_key: 'github-commits-list-0001',
  parameters,
});
assert.equal(task.state, 'READY');
assert.equal(task.risk_level, 'LOW');
const completed = await taskBroker.run(actor, task.id);
assert.equal(completed.state, 'SUCCEEDED');
assert.equal(completed.result.commits.length, 2);
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
    tool: 'github.commits.list',
    tool_version: '1.0.0',
    account_ref: 'github-primary',
    environment: 'production',
    idempotency_key: 'github-commits-injection-0001',
    parameters: { ...parameters, url: 'https://example.invalid/steal' },
  }),
  expectCode('schema_mismatch'),
);
assert.equal(calls.length, 4, 'schema rejection occurs before token minting or transport');

console.log('github commits adapter: typed filters, least privilege and bounded task loop passed');
