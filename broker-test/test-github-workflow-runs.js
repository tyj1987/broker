import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { resolve } from 'node:path';
import { Readable } from 'node:stream';

import {
  createGitHubWorkflowRunsListAdapter,
  GITHUB_WORKFLOW_RUNS_LIST_CONTRACT,
} from '../broker/adapters/github-workflow-runs-list.js';
import { createGitHubWorkflowRunsListExecutor } from '../broker/adapters/github-workflow-runs-list-executor.js';
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
  actor: 'octocat',
  branch: 'master',
  event: 'workflow_dispatch',
  status: 'success',
  head_sha: SHA,
  exclude_pull_requests: true,
  check_suite_id: 98765,
  per_page: 2,
  page: 3,
};
const context = {
  accountRef: 'github-primary',
  environment: 'production',
  execution: {
    tool: 'github.workflow-runs.list@1.0.0',
    target: 'tyj1987/broker',
    environment: 'production',
    execution_id: EXECUTION_ID,
    request_binding: REQUEST_BINDING,
  },
  signal: new AbortController().signal,
};
const validLease = () => ({
  token: 'unit-workflow-token',
  repository: 'tyj1987/broker',
  expires_at: new Date(NOW + 60_000).toISOString(),
  permissions: { actions: 'read' },
});
const validBody = () => ({
  total_count: 7,
  workflow_runs: [
    {
      id: 1001,
      name: 'CI output is untrusted external content',
      display_title: 'must not be projected',
      event: 'workflow_dispatch',
      status: 'completed',
      conclusion: 'success',
      head_branch: 'master',
      head_sha: SHA,
      run_number: 17,
      run_attempt: 1,
      created_at: '2026-09-09T12:00:00Z',
      updated_at: '2026-09-09T12:10:00Z',
      pull_requests: [{ number: 24, title: 'hidden' }],
      jobs_url: 'https://api.github.com/hidden/jobs',
      logs_url: 'https://api.github.com/hidden/logs',
    },
    {
      id: 1002,
      name: 'Deploy ECS',
      event: 'push',
      status: 'in_progress',
      conclusion: null,
      head_branch: null,
      head_sha: 'b'.repeat(40),
      run_number: 18,
      run_attempt: 2,
      created_at: '2026-09-10T12:00:00Z',
      updated_at: '2026-09-10T12:01:00Z',
    },
  ],
});

let requestInput;
let tokenInput;
const adapter = createGitHubWorkflowRunsListAdapter({
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
  workflow_runs: [
    {
      id: 1001,
      name: 'CI output is untrusted external content',
      content_trust: 'untrusted_external',
      event: 'workflow_dispatch',
      status: 'completed',
      conclusion: 'success',
      head_branch: 'master',
      head_sha: SHA,
      run_number: 17,
      run_attempt: 1,
      created_at: '2026-09-09T12:00:00Z',
      updated_at: '2026-09-09T12:10:00Z',
    },
    {
      id: 1002,
      name: 'Deploy ECS',
      content_trust: 'untrusted_external',
      event: 'push',
      status: 'in_progress',
      conclusion: null,
      head_branch: null,
      head_sha: 'b'.repeat(40),
      run_number: 18,
      run_attempt: 2,
      created_at: '2026-09-10T12:00:00Z',
      updated_at: '2026-09-10T12:01:00Z',
    },
  ],
  total_count: 7,
  page: 3,
  per_page: 2,
  has_more: true,
});
assert.equal(tokenInput.repository, 'tyj1987/broker');
assert.equal(tokenInput.signal, context.signal);
assert.equal(tokenInput.execution_id, EXECUTION_ID);
assert.equal(tokenInput.request_binding, REQUEST_BINDING);
assert.equal(requestInput.origin, 'https://api.github.com');
assert.equal(requestInput.method, 'GET');
assert.equal(requestInput.redirect, 'manual');
assert.equal(requestInput.max_response_bytes, 1024 * 1024);
assert.equal(requestInput.headers['X-GitHub-Api-Version'], '2026-03-10');
assert.equal(
  requestInput.path,
  `/repos/tyj1987/broker/actions/runs?per_page=2&page=3&actor=octocat&branch=master&event=workflow_dispatch&status=success&head_sha=${SHA}&exclude_pull_requests=true&check_suite_id=98765`,
);
for (const excluded of [
  'unit-workflow-token',
  'must not be projected',
  'hidden/jobs',
  'hidden/logs',
  'pull_requests',
]) {
  assert.equal(JSON.stringify(result).includes(excluded), false);
}

assert.throws(() => createGitHubWorkflowRunsListAdapter(), TypeError);
assert.throws(() => createGitHubWorkflowRunsListAdapter({ request: async () => {} }), TypeError);
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
  actor: ['', 'bad_name', 1],
  branch: ['', 'bad\nbranch', 1],
  event: ['', 'pull-request', 1],
  status: ['', 'unknown', 1],
  head_sha: ['', 'abc', 1],
  exclude_pull_requests: ['true', 1],
  check_suite_id: [0, 1.5, '1'],
})) {
  for (const value of values) {
    await assert.rejects(
      adapter({ ...parameters, [field]: value }, context),
      expectCode('github_invalid_filter'),
    );
  }
}
for (const invalid of [0, 101, 1.5]) {
  await assert.rejects(
    adapter({ ...parameters, per_page: invalid }, context),
    expectCode('github_invalid_pagination'),
  );
}
for (const execution of [
  { ...context.execution, tool: 'github.issues.list@1.0.0' },
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
  createGitHubWorkflowRunsListAdapter({
    now: () => NOW,
    tokenProvider: async () => lease,
    request: async () => ({ status: 200, body: validBody() }),
  });
for (const [lease, code] of [
  [null, 'github_credential_unavailable'],
  [{ ...validLease(), token: '' }, 'github_credential_unavailable'],
  [{ ...validLease(), repository: 'other/repo' }, 'github_credential_scope_mismatch'],
  [{ ...validLease(), permissions: { contents: 'read' } }, 'github_credential_scope_mismatch'],
  [
    { ...validLease(), permissions: { actions: 'read', contents: 'read' } },
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
  createGitHubWorkflowRunsListAdapter({
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
  createGitHubWorkflowRunsListAdapter({
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
for (const body of [
  '{bad-json',
  'x'.repeat(1024 * 1024 + 1),
  {},
  { total_count: -1, workflow_runs: [] },
  { total_count: 1, workflow_runs: [null] },
  { total_count: 1, workflow_runs: [{ ...validBody().workflow_runs[0], status: 'unknown' }] },
  { total_count: 1, workflow_runs: [{ ...validBody().workflow_runs[0], name: 'bad\nname' }] },
  { total_count: 1, workflow_runs: [{ ...validBody().workflow_runs[0], conclusion: 'unknown' }] },
  { total_count: 1, workflow_runs: [{ ...validBody().workflow_runs[0], head_branch: '' }] },
  { total_count: 1, workflow_runs: [{ ...validBody().workflow_runs[0], created_at: 'bad' }] },
]) {
  await assert.rejects(
    withResponse({ status: 200, body })({ ...parameters, per_page: 1 }, context),
    expectCode(
      typeof body === 'string' && body.length > 1024 * 1024
        ? 'github_response_too_large'
        : 'github_invalid_response',
    ),
  );
}
await assert.rejects(
  createGitHubWorkflowRunsListAdapter({
    now: () => NOW,
    tokenProvider: async () => validLease(),
    request: async () => {
      throw new Error('canary-network');
    },
  })(parameters, context),
  (error) => expectCode('github_unavailable')(error) && !error.message.includes('canary'),
);
await assert.rejects(
  createGitHubWorkflowRunsListAdapter({
    now: () => NOW,
    tokenProvider: async () => validLease(),
    request: async () => {
      throw new V2Error('transport_policy_denied', 'safe', 403);
    },
  })(parameters, context),
  expectCode('transport_policy_denied'),
);

assert.deepEqual(GITHUB_WORKFLOW_RUNS_LIST_CONTRACT, {
  tool: 'github.workflow-runs.list@1.0.0',
  origin: 'https://api.github.com',
  method: 'GET',
  path_template: '/repos/{owner}/{repo}/actions/runs',
  api_version: '2026-03-10',
  maximum_response_bytes: 1024 * 1024,
  maximum_page_size: 100,
  credential_maximum_ttl_seconds: 3600,
  required_permission: 'actions:read',
  output_content_trust: 'untrusted_external',
  output_excludes: ['pull_requests', 'jobs', 'logs', 'artifacts', 'authorization', 'token'],
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
          token: 'short-lived-workflow-token',
          expires_at: new Date(NOW + 60 * 60_000).toISOString(),
          permissions: { actions: 'read' },
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
const executor = createGitHubWorkflowRunsListExecutor({
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
assert.equal(executorResult.workflow_runs.length, 2);
assert.deepEqual(JSON.parse(calls[0].body), {
  repositories: ['broker'],
  permissions: { actions: 'read' },
});
assert.equal(JSON.stringify(executorResult).includes('short-lived-workflow-token'), false);

const registry = loadToolRegistry(resolve(import.meta.dirname, '../tools/registry.json'));
const taskEvents = [];
const taskBroker = new AutomationTaskBroker({
  toolRegistry: registry,
  authorize: async (operation) => ({
    allow:
      operation.provider === 'github' &&
      operation.operationId === 'workflow_runs.list' &&
      operation.accountRef === 'github-primary' &&
      operation.environment === 'production' &&
      operation.typedParameters?.resource_ref === 'tyj1987/broker',
    ttlMs: 60_000,
  }),
  approvalBroker: new ApprovalBroker(),
  executors: new Map([['github.workflow-runs.list@1.0.0', executor]]),
  onEvent: (event) => taskEvents.push(event),
});
const actor = {
  name: 'ci-observer',
  context: {
    via: 'workload_identity',
    client: { role: 'developer', principal_type: 'workload', security_profile: 'strict' },
  },
};
const task = await taskBroker.create(actor, {
  tool: 'github.workflow-runs.list',
  tool_version: '1.0.0',
  account_ref: 'github-primary',
  environment: 'production',
  idempotency_key: 'github-runs-list-0001',
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
  taskEvents.every((event) => !JSON.stringify(event).includes('short-lived-workflow-token')),
);
await assert.rejects(taskBroker.run(actor, task.id), expectCode('invalid_state'));
assert.equal(calls.length, 4);
await assert.rejects(
  taskBroker.create(actor, {
    tool: 'github.workflow-runs.list',
    tool_version: '1.0.0',
    account_ref: 'github-primary',
    environment: 'production',
    idempotency_key: 'github-runs-injection-0001',
    parameters: { ...parameters, url: 'https://example.invalid/steal' },
  }),
  expectCode('schema_mismatch'),
);
assert.equal(calls.length, 4);

console.log(
  'github workflow runs adapter: actions-read lease, bounded status and full task loop passed',
);
