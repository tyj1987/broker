import assert from 'node:assert/strict';
import { resolve } from 'node:path';

import { createGitHubPullRequestCreateAdapter } from '../broker/adapters/github-pull-request-create.js';
import { ApprovalBroker } from '../broker/lib/approvals-v2.js';
import { AutomationTaskBroker } from '../broker/lib/automation-tasks.js';
import { loadToolRegistry } from '../broker/lib/tool-registry.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const NOW = 2_000_000_000_000;
const registry = loadToolRegistry(resolve(import.meta.dirname, '../tools/registry.json'));
const policy = {
  enabled: true,
  approval_required: true,
  required_approvals: 1,
  approval_roles: ['admin'],
  accounts: ['github-primary'],
  environments: ['production'],
  resources: ['tyj1987/broker'],
  parameter_schema: {
    type: 'object',
    required: ['resource_ref', 'owner', 'repo', 'title', 'head', 'base'],
    properties: {
      resource_ref: { type: 'string', min_length: 1, max_length: 256 },
      owner: { type: 'string', min_length: 1, max_length: 39 },
      repo: { type: 'string', min_length: 1, max_length: 100 },
      title: { type: 'string', min_length: 1, max_length: 256 },
      body: { type: 'string', min_length: 1, max_length: 10_000 },
      head: { type: 'string', min_length: 1, max_length: 255 },
      base: { type: 'string', min_length: 1, max_length: 255 },
      draft: { type: 'boolean' },
    },
  },
};
const approvals = new ApprovalBroker({
  now: () => NOW,
  getPolicy: (provider, operationId) =>
    provider === 'github' && operationId === 'pull_request.create' ? policy : null,
});
const upstreamCalls = [];
const executor = createGitHubPullRequestCreateAdapter({
  now: () => NOW,
  tokenProvider: async () => ({
    token: 'short-lived-write-token',
    repository: 'tyj1987/broker',
    permissions: { pull_requests: 'write' },
    expires_at: new Date(NOW + 60_000).toISOString(),
  }),
  request: async (input) => {
    upstreamCalls.push(input);
    return {
      status: 201,
      body: {
        number: 81,
        state: 'open',
        draft: true,
        head: { ref: 'codex/task-loop' },
        base: { ref: 'master' },
      },
    };
  },
});
const events = [];
const authorize = async (operation, options = {}) => {
  const target = operation.typedParameters?.resource_ref;
  if (
    operation.provider !== 'github' ||
    operation.operationId !== 'pull_request.create' ||
    operation.accountRef !== 'github-primary' ||
    operation.environment !== 'production' ||
    target !== 'tyj1987/broker'
  ) {
    return { allow: false, reason: 'policy_denied' };
  }
  if (options.ignoreApproval !== true && operation.identity.context?.approvalGrants?.length !== 1) {
    return { allow: false, reason: 'approval_required' };
  }
  return { allow: true, ttlMs: 60_000 };
};
const broker = new AutomationTaskBroker({
  toolRegistry: registry,
  authorize,
  approvalBroker: approvals,
  executors: new Map([['github.pull-request.create@1.0.0', executor]]),
  now: () => NOW,
  onEvent: (event) => events.push(event),
});
const requester = {
  name: 'codex-52trz',
  context: {
    via: 'workload_identity',
    client: { role: 'developer', principal_type: 'workload', security_profile: 'strict' },
  },
};
const approver = {
  name: 'release-owner',
  context: {
    via: 'session',
    authFactors: ['webauthn'],
    client: { role: 'admin', principal_type: 'human', security_profile: 'strict' },
  },
};
const input = {
  tool: 'github.pull-request.create',
  tool_version: '1.0.0',
  account_ref: 'github-primary',
  environment: 'production',
  idempotency_key: 'github-pr-create-task-0001',
  parameters: {
    resource_ref: 'tyj1987/broker',
    owner: 'tyj1987',
    repo: 'broker',
    title: 'Task loop acceptance',
    head: 'codex/task-loop',
    base: 'master',
  },
};

const task = await broker.create(requester, input);
assert.equal(task.state, 'PENDING_APPROVAL');
assert.equal(task.risk_level, 'HIGH');
assert.equal(upstreamCalls.length, 0);
await assert.rejects(broker.run(requester, task.id), (error) => error instanceof V2Error);
assert.equal(upstreamCalls.length, 0, 'pending approval cannot reach GitHub');
assert.equal(approvals.decide(approver, task.approval_id, 'approve').status, 'APPROVED');

const completed = await broker.run(requester, task.id);
assert.equal(completed.state, 'SUCCEEDED');
assert.deepEqual(completed.result, {
  number: 81,
  state: 'open',
  draft: true,
  head: 'codex/task-loop',
  base: 'master',
  url: 'https://github.com/tyj1987/broker/pull/81',
});
assert.equal(upstreamCalls.length, 1);
assert.deepEqual(JSON.parse(upstreamCalls[0].body), {
  title: 'Task loop acceptance',
  head: 'codex/task-loop',
  base: 'master',
  draft: true,
});
assert.deepEqual(
  broker.eventsFor(requester, task.id).map((event) => event.state),
  ['REQUESTED', 'PENDING_APPROVAL', 'READY', 'EXECUTING', 'SUCCEEDED'],
);
assert.ok(events.every((event) => !JSON.stringify(event).includes('short-lived-write-token')));
assert.ok(events.every((event) => !JSON.stringify(event).includes('authorization')));
await assert.rejects(
  broker.run(requester, task.id),
  (error) => error instanceof V2Error && error.code === 'invalid_state',
);
assert.equal(upstreamCalls.length, 1, 'terminal task cannot replay pull request creation');

await assert.rejects(
  broker.create(requester, {
    ...input,
    idempotency_key: 'github-pr-injection-0001',
    parameters: { ...input.parameters, url: 'https://evil.example/steal' },
  }),
  (error) => error instanceof V2Error && error.code === 'schema_mismatch',
);
assert.equal(upstreamCalls.length, 1, 'schema rejection occurs before approval and execution');

console.log('github pull request task loop: approval, single execution and audit redaction passed');
