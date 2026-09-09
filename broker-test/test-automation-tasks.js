import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { ApprovalBroker } from '../broker/lib/approvals-v2.js';
import { AutomationTaskBroker } from '../broker/lib/automation-tasks.js';
import { loadToolRegistry } from '../broker/lib/tool-registry.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const expectCode = (code) => (error) => error instanceof V2Error && error.code === code;
const registry = loadToolRegistry(resolve(import.meta.dirname, '../tools/registry.json'));
let now = 1_900_000_000_000;
const observed = [];
const executorContexts = [];
const criticalPolicy = {
  enabled: true, approval_required: true, required_approvals: 2, approval_roles: ['admin'],
  accounts: ['control-plane'], environments: ['production'], resources: ['device-state'],
  parameter_schema: {
    type: 'object', required: ['resource_ref', 'device_id', 'state'],
    properties: { resource_ref: { type: 'string' }, device_id: { type: 'string' }, state: { type: 'string' } },
  },
};
const approvals = new ApprovalBroker({
  now: () => now,
  getPolicy: (provider, operationId) => provider === 'broker' && operationId === 'device.state' ? criticalPolicy : null,
});
const authorize = async (operation, options = {}) => {
  if (operation.provider === 'denied') return { allow: false, reason: 'policy_denied' };
  if (operation.operationId === 'device.state' && options.ignoreApproval !== true
    && (operation.identity.context?.approvalGrants || []).length < 2) return { allow: false, reason: 'approval_required' };
  return { allow: true, ttlMs: 60_000 };
};
const executors = new Map([
  ['broker.tools.inspect@1.0.0', async (parameters, context) => {
    executorContexts.push(context);
    const tool = registry.findByName(parameters.tool_name, parameters.tool_version);
    return {
      name: tool.name, version: tool.version, provider: tool.provider,
      operation_id: tool.operation_id, risk_level: tool.risk_level, agent_execution: tool.agent_execution,
    };
  }],
  ['broker.device.state@1.0.0', async (parameters) => ({ id: parameters.device_id, state: parameters.state })],
]);
const broker = new AutomationTaskBroker({
  toolRegistry: registry, authorize, approvalBroker: approvals, executors,
  now: () => now, onEvent: (event) => observed.push(event),
});
const human = {
  name: 'requester', isAdmin: true,
  context: { via: 'session', authFactors: ['webauthn'], client: { role: 'admin', security_profile: 'strict' } },
};
const lowInput = {
  tool: 'broker.tools.inspect', tool_version: '1.0.0', account_ref: 'control-plane',
  environment: 'production', idempotency_key: 'inspect-task-0001',
  parameters: { resource_ref: 'tool-registry', tool_name: 'github.repository.read', tool_version: '1.0.0' },
};

const low = await broker.create(human, lowInput);
assert.equal(low.state, 'READY');
assert.equal(low.risk_level, 'LOW');
assert.equal((await broker.create(human, lowInput)).id, low.id, 'same idempotency key returns the original task');
await assert.rejects(broker.create(human, {
  ...lowInput, parameters: { ...lowInput.parameters, tool_name: 'openai.models.list' },
}), expectCode('idempotency_conflict'));
const completed = await broker.run(human, low.id);
assert.equal(completed.state, 'SUCCEEDED');
assert.equal(completed.result.name, 'github.repository.read');
assert.match(completed.execution_id, /^[a-f0-9-]{36}$/);
assert.equal(completed.latency_ms, 0);
assert.equal(executorContexts[0].execution.execution_id, completed.execution_id);
assert.ok(!JSON.stringify(executorContexts[0]).includes('et1.'), 'executor receives verified claims, not the bearer capability');
assert.equal(broker.get(human, low.id).result.version, '1.0.0');
assert.deepEqual(broker.eventsFor(human, low.id).map((event) => event.state), [
  'REQUESTED', 'READY', 'EXECUTING', 'SUCCEEDED',
]);
assert.ok(observed.every((event) => !JSON.stringify(event).includes('typed_parameters')));
await assert.rejects(broker.run(human, low.id), expectCode('invalid_state'));

let concurrentAuthorizations = 0;
const concurrentBroker = new AutomationTaskBroker({
  toolRegistry: registry,
  authorize: async () => {
    concurrentAuthorizations += 1;
    await new Promise((resolvePending) => setImmediate(resolvePending));
    return { allow: true, ttlMs: 60_000 };
  },
  approvalBroker: approvals, executors,
});
const [concurrentA, concurrentB] = await Promise.all([
  concurrentBroker.create(human, { ...lowInput, idempotency_key: 'concurrent-task-001' }),
  concurrentBroker.create(human, { ...lowInput, idempotency_key: 'concurrent-task-001' }),
]);
assert.equal(concurrentA.id, concurrentB.id);
assert.equal(concurrentAuthorizations, 1, 'concurrent retries share one authorization and task creation');

let releaseExecution;
let executionCalls = 0;
const executionGate = new Promise((resolveExecution) => { releaseExecution = resolveExecution; });
const singleExecutionBroker = new AutomationTaskBroker({
  toolRegistry: registry, authorize, approvalBroker: approvals,
  executors: new Map([['broker.tools.inspect@1.0.0', async () => {
    executionCalls += 1;
    await executionGate;
    return {
      name: 'github.repository.read', version: '1.0.0', provider: 'github',
      operation_id: 'repository.read', risk_level: 'LOW', agent_execution: true,
    };
  }]]),
});
const singleExecution = await singleExecutionBroker.create(human, {
  ...lowInput, idempotency_key: 'single-execution-01',
});
const firstRun = singleExecutionBroker.run(human, singleExecution.id);
await new Promise((resolvePending) => setImmediate(resolvePending));
await assert.rejects(singleExecutionBroker.run(human, singleExecution.id), expectCode('invalid_state'));
releaseExecution();
assert.equal((await firstRun).state, 'SUCCEEDED');
assert.equal(executionCalls, 1, 'concurrent run requests cannot invoke an adapter twice');

let releaseAuthorization;
let authorizationCalls = 0;
const authorizationGate = new Promise((resolveAuthorization) => { releaseAuthorization = resolveAuthorization; });
const authorizingBroker = new AutomationTaskBroker({
  toolRegistry: registry,
  authorize: async () => {
    authorizationCalls += 1;
    if (authorizationCalls > 1) await authorizationGate;
    return { allow: true, ttlMs: 60_000 };
  },
  approvalBroker: approvals, executors,
});
const authorizingTask = await authorizingBroker.create(human, {
  ...lowInput, idempotency_key: 'authorizing-task-01',
});
const authorizingRun = authorizingBroker.run(human, authorizingTask.id);
assert.throws(() => authorizingBroker.cancel(human, authorizingTask.id), expectCode('invalid_state'));
releaseAuthorization();
assert.equal((await authorizingRun).state, 'SUCCEEDED');

const criticalInput = {
  tool: 'broker.device.state', tool_version: '1.0.0', account_ref: 'control-plane',
  environment: 'production', idempotency_key: 'critical-task-0001',
  parameters: { resource_ref: 'device-state', device_id: 'device-01', state: 'revoked' },
};
const critical = await broker.create(human, criticalInput);
assert.equal(critical.state, 'PENDING_APPROVAL');
assert.equal(critical.risk_level, 'CRITICAL');
const approver = (name) => ({ name, context: { via: 'session', authFactors: ['webauthn'], client: { role: 'admin' } } });
approvals.decide(approver('admin-b'), critical.approval_id, 'approve');
approvals.decide(approver('admin-c'), critical.approval_id, 'approve');
const criticalDone = await broker.run(human, critical.id);
assert.equal(criticalDone.state, 'SUCCEEDED');
assert.deepEqual(criticalDone.result, { id: 'device-01', state: 'revoked' });
assert.equal(approvals.list(human).find((item) => item.id === critical.approval_id).status, 'SUCCEEDED');

const revokedApprovals = new ApprovalBroker({
  now: () => now,
  getPolicy: (provider, operationId) => provider === 'broker' && operationId === 'device.state' ? criticalPolicy : null,
});
const revokedBroker = new AutomationTaskBroker({
  toolRegistry: registry,
  authorize: async (_operation, options = {}) => options.ignoreApproval === true
    ? { allow: true, ttlMs: 60_000 }
    : { allow: false, reason: 'policy_revoked' },
  approvalBroker: revokedApprovals, executors, now: () => now,
});
const revoked = await revokedBroker.create(human, { ...criticalInput, idempotency_key: 'critical-task-revoke' });
await assert.rejects(revokedBroker.run(human, revoked.id), expectCode('approval_mismatch'));
revokedApprovals.decide(approver('admin-d'), revoked.approval_id, 'approve');
revokedApprovals.decide(approver('admin-e'), revoked.approval_id, 'approve');
const revokedResult = await revokedBroker.run(human, revoked.id);
assert.equal(revokedResult.state, 'FAILED');
assert.deepEqual(revokedResult.error, { code: 'policy_revoked' });
assert.equal(revokedApprovals.list(human).find((item) => item.id === revoked.approval_id).status, 'FAILED');

const cancellable = await broker.create(human, { ...lowInput, idempotency_key: 'inspect-task-cancel' });
assert.equal(broker.cancel(human, cancellable.id).state, 'CANCELLED');
assert.throws(() => broker.cancel(human, cancellable.id), expectCode('invalid_state'));

const pendingCancellation = await broker.create(human, { ...criticalInput, idempotency_key: 'critical-task-cancel' });
assert.equal(broker.cancel(human, pendingCancellation.id).state, 'CANCELLED');
assert.equal(approvals.list(human).find((item) => item.id === pendingCancellation.approval_id).status, 'CANCELLED');

const expiring = await broker.create(human, { ...lowInput, idempotency_key: 'inspect-task-expire' });
now += 60_001;
assert.equal(broker.get(human, expiring.id).state, 'EXPIRED');
await assert.rejects(broker.run(human, expiring.id), expectCode('invalid_state'));

await assert.rejects(broker.create(human, { ...lowInput, tool: 'missing.tool', idempotency_key: 'missing-tool-0001' }), expectCode('tool_unregistered'));
await assert.rejects(broker.create(human, { ...lowInput, idempotency_key: 'short' }), expectCode('invalid_request'));
await assert.rejects(broker.create(human, { ...lowInput, idempotency_key: 'bad-schema-task01', parameters: { ...lowInput.parameters, extra: true } }), expectCode('schema_mismatch'));
await assert.rejects(broker.create(null, lowInput), expectCode('unauthorized'));
await assert.rejects(broker.create(human, { ...lowInput, idempotency_key: 'invalid-request-01', unexpected: true }), expectCode('invalid_request'));
assert.throws(() => broker.get(null, low.id), expectCode('unauthorized'));
assert.throws(() => broker.get(human, '00000000-0000-4000-8000-000000000000'), expectCode('not_found'));
assert.throws(() => broker.get({ ...human, name: 'other', isAdmin: false }, low.id), expectCode('forbidden'));
assert.equal(broker.get({ ...human, name: 'other', isAdmin: true }, low.id).id, low.id);

const deniedRegistry = {
  findByName(name, version) {
    const tool = registry.findByName(name, version);
    return tool ? { ...tool, provider: 'denied' } : null;
  },
};
const deniedBroker = new AutomationTaskBroker({
  toolRegistry: deniedRegistry, authorize, approvalBroker: approvals, executors,
});
await assert.rejects(deniedBroker.create(human, { ...lowInput, idempotency_key: 'policy-denied-0001' }), expectCode('forbidden'));
await assert.rejects(deniedBroker.create(human, { ...lowInput, idempotency_key: 'policy-denied-0001' }), expectCode('forbidden'));
assert.equal(deniedBroker.idempotency.size, 0, 'failed creation cannot poison an idempotency key');

const approvalFailureBroker = new AutomationTaskBroker({
  toolRegistry: registry, authorize, executors,
  approvalBroker: { create() { throw new V2Error('approval_unavailable', 'approval unavailable', 503); } },
});
await assert.rejects(approvalFailureBroker.create(human, {
  ...criticalInput, idempotency_key: 'task-case-approve01',
}), expectCode('approval_unavailable'));
assert.equal(approvalFailureBroker.tasks.size, 0);
assert.equal(approvalFailureBroker.idempotency.size, 0);

const failureBroker = (executor) => new AutomationTaskBroker({
  toolRegistry: registry, authorize, approvalBroker: approvals,
  executors: executor === undefined ? new Map() : new Map([['broker.tools.inspect@1.0.0', executor]]),
  now: () => now,
});
const unavailableBroker = failureBroker();
const unavailable = await unavailableBroker.create(human, { ...lowInput, idempotency_key: 'task-case-missing1' });
assert.equal((await unavailableBroker.run(human, unavailable.id)).error.code, 'executor_unavailable');

const throwingBroker = failureBroker(async () => { throw new Error('canary must never escape'); });
const throwing = await throwingBroker.create(human, { ...lowInput, idempotency_key: 'task-case-throws01' });
const thrownResult = await throwingBroker.run(human, throwing.id);
assert.equal(thrownResult.state, 'FAILED');
assert.deepEqual(thrownResult.error, { code: 'executor_failed' });
assert.ok(!JSON.stringify(thrownResult).includes('canary'));

const invalidOutputBroker = failureBroker(async () => ({ name: 'incomplete' }));
const invalidOutput = await invalidOutputBroker.create(human, { ...lowInput, idempotency_key: 'bad-output-task-01' });
assert.equal((await invalidOutputBroker.run(human, invalidOutput.id)).error.code, 'schema_mismatch');

const tokenFailureBroker = new AutomationTaskBroker({
  toolRegistry: registry, authorize, approvalBroker: approvals, executors,
  executionTokens: { issue() { throw new V2Error('execution_token_failed', 'unavailable', 503); } },
});
const tokenFailure = await tokenFailureBroker.create(human, { ...lowInput, idempotency_key: 'token-failure-task1' });
assert.equal((await tokenFailureBroker.run(human, tokenFailure.id)).error.code, 'execution_token_failed');

const capacityBroker = new AutomationTaskBroker({
  toolRegistry: registry, authorize, approvalBroker: approvals, executors, maxTasks: 1,
});
await capacityBroker.create(human, { ...lowInput, idempotency_key: 'capacity-task-0001' });
await assert.rejects(capacityBroker.create(human, { ...lowInput, idempotency_key: 'capacity-task-0002' }), expectCode('capacity'));

const pruningBroker = new AutomationTaskBroker({
  toolRegistry: registry, authorize, approvalBroker: approvals, executors, now: () => now,
});
const oldTask = await pruningBroker.create(human, { ...lowInput, idempotency_key: 'prunable-task-0001' });
await pruningBroker.run(human, oldTask.id);
now += 60 * 60_000 + 1;
const replacement = await pruningBroker.create(human, { ...lowInput, idempotency_key: 'prunable-task-0001' });
assert.notEqual(replacement.id, oldTask.id, 'expired retention must not pin an idempotency key forever');

const sequenceTask = pruningBroker.tasks.get(replacement.id);
sequenceTask.events = Array.from({ length: 64 }, (_, index) => ({ sequence: index + 1 }));
sequenceTask.nextSequence = 65;
sequenceTask.state = 'REQUESTED';
pruningBroker.transition(sequenceTask, 'READY', 'sequence_test');
assert.equal(sequenceTask.events.length, 64);
assert.equal(sequenceTask.events.at(-1).sequence, 65);
assert.throws(() => pruningBroker.transition(sequenceTask, 'UNKNOWN', 'invalid'), expectCode('invalid_state'));
assert.throws(() => pruningBroker.transition(sequenceTask, 'SUCCEEDED', 'invalid'), expectCode('invalid_state'));

const schemaTool = {
  ...registry.findByName('broker.tools.inspect', '1.0.0'),
  name: 'broker.schema.check', operation_id: 'schema.check',
  input_schema: {
    type: 'object', additionalProperties: false,
    required: ['resource_ref', 'items', 'count', 'ratio', 'enabled', 'mode', 'label'],
    properties: {
      resource_ref: { type: 'string', const: 'schema' },
      items: { type: 'array', maxItems: 2, items: { type: 'string' } },
      count: { type: 'integer' }, ratio: { type: 'number' }, enabled: { type: 'boolean' },
      mode: { type: 'string', enum: ['safe'] }, label: { type: 'string', minLength: 2, maxLength: 4 },
    },
  },
};
const schemaBroker = new AutomationTaskBroker({
  toolRegistry: { findByName: (name, version) => name === schemaTool.name && version === schemaTool.version ? schemaTool : null },
  authorize, approvalBroker: approvals,
});
const validSchemaParameters = {
  resource_ref: 'schema', items: ['a'], count: 1, ratio: 0.5, enabled: true, mode: 'safe', label: 'ok',
};
assert.equal((await schemaBroker.create(human, {
  tool: schemaTool.name, tool_version: schemaTool.version, account_ref: 'control-plane', environment: 'development',
  parameters: validSchemaParameters, idempotency_key: 'schema-valid-task01',
})).state, 'READY');
const rejectSchema = async (parameters) => assert.rejects(schemaBroker.create(human, {
  tool: schemaTool.name, tool_version: schemaTool.version, account_ref: 'control-plane', environment: 'development',
  parameters, idempotency_key: 'schema-invalid-001',
}), expectCode('schema_mismatch'));
await rejectSchema({ ...validSchemaParameters, resource_ref: 'other' });
await rejectSchema({ ...validSchemaParameters, items: 'a' });
await rejectSchema({ ...validSchemaParameters, items: ['a', 'b', 'c'] });
await rejectSchema({ ...validSchemaParameters, items: [1] });
await rejectSchema({ ...validSchemaParameters, count: 1.5 });
await rejectSchema({ ...validSchemaParameters, ratio: Number.POSITIVE_INFINITY });
await rejectSchema({ ...validSchemaParameters, enabled: 'yes' });
await rejectSchema({ ...validSchemaParameters, mode: 'unsafe' });
await rejectSchema({ ...validSchemaParameters, label: 'x' });
await rejectSchema({ ...validSchemaParameters, label: 'excess' });

console.log('automation tasks: low-risk and approved critical end-to-end loops passed');
