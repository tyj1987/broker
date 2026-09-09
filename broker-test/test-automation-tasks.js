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

await assert.rejects(
  new AutomationTaskBroker({ toolRegistry: registry, authorize, approvalBroker: approvals, executors })
    .create({ ...human, name: 'invalid\0principal' }, lowInput),
  expectCode('unauthorized'),
);

assert.deepEqual(
  broker.listTools(human).map((tool) => tool.name),
  ['broker.tools.inspect', 'broker.device.state'],
);

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
const sameOwnerApiKey = (overrides = {}) => ({
  name: human.name,
  context: {
    via: 'api_key',
    client: { role: 'admin' },
    apiKey: {
      scopes: ['operations:execute'],
      allowed_services: ['broker'],
      allowed_operations: ['broker:tools.inspect'],
      allowed_accounts: ['control-plane'],
      allowed_resources: ['tool-registry'],
      allowed_environments: ['production'],
      ...overrides,
    },
  },
});
assert.equal(broker.get(sameOwnerApiKey(), low.id).id, low.id);
const narrowedSession = {
  ...human,
  context: {
    ...human.context,
    apiKey: sameOwnerApiKey({ allowed_resources: ['another-resource'] }).context.apiKey,
  },
};
assert.throws(
  () => broker.get(narrowedSession, low.id),
  expectCode('forbidden'),
  'a bearer key narrows a simultaneous session identity',
);
await assert.rejects(
  broker.create(narrowedSession, { ...lowInput, idempotency_key: 'narrowed-session-task1' }),
  expectCode('forbidden'),
);
assert.equal(
  broker.listTools(narrowedSession).some((tool) => tool.name === 'broker.tools.inspect'),
  true,
  'tool discovery remains visible when the key has at least one allowed resource',
);
for (const revokedGrant of [
  { allowed_services: [] },
  { allowed_operations: [] },
  { allowed_accounts: ['another-account'] },
  { allowed_resources: ['another-resource'] },
  { allowed_environments: ['staging'] },
]) {
  const revokedSameOwnerKey = sameOwnerApiKey(revokedGrant);
  assert.throws(() => broker.get(revokedSameOwnerKey, low.id), expectCode('forbidden'));
  assert.throws(() => broker.eventsFor(revokedSameOwnerKey, low.id), expectCode('forbidden'));
  await assert.rejects(broker.create(revokedSameOwnerKey, lowInput), expectCode('forbidden'));
}
assert.ok(observed.every((event) => !JSON.stringify(event).includes('typed_parameters')));
const completionAudit = observed.find((event) => event.task_id === low.id && event.state === 'SUCCEEDED');
assert.deepEqual({
  actor: completionAudit.actor,
  identity: completionAudit.identity,
  role: completionAudit.role,
  tool: completionAudit.tool,
  target: completionAudit.target,
  environment: completionAudit.environment,
  risk: completionAudit.risk_level,
  decision: completionAudit.policy_decision,
  approval: completionAudit.approval_id,
  execution: completionAudit.execution_id,
  result: completionAudit.result,
  latency: completionAudit.latency_ms,
}, {
  actor: 'requester', identity: 'session', role: 'admin', tool: 'broker.tools.inspect',
  target: 'tool-registry', environment: 'production', risk: 'LOW', decision: 'allow',
  approval: null, execution: completed.execution_id, result: 'succeeded', latency: 0,
});
await assert.rejects(broker.run(human, low.id), expectCode('invalid_state'));

const targetCanary = `ghp_${'A'.repeat(40)}`;
const redactedTargetEvents = [];
const redactedTargetTool = {
  ...registry.findByName('broker.tools.inspect', '1.0.0'),
  input_schema: {
    ...registry.findByName('broker.tools.inspect', '1.0.0').input_schema,
    properties: {
      ...registry.findByName('broker.tools.inspect', '1.0.0').input_schema.properties,
      resource_ref: { type: 'string' },
    },
  },
};
const redactedTargetBroker = new AutomationTaskBroker({
  toolRegistry: {
    findByName(name, version) {
      return name === redactedTargetTool.name && version === redactedTargetTool.version
        ? structuredClone(redactedTargetTool) : null;
    },
  },
  authorize, approvalBroker: approvals, executors,
  now: () => now, onEvent: (event) => redactedTargetEvents.push(event),
});
const redactedTargetTask = await redactedTargetBroker.create(human, {
  ...lowInput,
  idempotency_key: 'redacted-target-001',
  parameters: { ...lowInput.parameters, resource_ref: targetCanary },
});
assert.equal((await redactedTargetBroker.run(human, redactedTargetTask.id)).state, 'SUCCEEDED');
assert.ok(redactedTargetEvents.every((event) => !JSON.stringify(event).includes(targetCanary)));
assert.ok(redactedTargetEvents.some((event) => event.target === 'ghp_***'));

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

let raceNow = 1_900_100_000_000;
let releaseExpiryRace;
const expiryRaceGate = new Promise((resolveExecution) => { releaseExpiryRace = resolveExecution; });
const expiryRaceBroker = new AutomationTaskBroker({
  toolRegistry: registry,
  authorize: async () => ({ allow: true, ttlMs: 5_000 }),
  approvalBroker: approvals,
  now: () => raceNow,
  executors: new Map([['broker.tools.inspect@1.0.0', async () => {
    await expiryRaceGate;
    return {
      name: 'github.repository.read', version: '1.0.0', provider: 'github',
      operation_id: 'repo.read', risk_level: 'LOW', agent_execution: true,
    };
  }]]),
});
const expiryRaceTask = await expiryRaceBroker.create(human, {
  ...lowInput, idempotency_key: 'execution-expiry-race-01',
});
const expiryRaceRun = expiryRaceBroker.run(human, expiryRaceTask.id);
await new Promise((resolvePending) => setImmediate(resolvePending));
raceNow += 5_001;
assert.equal(
  expiryRaceBroker.get(human, expiryRaceTask.id).state,
  'EXECUTING',
  'observation cannot expire a running task',
);
assert.equal(
  expiryRaceBroker.eventsFor(human, expiryRaceTask.id).at(-1).state,
  'EXECUTING',
  'event reads cannot mutate a running task',
);
assert.throws(
  () => expiryRaceBroker.cancel(human, expiryRaceTask.id),
  expectCode('invalid_state'),
  'cancellation cannot rewrite an in-flight execution as expired',
);
releaseExpiryRace();
assert.equal((await expiryRaceRun).state, 'SUCCEEDED');

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
const expiringCritical = await broker.create(human, { ...criticalInput, idempotency_key: 'critical-expire-001' });
now += 60_001;
assert.equal(broker.get(human, expiring.id).state, 'EXPIRED');
await assert.rejects(broker.run(human, expiring.id), expectCode('invalid_state'));
assert.equal(broker.get(human, expiringCritical.id).state, 'EXPIRED');
assert.equal(
  approvals.list(human).find((item) => item.id === expiringCritical.approval_id).status,
  'CANCELLED',
  'task expiry revokes its unused approval',
);

await assert.rejects(broker.create(human, { ...lowInput, tool: 'missing.tool', idempotency_key: 'missing-tool-0001' }), expectCode('tool_unregistered'));
await assert.rejects(broker.create(human, { ...lowInput, idempotency_key: 'short' }), expectCode('invalid_request'));
await assert.rejects(broker.create(human, { ...lowInput, idempotency_key: 'bad-schema-task01', parameters: { ...lowInput.parameters, extra: true } }), expectCode('schema_mismatch'));
await assert.rejects(broker.create(null, lowInput), expectCode('unauthorized'));
await assert.rejects(broker.create(human, { ...lowInput, idempotency_key: 'invalid-request-01', unexpected: true }), expectCode('invalid_request'));
assert.throws(() => broker.get(null, low.id), expectCode('unauthorized'));
assert.throws(() => broker.get(human, '00000000-0000-4000-8000-000000000000'), expectCode('not_found'));
assert.throws(
  () => broker.get({
    name: 'other',
    isAdmin: false,
    context: { via: 'session', authFactors: ['webauthn'], client: { role: 'developer' } },
  }, low.id),
  expectCode('forbidden'),
);
assert.equal(broker.get({ ...human, name: 'other', isAdmin: true }, low.id).id, low.id);
const adminApiKey = {
  name: 'other-admin-key',
  isAdmin: true,
  context: { via: 'api_key', client: { role: 'admin' }, apiKey: { scopes: ['operations:execute'] } },
};
assert.throws(() => broker.get(adminApiKey, low.id), expectCode('forbidden'));
assert.throws(() => broker.eventsFor(adminApiKey, low.id), expectCode('forbidden'));
assert.throws(() => broker.cancel(adminApiKey, low.id), expectCode('forbidden'));
await assert.rejects(broker.run(adminApiKey, low.id), expectCode('forbidden'));
assert.throws(
  () => broker.get({
    name: 'other-admin-session',
    isAdmin: true,
    context: { via: 'session', authFactors: [], client: { role: 'admin' } },
  }, low.id),
  expectCode('forbidden'),
  'cross-owner administration requires WebAuthn step-up',
);

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

const orphanSafeApprovals = new ApprovalBroker({
  now: () => now,
  getPolicy: (provider, operationId) => provider === 'broker' && operationId === 'device.state' ? criticalPolicy : null,
});
const orphanSafeBroker = new AutomationTaskBroker({
  toolRegistry: registry, authorize, approvalBroker: orphanSafeApprovals, executors,
  now: () => now,
  onEvent(event) {
    if (event.state === 'PENDING_APPROVAL') throw new Error('pending audit unavailable');
  },
});
await assert.rejects(orphanSafeBroker.create(human, {
  ...criticalInput, idempotency_key: 'orphan-safe-00001',
}), /pending audit unavailable/);
assert.equal(orphanSafeBroker.tasks.size, 0);
assert.equal(orphanSafeBroker.idempotency.size, 0);
const orphanedApproval = orphanSafeApprovals.list(human)[0];
assert.equal(orphanedApproval.status, 'CANCELLED', 'failed task creation revokes its otherwise orphaned approval');
assert.throws(
  () => orphanSafeApprovals.claimFor(human, { ...criticalInput, approval_request_id: orphanedApproval.id }),
  expectCode('invalid_state'),
);

let failCancellationAudit = true;
const retryCancelApprovals = new ApprovalBroker({
  now: () => now,
  getPolicy: (provider, operationId) => provider === 'broker' && operationId === 'device.state' ? criticalPolicy : null,
});
const retryCancelBroker = new AutomationTaskBroker({
  toolRegistry: registry, authorize, approvalBroker: retryCancelApprovals, executors,
  now: () => now,
  onEvent(event) {
    if (event.state === 'CANCELLED' && failCancellationAudit) {
      failCancellationAudit = false;
      throw new Error('cancellation audit unavailable');
    }
  },
});
const retryCancelTask = await retryCancelBroker.create(human, {
  ...criticalInput, idempotency_key: 'retry-cancel-0001',
});
assert.throws(() => retryCancelBroker.cancel(human, retryCancelTask.id), /cancellation audit unavailable/);
assert.equal(retryCancelBroker.get(human, retryCancelTask.id).state, 'PENDING_APPROVAL');
assert.equal(retryCancelApprovals.list(human)[0].status, 'REQUESTED');
assert.equal(retryCancelBroker.cancel(human, retryCancelTask.id).state, 'CANCELLED');

const failureObserved = [];
const failureBroker = (executor) => new AutomationTaskBroker({
  toolRegistry: registry, authorize, approvalBroker: approvals,
  executors: executor === undefined ? new Map() : new Map([['broker.tools.inspect@1.0.0', executor]]),
  now: () => now, onEvent: (event) => failureObserved.push(event),
});
const unavailableBroker = failureBroker();
await assert.rejects(
  unavailableBroker.create(human, { ...lowInput, idempotency_key: 'task-case-missing1' }),
  expectCode('executor_unavailable'),
);
assert.equal(unavailableBroker.tasks.size, 0);
assert.equal(unavailableBroker.idempotency.size, 0);

const disappearingExecutorBroker = failureBroker(async () => ({}));
const disappearingExecutorTask = await disappearingExecutorBroker.create(human, {
  ...lowInput, idempotency_key: 'task-case-removed01',
});
disappearingExecutorBroker.executors.clear();
assert.equal(
  (await disappearingExecutorBroker.run(human, disappearingExecutorTask.id)).error.code,
  'executor_unavailable',
);

const throwingBroker = failureBroker(async () => { throw new Error('canary must never escape'); });
const throwing = await throwingBroker.create(human, { ...lowInput, idempotency_key: 'task-case-throws01' });
const thrownResult = await throwingBroker.run(human, throwing.id);
assert.equal(thrownResult.state, 'FAILED');
assert.deepEqual(thrownResult.error, { code: 'executor_failed' });
assert.ok(!JSON.stringify(thrownResult).includes('canary'));
const failureAudit = failureObserved.find((event) => event.task_id === throwing.id && event.state === 'FAILED');
assert.equal(failureAudit.result, 'failed');
assert.equal(failureAudit.error, 'executor_failed');

const invalidOutputBroker = failureBroker(async () => ({ name: 'incomplete' }));
const invalidOutput = await invalidOutputBroker.create(human, { ...lowInput, idempotency_key: 'bad-output-task-01' });
assert.equal((await invalidOutputBroker.run(human, invalidOutput.id)).error.code, 'schema_mismatch');

let rateNow = 2_000_000_000_000;
let rateExecutorCalls = 0;
const rateTool = {
  ...registry.findByName('broker.tools.inspect', '1.0.0'),
  input_schema: {
    ...registry.findByName('broker.tools.inspect', '1.0.0').input_schema,
    properties: {
      ...registry.findByName('broker.tools.inspect', '1.0.0').input_schema.properties,
      resource_ref: { type: 'string' },
    },
  },
  rate_limit: { requests: 1, window_seconds: 60 },
};
const rateBroker = new AutomationTaskBroker({
  toolRegistry: {
    findByName(name, version) {
      return name === rateTool.name && version === rateTool.version ? structuredClone(rateTool) : null;
    },
  },
  authorize, approvalBroker: approvals, now: () => rateNow,
  executors: new Map([['broker.tools.inspect@1.0.0', async () => {
    rateExecutorCalls += 1;
    return {
      name: 'github.repository.read', version: '1.0.0', provider: 'github',
      operation_id: 'repo.read', risk_level: 'LOW', agent_execution: true,
    };
  }]]),
});
const rateOne = await rateBroker.create(human, { ...lowInput, idempotency_key: 'rate-task-000000001' });
assert.equal((await rateBroker.run(human, rateOne.id)).state, 'SUCCEEDED');
const rateTwo = await rateBroker.create(human, {
  ...lowInput, idempotency_key: 'rate-task-000000002',
  parameters: { ...lowInput.parameters, resource_ref: 'different-target' },
});
const limitedResult = await rateBroker.run(human, rateTwo.id);
assert.equal(limitedResult.state, 'FAILED');
assert.deepEqual(limitedResult.error, { code: 'tool_rate_limited' });
assert.equal(rateExecutorCalls, 1, 'changing target cannot bypass the per-tool execution limit');
rateNow += 60_000;
const rateThree = await rateBroker.create(human, { ...lowInput, idempotency_key: 'rate-task-000000003' });
assert.equal((await rateBroker.run(human, rateThree.id)).state, 'SUCCEEDED');
assert.equal(rateExecutorCalls, 2, 'a new fixed window restores the registered execution quota');

let timeoutSignalAborted = false;
const timeoutTool = { ...registry.findByName('broker.tools.inspect', '1.0.0'), timeout_ms: 100 };
const timeoutBroker = new AutomationTaskBroker({
  toolRegistry: {
    findByName(name, version) {
      return name === timeoutTool.name && version === timeoutTool.version ? structuredClone(timeoutTool) : null;
    },
  },
  authorize, approvalBroker: approvals,
  executors: new Map([['broker.tools.inspect@1.0.0', async (_parameters, context) => new Promise((resolve) => {
    context.signal.addEventListener('abort', () => {
      timeoutSignalAborted = true;
      resolve({
        name: 'too-late', version: '1.0.0', provider: 'broker', operation_id: 'tools.inspect',
        risk_level: 'LOW', agent_execution: true,
      });
    }, { once: true });
  })]]),
});
const timedOut = await timeoutBroker.create(human, { ...lowInput, idempotency_key: 'timeout-task-0000001' });
const timedOutResult = await timeoutBroker.run(human, timedOut.id);
assert.equal(timedOutResult.state, 'FAILED');
assert.deepEqual(timedOutResult.error, { code: 'executor_timeout' });
assert.equal(timeoutSignalAborted, true, 'deadline aborts the adapter signal');
assert.equal(timeoutBroker.get(human, timedOut.id).result, undefined, 'late adapter output cannot commit');

let expirySignalAborted = false;
const expiryTool = { ...timeoutTool, timeout_ms: 2_500 };
const expiryBroker = new AutomationTaskBroker({
  toolRegistry: {
    findByName(name, version) {
      return name === expiryTool.name && version === expiryTool.version ? structuredClone(expiryTool) : null;
    },
  },
  authorize: async () => ({ allow: true, ttlMs: 1_500 }), approvalBroker: approvals,
  executors: new Map([['broker.tools.inspect@1.0.0', async (_parameters, context) => new Promise((resolve) => {
    context.signal.addEventListener('abort', () => {
      expirySignalAborted = true;
      resolve({
        name: 'too-late', version: '1.0.0', provider: 'broker', operation_id: 'tools.inspect',
        risk_level: 'LOW', agent_execution: true,
      });
    }, { once: true });
  })]]),
});
const expiresDuringRun = await expiryBroker.create(human, { ...lowInput, idempotency_key: 'expiry-task-00000001' });
const expiredDuringRun = await expiryBroker.run(human, expiresDuringRun.id);
assert.equal(expiredDuringRun.state, 'EXPIRED');
assert.equal(expiredDuringRun.error, undefined);
assert.equal(expirySignalAborted, true, 'absolute task expiry aborts the adapter signal');

const tokenFailureBroker = new AutomationTaskBroker({
  toolRegistry: registry, authorize, approvalBroker: approvals, executors,
  executionTokens: { issue() { throw new V2Error('execution_token_failed', 'unavailable', 503); } },
});
const tokenFailure = await tokenFailureBroker.create(human, { ...lowInput, idempotency_key: 'token-failure-task1' });
assert.equal((await tokenFailureBroker.run(human, tokenFailure.id)).error.code, 'execution_token_failed');

const unsafeOutputBroker = new AutomationTaskBroker({
  toolRegistry: registry,
  authorize,
  approvalBroker: approvals,
  executors: new Map([['broker.tools.inspect@1.0.0', async () => ({
    name: `gh${'p_'}${'A'.repeat(24)}`,
    version: '1.0.0', provider: 'broker', operation_id: 'tools.inspect',
    risk_level: 'LOW', agent_execution: true,
  })]]),
});
const unsafeOutput = await unsafeOutputBroker.create(human, {
  ...lowInput, idempotency_key: 'unsafe-output-task01',
});
const unsafeOutputResult = await unsafeOutputBroker.run(human, unsafeOutput.id);
assert.equal(unsafeOutputResult.state, 'FAILED');
assert.deepEqual(unsafeOutputResult.error, { code: 'unsafe_result' });
assert.equal(unsafeOutputResult.result, undefined, 'credential-like executor output is never retained');

let auditedExecutionCalls = 0;
const mandatoryAuditEvents = [];
const auditFailureBroker = new AutomationTaskBroker({
  toolRegistry: registry,
  authorize,
  approvalBroker: approvals,
  executors: new Map([['broker.tools.inspect@1.0.0', async () => {
    auditedExecutionCalls++;
    return { name: 'blocked', version: '1.0.0', provider: 'broker', operation_id: 'tools.inspect', risk_level: 'LOW', agent_execution: true };
  }]]),
  onEvent(event) {
    mandatoryAuditEvents.push(event);
    if (event.state === 'EXECUTING') throw new Error('mandatory audit unavailable');
  },
});
const auditProtected = await auditFailureBroker.create(human, {
  ...lowInput, idempotency_key: 'mandatory-audit-task1',
});
await assert.rejects(auditFailureBroker.run(human, auditProtected.id), /mandatory audit unavailable/);
assert.equal(auditedExecutionCalls, 0, 'executor must not run when its EXECUTING audit cannot be stored');
assert.equal(auditFailureBroker.get(human, auditProtected.id).state, 'READY', 'failed audit leaves prior task state intact');
assert.equal(
  mandatoryAuditEvents.filter((event) => event.state === 'EXECUTING').length,
  1,
  'the mandatory sink receives exactly one attempted execution transition',
);
assert.equal(
  auditFailureBroker.eventsFor(human, auditProtected.id).some((event) => event.state === 'EXECUTING'),
  false,
  'failed audit does not enter the committed task event stream',
);

let approvedExecutionCalls = 0;
let failApprovedExecutionAudit = true;
const retryableApprovals = new ApprovalBroker({
  now: () => now,
  getPolicy: (provider, operationId) => provider === 'broker' && operationId === 'device.state' ? criticalPolicy : null,
});
const singleAttemptCritical = {
  ...registry.findByName('broker.device.state', '1.0.0'),
  rate_limit: { requests: 1, window_seconds: 3600 },
};
const approvedAuditFailureBroker = new AutomationTaskBroker({
  toolRegistry: {
    findByName(name, version) {
      return name === singleAttemptCritical.name && version === singleAttemptCritical.version
        ? structuredClone(singleAttemptCritical) : null;
    },
  },
  authorize,
  approvalBroker: retryableApprovals,
  executors: new Map([['broker.device.state@1.0.0', async (parameters) => {
    approvedExecutionCalls++;
    return { id: parameters.device_id, state: parameters.state };
  }]]),
  now: () => now,
  onEvent(event) {
    if (event.state === 'EXECUTING' && failApprovedExecutionAudit) {
      failApprovedExecutionAudit = false;
      throw new Error('mandatory approval audit unavailable');
    }
  },
});
const approvalAuditProtected = await approvedAuditFailureBroker.create(human, {
  ...criticalInput, idempotency_key: 'approval-audit-retry01',
});
retryableApprovals.decide(approver('admin-f'), approvalAuditProtected.approval_id, 'approve');
retryableApprovals.decide(approver('admin-g'), approvalAuditProtected.approval_id, 'approve');
await assert.rejects(
  approvedAuditFailureBroker.run(human, approvalAuditProtected.id),
  /mandatory approval audit unavailable/,
);
assert.equal(approvedExecutionCalls, 0, 'an approved executor cannot run before its mandatory audit is stored');
assert.equal(approvedAuditFailureBroker.get(human, approvalAuditProtected.id).state, 'READY');
assert.equal(
  retryableApprovals.list(human).find((item) => item.id === approvalAuditProtected.approval_id).status,
  'APPROVED',
  'an unused approval claim is released after a pre-execution audit outage',
);
assert.equal((await approvedAuditFailureBroker.run(human, approvalAuditProtected.id)).state, 'SUCCEEDED');
assert.equal(approvedExecutionCalls, 1, 'the released approval can be claimed once after audit recovery');
assert.equal(
  retryableApprovals.list(human).find((item) => item.id === approvalAuditProtected.approval_id).status,
  'SUCCEEDED',
);

let policyOutage = true;
let policyRecoveryExecutions = 0;
const policyRecoveryApprovals = new ApprovalBroker({
  now: () => now,
  getPolicy: (provider, operationId) => provider === 'broker' && operationId === 'device.state' ? criticalPolicy : null,
});
const policyRecoveryBroker = new AutomationTaskBroker({
  toolRegistry: registry,
  authorize: async (operation, options = {}) => {
    if (options.ignoreApproval === true) return { allow: true, ttlMs: 60_000 };
    if (policyOutage) {
      policyOutage = false;
      throw new V2Error('policy_unavailable', 'policy unavailable', 503);
    }
    return authorize(operation, options);
  },
  approvalBroker: policyRecoveryApprovals,
  executors: new Map([['broker.device.state@1.0.0', async (parameters) => {
    policyRecoveryExecutions++;
    return { id: parameters.device_id, state: parameters.state };
  }]]),
  now: () => now,
});
const policyRecoveryTask = await policyRecoveryBroker.create(human, {
  ...criticalInput, idempotency_key: 'policy-retry-0001',
});
policyRecoveryApprovals.decide(approver('admin-l'), policyRecoveryTask.approval_id, 'approve');
policyRecoveryApprovals.decide(approver('admin-m'), policyRecoveryTask.approval_id, 'approve');
await assert.rejects(policyRecoveryBroker.run(human, policyRecoveryTask.id), expectCode('policy_unavailable'));
assert.equal(policyRecoveryBroker.get(human, policyRecoveryTask.id).state, 'READY');
assert.equal(policyRecoveryExecutions, 0);
assert.equal(
  policyRecoveryApprovals.list(human).find((item) => item.id === policyRecoveryTask.approval_id).status,
  'APPROVED',
  'a policy outage releases an approval that has not reached an executor',
);
assert.equal((await policyRecoveryBroker.run(human, policyRecoveryTask.id)).state, 'SUCCEEDED');
assert.equal(policyRecoveryExecutions, 1);

let denyAuditOutage = true;
const denialAuditApprovals = new ApprovalBroker({
  now: () => now,
  getPolicy: (provider, operationId) => provider === 'broker' && operationId === 'device.state' ? criticalPolicy : null,
});
const denialAuditBroker = new AutomationTaskBroker({
  toolRegistry: registry,
  authorize: async (_operation, options = {}) => options.ignoreApproval === true
    ? { allow: true, ttlMs: 60_000 }
    : { allow: false, reason: 'policy_revoked' },
  approvalBroker: denialAuditApprovals,
  executors,
  now: () => now,
  onEvent(event) {
    if (event.state === 'FAILED' && denyAuditOutage) {
      denyAuditOutage = false;
      throw new Error('denial audit unavailable');
    }
  },
});
const denialAuditTask = await denialAuditBroker.create(human, {
  ...criticalInput, idempotency_key: 'deny-audit-000001',
});
denialAuditApprovals.decide(approver('admin-n'), denialAuditTask.approval_id, 'approve');
denialAuditApprovals.decide(approver('admin-o'), denialAuditTask.approval_id, 'approve');
await assert.rejects(denialAuditBroker.run(human, denialAuditTask.id), /denial audit unavailable/);
assert.equal(denialAuditBroker.get(human, denialAuditTask.id).state, 'READY');
assert.equal(denialAuditApprovals.list(human)[0].status, 'APPROVED');
assert.equal((await denialAuditBroker.run(human, denialAuditTask.id)).state, 'FAILED');
assert.equal(denialAuditApprovals.list(human)[0].status, 'FAILED');

const terminalAuditApprovals = new ApprovalBroker({
  now: () => now,
  getPolicy: (provider, operationId) => provider === 'broker' && operationId === 'device.state' ? criticalPolicy : null,
});
let terminalAuditExecutions = 0;
const terminalAuditFailureBroker = new AutomationTaskBroker({
  toolRegistry: registry,
  authorize,
  approvalBroker: terminalAuditApprovals,
  executors: new Map([['broker.device.state@1.0.0', async (parameters) => {
    terminalAuditExecutions++;
    return { id: parameters.device_id, state: parameters.state };
  }]]),
  now: () => now,
  onEvent(event) {
    if (event.state === 'SUCCEEDED') throw new Error('terminal audit unavailable');
  },
});
const terminalAuditProtected = await terminalAuditFailureBroker.create(human, {
  ...criticalInput, idempotency_key: 'terminal-audit-failure1',
});
terminalAuditApprovals.decide(approver('admin-h'), terminalAuditProtected.approval_id, 'approve');
terminalAuditApprovals.decide(approver('admin-i'), terminalAuditProtected.approval_id, 'approve');
await assert.rejects(
  terminalAuditFailureBroker.run(human, terminalAuditProtected.id),
  /terminal audit unavailable/,
);
const indeterminateTask = terminalAuditFailureBroker.get(human, terminalAuditProtected.id);
assert.equal(indeterminateTask.state, 'EXECUTING', 'post-execution audit failure cannot make the task retryable');
assert.equal(indeterminateTask.result, undefined, 'an unaudited result is not released to the caller');
assert.equal(
  terminalAuditApprovals.list(human).find((item) => item.id === terminalAuditProtected.approval_id).status,
  'EXECUTING',
  'the consumed approval remains bound to the indeterminate execution',
);
await assert.rejects(terminalAuditFailureBroker.run(human, terminalAuditProtected.id), expectCode('invalid_state'));
assert.equal(terminalAuditExecutions, 1, 'an indeterminate upstream result is never replayed');

const failedTerminalApprovals = new ApprovalBroker({
  now: () => now,
  getPolicy: (provider, operationId) => provider === 'broker' && operationId === 'device.state' ? criticalPolicy : null,
});
const failedTerminalAuditBroker = new AutomationTaskBroker({
  toolRegistry: registry,
  authorize,
  approvalBroker: failedTerminalApprovals,
  executors: new Map([['broker.device.state@1.0.0', async () => { throw new Error('upstream failure'); }]]),
  now: () => now,
  onEvent(event) {
    if (event.state === 'FAILED') throw new Error('failed terminal audit unavailable');
  },
});
const failedTerminalTask = await failedTerminalAuditBroker.create(human, {
  ...criticalInput, idempotency_key: 'failed-audit-failure01',
});
failedTerminalApprovals.decide(approver('admin-j'), failedTerminalTask.approval_id, 'approve');
failedTerminalApprovals.decide(approver('admin-k'), failedTerminalTask.approval_id, 'approve');
await assert.rejects(
  failedTerminalAuditBroker.run(human, failedTerminalTask.id),
  /failed terminal audit unavailable/,
);
assert.equal(failedTerminalAuditBroker.get(human, failedTerminalTask.id).state, 'EXECUTING');
assert.equal(
  failedTerminalApprovals.list(human).find((item) => item.id === failedTerminalTask.approval_id).status,
  'EXECUTING',
);
await assert.rejects(failedTerminalAuditBroker.run(human, failedTerminalTask.id), expectCode('invalid_state'));

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
      items: { type: 'array', minItems: 1, maxItems: 2, items: { type: 'string' } },
      count: { type: 'integer', minimum: 1, maximum: 2 }, ratio: { type: 'number', minimum: 0, maximum: 1 }, enabled: { type: 'boolean' },
      mode: { type: 'string', enum: ['safe'] }, label: { type: 'string', minLength: 2, maxLength: 4 },
    },
  },
};
const schemaBroker = new AutomationTaskBroker({
  toolRegistry: { findByName: (name, version) => name === schemaTool.name && version === schemaTool.version ? schemaTool : null },
  authorize, approvalBroker: approvals,
  executors: new Map([[`${schemaTool.name}@${schemaTool.version}`, async () => ({})]]),
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
await rejectSchema({ ...validSchemaParameters, items: [] });
await rejectSchema({ ...validSchemaParameters, items: ['a', 'b', 'c'] });
await rejectSchema({ ...validSchemaParameters, items: [1] });
await rejectSchema({ ...validSchemaParameters, count: 1.5 });
await rejectSchema({ ...validSchemaParameters, count: 0 });
await rejectSchema({ ...validSchemaParameters, ratio: Number.POSITIVE_INFINITY });
await rejectSchema({ ...validSchemaParameters, ratio: 2 });
await rejectSchema({ ...validSchemaParameters, enabled: 'yes' });
await rejectSchema({ ...validSchemaParameters, mode: 'unsafe' });
await rejectSchema({ ...validSchemaParameters, label: 'x' });
await rejectSchema({ ...validSchemaParameters, label: 'excess' });

const persistenceTool = {
  ...registry.findByName('broker.tools.inspect', '1.0.0'),
  rate_limit: { requests: 1, window_seconds: 60 },
};
const persistenceRegistry = {
  findByName(name, version) {
    return name === persistenceTool.name && version === persistenceTool.version
      ? structuredClone(persistenceTool) : null;
  },
};
let persistenceExecutions = 0;
const persistenceExecutors = new Map([['broker.tools.inspect@1.0.0', async () => {
  persistenceExecutions += 1;
  return {
    name: 'github.repository.read', version: '1.0.0', provider: 'github',
    operation_id: 'repo.read', risk_level: 'LOW', agent_execution: true,
  };
}]]);
const beforeRestart = new AutomationTaskBroker({
  toolRegistry: persistenceRegistry, authorize, approvalBroker: approvals,
  executors: persistenceExecutors, now: () => now,
});
const persistedSuccess = await beforeRestart.create(human, {
  ...lowInput, idempotency_key: 'persisted-success-0001',
});
assert.equal((await beforeRestart.run(human, persistedSuccess.id)).state, 'SUCCEEDED');
const persistedReady = await beforeRestart.create(human, {
  ...lowInput, idempotency_key: 'persisted-ready-000001',
});
const taskState = beforeRestart.exportState();
assert.equal(taskState.version, 1);
assert.equal(taskState.tasks.length, 2);

const afterRestart = new AutomationTaskBroker({
  toolRegistry: persistenceRegistry, authorize, approvalBroker: approvals,
  executors: persistenceExecutors, now: () => now,
});
afterRestart.restoreState(taskState);
assert.equal(afterRestart.get(human, persistedSuccess.id).state, 'SUCCEEDED');
assert.equal(
  (await afterRestart.create(human, { ...lowInput, idempotency_key: 'persisted-success-0001' })).id,
  persistedSuccess.id,
  'idempotency bindings must survive restart',
);
assert.equal((await afterRestart.run(human, persistedReady.id)).error.code, 'tool_rate_limited');
assert.equal(persistenceExecutions, 1, 'execution rate limits must survive restart');

const indeterminateState = terminalAuditFailureBroker.exportState();
assert.equal(indeterminateState.tasks[0].result, null, 'an unaudited upstream result is not persisted');
assert.ok(!JSON.stringify(indeterminateState).includes('et1.'), 'durable task state contains no bearer capability');
const indeterminateAfterRestart = new AutomationTaskBroker({
  toolRegistry: registry, authorize, approvalBroker: terminalAuditApprovals,
  executors, now: () => now,
});
indeterminateAfterRestart.restoreState(indeterminateState);
await assert.rejects(
  indeterminateAfterRestart.run(human, terminalAuditProtected.id),
  expectCode('invalid_state'),
  'an indeterminate execution must not become replayable after restart',
);

const restoreGuard = new AutomationTaskBroker({
  toolRegistry: persistenceRegistry, authorize, approvalBroker: approvals,
  executors: persistenceExecutors, now: () => now,
});
const guardTask = await restoreGuard.create(human, {
  ...lowInput, idempotency_key: 'persisted-guard-000001',
});
restoreGuard.tasks.get(guardTask.id).running = true;
assert.equal(restoreGuard.exportState().tasks[0].state, 'READY', 'an active pre-execution task can be checkpointed');
assert.throws(() => restoreGuard.restoreState(taskState), expectCode('state_busy'));
restoreGuard.tasks.get(guardTask.id).running = false;
const validTaskState = taskState.tasks[0];
const readyTaskState = taskState.tasks[1];
for (const corrupt of [
  null,
  { version: 2, tasks: [], idempotency: [], rate_limits: [] },
  { ...taskState, unexpected: true },
  { ...taskState, tasks: [null] },
  { ...taskState, tasks: [{ ...validTaskState, unexpected: true }] },
  { ...taskState, tasks: [{ ...validTaskState, owner: '' }] },
  { ...taskState, tasks: [{ ...validTaskState, state: 'UNKNOWN' }] },
  { ...taskState, tasks: [{ ...validTaskState, tool: 'missing.tool' }] },
  { ...taskState, tasks: [{ ...validTaskState, parameters: {} }] },
  { ...taskState, tasks: [{ ...validTaskState, request_fingerprint: 'not-a-digest' }] },
  { ...taskState, tasks: [{ ...validTaskState, created_at: 'not-a-timestamp' }] },
  { ...taskState, tasks: [{ ...validTaskState, updated_at: new Date(now - 1).toISOString() }] },
  { ...taskState, tasks: [{ ...validTaskState, events: [] }] },
  { ...taskState, tasks: [{ ...readyTaskState, next_sequence: 1 }] },
  { ...taskState, tasks: [{ ...readyTaskState, events: [null] }] },
  { ...taskState, tasks: [{
    ...readyTaskState,
    events: readyTaskState.events.map((event, index) => index === 0 ? { ...event, unexpected: true } : event),
  }] },
  { ...taskState, tasks: [{
    ...readyTaskState,
    events: readyTaskState.events.map((event, index) => index === 0 ? { ...event, sequence: 2 } : event),
  }] },
  { ...taskState, tasks: [{
    ...readyTaskState,
    events: readyTaskState.events.map((event, index) => index === 1 ? { ...event, state: 'SUCCEEDED' } : event),
  }] },
  { ...taskState, tasks: [{
    ...readyTaskState,
    events: readyTaskState.events.map((event, index) => index === 1 ? { ...event, reason: '' } : event),
  }] },
  { ...taskState, tasks: [{ ...readyTaskState, next_sequence: readyTaskState.next_sequence + 1 }] },
  { ...taskState, tasks: [{ ...readyTaskState, updated_at: new Date(now + 1).toISOString() }] },
  { ...taskState, tasks: [{ ...validTaskState, approval_id: 'not-a-uuid' }] },
  { ...taskState, tasks: [{ ...validTaskState, execution_id: null }] },
  { ...taskState, tasks: [{ ...validTaskState, result: null }] },
  { ...taskState, tasks: [{
    ...validTaskState,
    result: { ...validTaskState.result, name: `gh${'p_'}${'A'.repeat(24)}` },
  }] },
  { ...taskState, tasks: [{ ...validTaskState, error: 'unexpected' }] },
  { ...taskState, tasks: [{ ...readyTaskState, result: validTaskState.result }] },
  { ...taskState, tasks: [{ ...validTaskState, latency_ms: -1 }] },
  { ...taskState, tasks: [validTaskState, validTaskState] },
  { ...taskState, idempotency: [null] },
  { ...taskState, idempotency: [{ ...taskState.idempotency[0], key: '' }] },
  { ...taskState, idempotency: [{ ...taskState.idempotency[0], task_id: '00000000-0000-4000-8000-000000000000' }] },
  { ...taskState, idempotency: [{ ...taskState.idempotency[0], fingerprint: 'not-a-digest' }] },
  { ...taskState, idempotency: [taskState.idempotency[0], taskState.idempotency[0]] },
  { ...taskState, rate_limits: [null] },
  { ...taskState, rate_limits: [{ ...taskState.rate_limits[0], owner: '' }] },
  { ...taskState, rate_limits: [{ ...taskState.rate_limits[0], tool: 'missing.tool' }] },
  { ...taskState, rate_limits: [{ ...taskState.rate_limits[0], expires_at_ms: taskState.rate_limits[0].started_at_ms }] },
  { ...taskState, rate_limits: [{ ...taskState.rate_limits[0], expires_at_ms: taskState.rate_limits[0].expires_at_ms + 1 }] },
  { ...taskState, rate_limits: [{ ...taskState.rate_limits[0], count: 2 }] },
  { ...taskState, rate_limits: [taskState.rate_limits[0], taskState.rate_limits[0]] },
]) {
  assert.throws(() => restoreGuard.restoreState(corrupt), expectCode('state_corrupt'));
}
assert.equal(restoreGuard.get(human, guardTask.id).state, 'READY', 'rejected restore is atomic');
assert.throws(
  () => new AutomationTaskBroker({
    toolRegistry: persistenceRegistry, authorize, approvalBroker: approvals,
    executors: persistenceExecutors, maxTasks: 1,
  }).restoreState(taskState),
  expectCode('state_corrupt'),
);
assert.throws(
  () => new AutomationTaskBroker({
    toolRegistry: { findByName() { throw new Error('registry unavailable'); } },
    authorize, approvalBroker: approvals, executors: persistenceExecutors,
  }).restoreState({ ...taskState, idempotency: [], rate_limits: [] }),
  expectCode('state_corrupt'),
);
assert.throws(
  () => new AutomationTaskBroker({
    toolRegistry: { findByName() { throw new Error('registry unavailable'); } },
    authorize, approvalBroker: approvals, executors: persistenceExecutors,
  }).restoreState({ version: 1, tasks: [], idempotency: [], rate_limits: taskState.rate_limits }),
  expectCode('state_corrupt'),
);
let releasePendingAuthorization;
const pendingStateBroker = new AutomationTaskBroker({
  toolRegistry: persistenceRegistry,
  authorize: async () => new Promise((resolveAuthorization) => { releasePendingAuthorization = resolveAuthorization; }),
  approvalBroker: approvals, executors: persistenceExecutors, now: () => now,
});
const pendingCreation = pendingStateBroker.create(human, {
  ...lowInput, idempotency_key: 'persisted-pending-00001',
});
await new Promise((resolveImmediate) => setImmediate(resolveImmediate));
assert.throws(() => pendingStateBroker.exportState(), expectCode('state_busy'));
assert.throws(() => pendingStateBroker.restoreState(taskState), expectCode('state_busy'));
releasePendingAuthorization({ allow: true, ttlMs: 60_000 });
await pendingCreation;

const checkpointEvents = [];
let checkpointBroker;
checkpointBroker = new AutomationTaskBroker({
  toolRegistry: registry, authorize, approvalBroker: approvals, executors, now: () => now,
  onCheckpoint: (event) => checkpointEvents.push({ event, snapshot: checkpointBroker.exportState() }),
});
const checkpointTask = await checkpointBroker.create(human, {
  ...lowInput, idempotency_key: 'checkpoint-success-0001',
});
await checkpointBroker.run(human, checkpointTask.id);
assert.deepEqual(checkpointEvents.map(({ event }) => event.phase), ['created', 'pre_execute', 'terminal']);
assert.equal(checkpointEvents[0].snapshot.tasks[0].state, 'READY');
assert.equal(checkpointEvents[1].snapshot.tasks[0].state, 'EXECUTING');
assert.equal(checkpointEvents[2].snapshot.tasks[0].state, 'SUCCEEDED');
assert.ok(!JSON.stringify(checkpointEvents).includes('et1.'), 'checkpoints never expose bearer capabilities');

const creationCheckpointApprovals = new ApprovalBroker({
  now: () => now,
  getPolicy: (provider, operationId) => provider === 'broker' && operationId === 'device.state' ? criticalPolicy : null,
});
const creationCheckpointBroker = new AutomationTaskBroker({
  toolRegistry: registry, authorize, approvalBroker: creationCheckpointApprovals, executors, now: () => now,
  onCheckpoint(event) {
    if (event.phase === 'created') throw new Error('creation checkpoint unavailable');
  },
});
await assert.rejects(
  creationCheckpointBroker.create(human, {
    ...criticalInput, idempotency_key: 'checkpoint-create-fail1',
  }),
  /creation checkpoint unavailable/,
);
assert.equal(creationCheckpointBroker.tasks.size, 0);
assert.equal(creationCheckpointBroker.idempotency.size, 0);
assert.deepEqual(creationCheckpointApprovals.list(human), []);

const indeterminateCreationApprovals = new ApprovalBroker({
  now: () => now,
  getPolicy: (provider, operationId) => provider === 'broker' && operationId === 'device.state' ? criticalPolicy : null,
});
const indeterminateCreationBroker = new AutomationTaskBroker({
  toolRegistry: registry, authorize, approvalBroker: indeterminateCreationApprovals, executors, now: () => now,
  onCheckpoint(event) {
    if (event.phase === 'created') {
      throw new V2Error('state_commit_indeterminate', 'state requires reconciliation', 503);
    }
  },
});
const indeterminateCreationInput = {
  ...criticalInput, idempotency_key: 'checkpoint-create-unknown1',
};
await assert.rejects(
  indeterminateCreationBroker.create(human, indeterminateCreationInput),
  expectCode('state_commit_indeterminate'),
);
assert.equal(indeterminateCreationBroker.tasks.size, 1);
assert.equal(indeterminateCreationBroker.idempotency.size, 1);
assert.equal(indeterminateCreationApprovals.list(human)[0].status, 'REQUESTED');
assert.equal(
  (await indeterminateCreationBroker.create(human, indeterminateCreationInput)).state,
  'PENDING_APPROVAL',
  'an idempotent retry reconciles an indeterminate create without duplicating it',
);

let failCancellationCheckpoint = true;
const cancellationCheckpointApprovals = new ApprovalBroker({
  now: () => now,
  getPolicy: (provider, operationId) => provider === 'broker' && operationId === 'device.state' ? criticalPolicy : null,
});
const cancellationCheckpointBroker = new AutomationTaskBroker({
  toolRegistry: registry, authorize, approvalBroker: cancellationCheckpointApprovals, executors, now: () => now,
  onCheckpoint(event) {
    if (event.phase === 'cancelled' && failCancellationCheckpoint) {
      failCancellationCheckpoint = false;
      throw new Error('cancellation checkpoint unavailable');
    }
  },
});
const cancellationCheckpointTask = await cancellationCheckpointBroker.create(human, {
  ...criticalInput, idempotency_key: 'checkpoint-cancel-fail1',
});
assert.throws(
  () => cancellationCheckpointBroker.cancel(human, cancellationCheckpointTask.id),
  /cancellation checkpoint unavailable/,
);
assert.equal(cancellationCheckpointBroker.get(human, cancellationCheckpointTask.id).state, 'PENDING_APPROVAL');
assert.equal(cancellationCheckpointApprovals.list(human)[0].status, 'REQUESTED');
assert.equal(cancellationCheckpointBroker.cancel(human, cancellationCheckpointTask.id).state, 'CANCELLED');

const indeterminateCancellationApprovals = new ApprovalBroker({
  now: () => now,
  getPolicy: (provider, operationId) => provider === 'broker' && operationId === 'device.state' ? criticalPolicy : null,
});
const indeterminateCancellationBroker = new AutomationTaskBroker({
  toolRegistry: registry, authorize, approvalBroker: indeterminateCancellationApprovals, executors, now: () => now,
  onCheckpoint(event) {
    if (event.phase === 'cancelled') {
      throw new V2Error('state_commit_indeterminate', 'state requires reconciliation', 503);
    }
  },
});
const indeterminateCancellationTask = await indeterminateCancellationBroker.create(human, {
  ...criticalInput, idempotency_key: 'checkpoint-cancel-unknown1',
});
assert.throws(
  () => indeterminateCancellationBroker.cancel(human, indeterminateCancellationTask.id),
  expectCode('state_commit_indeterminate'),
);
assert.equal(indeterminateCancellationBroker.get(human, indeterminateCancellationTask.id).state, 'CANCELLED');
assert.equal(indeterminateCancellationApprovals.list(human)[0].status, 'CANCELLED');

let checkpointExecutorCalls = 0;
const unavailableCheckpointBroker = new AutomationTaskBroker({
  toolRegistry: registry, authorize, approvalBroker: approvals,
  executors: new Map([['broker.tools.inspect@1.0.0', async () => {
    checkpointExecutorCalls += 1;
    return {
      name: 'github.repository.read', version: '1.0.0', provider: 'github',
      operation_id: 'repo.read', risk_level: 'LOW', agent_execution: true,
    };
  }]]),
  now: () => now,
  onCheckpoint: (event) => {
    if (event.phase === 'pre_execute') throw new Error('durable state unavailable');
  },
});
const unavailableCheckpointTask = await unavailableCheckpointBroker.create(human, {
  ...lowInput, idempotency_key: 'checkpoint-failure-0001',
});
await assert.rejects(
  unavailableCheckpointBroker.run(human, unavailableCheckpointTask.id),
  /durable state unavailable/,
);
assert.equal(checkpointExecutorCalls, 0, 'executor cannot run before the durable EXECUTING checkpoint');
assert.equal(unavailableCheckpointBroker.get(human, unavailableCheckpointTask.id).state, 'EXECUTING');
assert.equal(unavailableCheckpointBroker.exportState().tasks[0].state, 'EXECUTING');
assert.throws(
  () => new AutomationTaskBroker({ toolRegistry: registry, authorize, approvalBroker: approvals, onCheckpoint: null }),
  expectCode('checkpoint_invalid'),
);
let asyncCheckpointExecutorCalls = 0;
const asyncCheckpointBroker = new AutomationTaskBroker({
  toolRegistry: registry, authorize, approvalBroker: approvals,
  executors: new Map([['broker.tools.inspect@1.0.0', async () => {
    asyncCheckpointExecutorCalls += 1;
    return {};
  }]]),
  onCheckpoint: (event) => event.phase === 'pre_execute' ? Promise.resolve() : undefined,
});
const asyncCheckpointTask = await asyncCheckpointBroker.create(human, {
  ...lowInput, idempotency_key: 'checkpoint-async-000001',
});
await assert.rejects(asyncCheckpointBroker.run(human, asyncCheckpointTask.id), expectCode('checkpoint_invalid'));
assert.equal(asyncCheckpointExecutorCalls, 0, 'asynchronous persistence cannot race executor invocation');

console.log('automation tasks: low-risk and approved critical end-to-end loops passed');
