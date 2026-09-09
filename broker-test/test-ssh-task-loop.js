import assert from 'node:assert/strict';
import { resolve } from 'node:path';

import { createSshHostInspectAdapter } from '../broker/adapters/ssh-host-inspect.js';
import { ApprovalBroker } from '../broker/lib/approvals-v2.js';
import { AutomationTaskBroker } from '../broker/lib/automation-tasks.js';
import { loadToolRegistry } from '../broker/lib/tool-registry.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const registry = loadToolRegistry(resolve(import.meta.dirname, '../tools/registry.json'));
const events = [];
const runnerCalls = [];
const executor = createSshHostInspectAdapter({
  runner: async (input) => {
    runnerCalls.push(input);
    return {
      target_ref: input.target_ref,
      hostname: 'broker-ecs.internal',
      uptime_seconds: 86400,
      load_1m: 0.25,
      disk_used_percent: 42.5,
      service_state: 'active',
    };
  },
});
const authorize = async (operation) => ({
  allow:
    operation.provider === 'ssh' &&
    operation.operationId === 'host.inspect' &&
    operation.accountRef === 'ssh-operations' &&
    operation.environment === 'production' &&
    operation.typedParameters?.resource_ref === 'prod-broker-ecs',
  ttlMs: 60_000,
});
const broker = new AutomationTaskBroker({
  toolRegistry: registry,
  authorize,
  approvalBroker: new ApprovalBroker(),
  executors: new Map([['ssh.host.inspect@1.0.0', executor]]),
  onEvent: (event) => events.push(event),
});
const actor = {
  name: 'operations-agent',
  context: {
    via: 'workload_identity',
    client: { role: 'operator', principal_type: 'workload', security_profile: 'strict' },
  },
};

const task = await broker.create(actor, {
  tool: 'ssh.host.inspect',
  tool_version: '1.0.0',
  account_ref: 'ssh-operations',
  environment: 'production',
  idempotency_key: 'ssh-inspection-task-0001',
  parameters: { resource_ref: 'prod-broker-ecs' },
});
assert.equal(task.state, 'READY');
assert.equal(task.risk_level, 'MEDIUM');

const completed = await broker.run(actor, task.id);
assert.equal(completed.state, 'SUCCEEDED');
assert.deepEqual(completed.result, {
  target_ref: 'prod-broker-ecs',
  hostname: 'broker-ecs.internal',
  uptime_seconds: 86400,
  load_1m: 0.25,
  disk_used_percent: 42.5,
  service_state: 'active',
});
assert.equal(runnerCalls.length, 1);
assert.deepEqual(
  {
    operation_id: runnerCalls[0].operation_id,
    account_ref: runnerCalls[0].account_ref,
    environment: runnerCalls[0].environment,
    target_ref: runnerCalls[0].target_ref,
  },
  {
    operation_id: 'host.inspect',
    account_ref: 'ssh-operations',
    environment: 'production',
    target_ref: 'prod-broker-ecs',
  },
);
assert.ok(runnerCalls[0].signal instanceof AbortSignal);
assert.equal(Object.hasOwn(runnerCalls[0], 'command'), false);
assert.equal(Object.hasOwn(runnerCalls[0], 'credential'), false);
assert.deepEqual(
  broker.eventsFor(actor, task.id).map((event) => event.state),
  ['REQUESTED', 'READY', 'EXECUTING', 'SUCCEEDED'],
);
assert.ok(events.every((event) => !JSON.stringify(event).includes('typed_parameters')));
assert.ok(events.every((event) => !JSON.stringify(event).includes('private_key')));
await assert.rejects(
  broker.run(actor, task.id),
  (error) => error instanceof V2Error && error.code === 'invalid_state',
);
assert.equal(runnerCalls.length, 1, 'a terminal task cannot replay its SSH capability');

await assert.rejects(
  broker.create(actor, {
    tool: 'ssh.host.inspect',
    tool_version: '1.0.0',
    account_ref: 'ssh-operations',
    environment: 'production',
    idempotency_key: 'ssh-injection-task-0001',
    parameters: { resource_ref: 'prod-broker-ecs', command: 'cat /etc/shadow' },
  }),
  (error) => error instanceof V2Error && error.code === 'schema_mismatch',
);
assert.equal(runnerCalls.length, 1, 'schema rejection occurs before the runner');

console.log('ssh automation loop: policy, token binding, execution, audit and anti-replay passed');
