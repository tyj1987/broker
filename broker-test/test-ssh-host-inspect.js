import assert from 'node:assert/strict';

import {
  createSshHostInspectAdapter,
  SSH_HOST_INSPECT_CONTRACT,
} from '../broker/adapters/ssh-host-inspect.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const TARGET = 'prod-broker-ecs';
const parameters = { resource_ref: TARGET };
const context = {
  accountRef: 'ssh-operations',
  environment: 'production',
  execution: { tool: 'ssh.host.inspect@1.0.0', target: TARGET, environment: 'production' },
  signal: new AbortController().signal,
};
const validResult = () => ({
  target_ref: TARGET,
  hostname: 'broker-ecs.internal',
  uptime_seconds: 86400,
  load_1m: 0.25,
  disk_used_percent: 42.5,
  service_state: 'active',
});
const expectCode = (code) => (error) => error instanceof V2Error && error.code === code;

let runnerInput;
const adapter = createSshHostInspectAdapter({
  runner: async (input) => {
    runnerInput = input;
    return { ...validResult() };
  },
});
assert.deepEqual(await adapter(parameters, context), validResult());
assert.deepEqual(runnerInput, {
  operation_id: 'host.inspect',
  account_ref: 'ssh-operations',
  environment: 'production',
  target_ref: TARGET,
  signal: context.signal,
});
assert.equal(Object.hasOwn(runnerInput, 'command'), false);
assert.equal(Object.hasOwn(runnerInput, 'credential'), false);

assert.throws(() => createSshHostInspectAdapter(), TypeError);
for (const changed of [
  null,
  {},
  { resource_ref: '' },
  { resource_ref: '../prod' },
  { resource_ref: 1 },
]) {
  await assert.rejects(
    adapter(changed, context),
    expectCode(
      changed === null || changed === undefined || Object.keys(changed).length === 0
        ? 'ssh_invalid_request'
        : 'ssh_invalid_target',
    ),
  );
}
for (const injected of [
  { ...parameters, command: 'cat /etc/shadow' },
  { ...parameters, timeout: 0 },
  { resource_ref: TARGET, __proto_pollution: true },
]) {
  await assert.rejects(adapter(injected, context), expectCode('ssh_invalid_request'));
}
for (const execution of [
  { ...context.execution, tool: 'ssh.exec@1.0.0' },
  { ...context.execution, target: 'other-host' },
  { ...context.execution, environment: 'staging' },
]) {
  await assert.rejects(
    adapter(parameters, { ...context, execution }),
    expectCode('ssh_execution_binding_mismatch'),
  );
}
await assert.rejects(
  adapter(parameters, { ...context, accountRef: '' }),
  expectCode('ssh_account_unavailable'),
);

const withResult = (result) => createSshHostInspectAdapter({ runner: async () => result });
for (const result of [
  null,
  { ...validResult(), target_ref: 'other-host' },
  { ...validResult(), hostname: '../bad' },
  { ...validResult(), uptime_seconds: -1 },
  { ...validResult(), uptime_seconds: 1.5 },
  { ...validResult(), load_1m: Number.NaN },
  { ...validResult(), disk_used_percent: 101 },
  { ...validResult(), service_state: 'starting' },
  { ...validResult(), private_key: 'canary-private-key' },
]) {
  await assert.rejects(
    withResult(result)(parameters, context),
    (error) =>
      error instanceof V2Error &&
      ['ssh_invalid_response', 'ssh_scope_mismatch'].includes(error.code) &&
      !error.message.includes('canary'),
  );
}
await assert.rejects(
  createSshHostInspectAdapter({
    runner: async () => {
      throw new Error('canary-private-key');
    },
  })(parameters, context),
  (error) => expectCode('ssh_runner_unavailable')(error) && !error.message.includes('canary'),
);

assert.deepEqual(SSH_HOST_INSPECT_CONTRACT, {
  tool: 'ssh.host.inspect@1.0.0',
  operation_id: 'host.inspect',
  input_fields: ['resource_ref'],
  output_fields: [
    'target_ref',
    'hostname',
    'uptime_seconds',
    'load_1m',
    'disk_used_percent',
    'service_state',
  ],
  arbitrary_command: false,
  credential_export: false,
  required_host_key_checking: 'strict',
});

console.log('ssh host inspect: target binding, typed output and secret isolation passed');
