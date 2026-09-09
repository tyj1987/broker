import assert from 'node:assert/strict';
import { resolve } from 'node:path';

import {
  createPostgresqlDatabaseInspectAdapter,
  POSTGRESQL_DATABASE_INSPECT_CONTRACT,
} from '../broker/adapters/postgresql-database-inspect.js';
import { ApprovalBroker } from '../broker/lib/approvals-v2.js';
import { AutomationTaskBroker } from '../broker/lib/automation-tasks.js';
import { loadToolRegistry } from '../broker/lib/tool-registry.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const TARGET = 'prod-app-read-replica';
const parameters = { resource_ref: TARGET };
const context = {
  accountRef: 'postgresql-observer',
  environment: 'production',
  execution: {
    tool: 'postgresql.database.inspect@1.0.0',
    target: TARGET,
    environment: 'production',
  },
  signal: new AbortController().signal,
};
const validResult = () => ({
  target_ref: TARGET,
  database: 'broker',
  server_version_num: 180006,
  in_recovery: true,
  current_user: 'broker_observer',
  transaction_read_only: true,
  role_superuser: false,
  role_bypass_rls: false,
  role_create_db: false,
  role_create_role: false,
  role_replication: false,
});
const publicResult = {
  target_ref: TARGET,
  database: 'broker',
  server_version_num: 180006,
  in_recovery: true,
  current_user: 'broker_observer',
  read_only_enforced: true,
};
const expectCode = (code) => (error) => error instanceof V2Error && error.code === code;

let runnerInput;
const adapter = createPostgresqlDatabaseInspectAdapter({
  runner: async (input) => {
    runnerInput = input;
    return validResult();
  },
});
assert.deepEqual(await adapter(parameters, context), publicResult);
assert.deepEqual(runnerInput, {
  query_id: 'database.inspect.v1',
  account_ref: 'postgresql-observer',
  environment: 'production',
  target_ref: TARGET,
  transaction: 'read_only',
  statement_timeout_ms: 5000,
  lock_timeout_ms: 1000,
  maximum_rows: 1,
  signal: context.signal,
});
assert.equal(Object.hasOwn(runnerInput, 'sql'), false);
assert.equal(Object.hasOwn(runnerInput, 'credential'), false);

assert.throws(() => createPostgresqlDatabaseInspectAdapter(), TypeError);
for (const changed of [null, {}, { resource_ref: '' }, { resource_ref: '../database' }]) {
  await assert.rejects(
    adapter(changed, context),
    (error) =>
      error instanceof V2Error &&
      ['postgresql_invalid_request', 'postgresql_invalid_target'].includes(error.code),
  );
}
for (const injected of [
  { ...parameters, sql: 'DROP TABLE users' },
  { ...parameters, query: 'SELECT pg_read_file(...)' },
  { ...parameters, parameters: ['anything'] },
]) {
  await assert.rejects(adapter(injected, context), expectCode('postgresql_invalid_request'));
}
for (const execution of [
  { ...context.execution, tool: 'postgresql.query.run@1.0.0' },
  { ...context.execution, target: 'other-database' },
  { ...context.execution, environment: 'staging' },
]) {
  await assert.rejects(
    adapter(parameters, { ...context, execution }),
    expectCode('postgresql_execution_binding_mismatch'),
  );
}
await assert.rejects(
  adapter(parameters, { ...context, accountRef: '' }),
  expectCode('postgresql_account_unavailable'),
);

const withResult = (result) =>
  createPostgresqlDatabaseInspectAdapter({ runner: async () => result });
for (const result of [
  null,
  { ...validResult(), target_ref: 'other-database' },
  { ...validResult(), database: '../broker' },
  { ...validResult(), current_user: 'bad user' },
  { ...validResult(), server_version_num: 99999 },
  { ...validResult(), in_recovery: 'yes' },
  { ...validResult(), unexpected_rows: ['canary-secret'] },
]) {
  await assert.rejects(
    withResult(result)(parameters, context),
    (error) =>
      error instanceof V2Error &&
      ['postgresql_invalid_response', 'postgresql_scope_mismatch'].includes(error.code) &&
      !error.message.includes('canary'),
  );
}
for (const changed of [
  { transaction_read_only: false },
  { transaction_read_only: 'on' },
  { role_superuser: true },
  { role_bypass_rls: true },
  { role_create_db: true },
  { role_create_role: true },
  { role_replication: true },
]) {
  await assert.rejects(
    withResult({ ...validResult(), ...changed })(parameters, context),
    expectCode('postgresql_read_only_boundary_failed'),
  );
}
await assert.rejects(
  createPostgresqlDatabaseInspectAdapter({
    runner: async () => {
      throw new Error('postgresql://user:canary-password@database');
    },
  })(parameters, context),
  (error) =>
    expectCode('postgresql_runner_unavailable')(error) && !error.message.includes('canary'),
);

const registry = loadToolRegistry(resolve(import.meta.dirname, '../tools/registry.json'));
const events = [];
let calls = 0;
const taskBroker = new AutomationTaskBroker({
  toolRegistry: registry,
  authorize: async (operation) => ({
    allow:
      operation.provider === 'postgresql' &&
      operation.operationId === 'database.inspect' &&
      operation.accountRef === 'postgresql-observer' &&
      operation.environment === 'production' &&
      operation.typedParameters?.resource_ref === TARGET,
    ttlMs: 60_000,
  }),
  approvalBroker: new ApprovalBroker(),
  executors: new Map([
    [
      'postgresql.database.inspect@1.0.0',
      createPostgresqlDatabaseInspectAdapter({
        runner: async (input) => {
          calls += 1;
          return { ...validResult(), target_ref: input.target_ref };
        },
      }),
    ],
  ]),
  onEvent: (event) => events.push(event),
});
const actor = {
  name: 'database-agent',
  context: {
    via: 'workload_identity',
    client: { role: 'operator', principal_type: 'workload', security_profile: 'strict' },
  },
};
const task = await taskBroker.create(actor, {
  tool: 'postgresql.database.inspect',
  tool_version: '1.0.0',
  account_ref: 'postgresql-observer',
  environment: 'production',
  idempotency_key: 'postgresql-inspect-task-0001',
  parameters,
});
assert.equal(task.state, 'READY');
const completed = await taskBroker.run(actor, task.id);
assert.equal(completed.state, 'SUCCEEDED');
assert.deepEqual(completed.result, publicResult);
assert.equal(calls, 1);
assert.deepEqual(
  taskBroker.eventsFor(actor, task.id).map((event) => event.state),
  ['REQUESTED', 'READY', 'EXECUTING', 'SUCCEEDED'],
);
for (const event of events) {
  const encoded = JSON.stringify(event);
  assert.equal(encoded.includes('DROP TABLE'), false);
  assert.equal(encoded.includes('postgresql://'), false);
  assert.equal(encoded.includes('typed_parameters'), false);
}
await assert.rejects(taskBroker.run(actor, task.id), expectCode('invalid_state'));
assert.equal(calls, 1);

assert.deepEqual(POSTGRESQL_DATABASE_INSPECT_CONTRACT, {
  tool: 'postgresql.database.inspect@1.0.0',
  query_id: 'database.inspect.v1',
  arbitrary_sql: false,
  credential_export: false,
  transaction: 'read_only',
  statement_timeout_ms: 5000,
  lock_timeout_ms: 1000,
  maximum_rows: 1,
  forbidden_role_attributes: ['SUPERUSER', 'BYPASSRLS', 'CREATEDB', 'CREATEROLE', 'REPLICATION'],
});

console.log('postgresql inspect: fixed query, role boundary and automation loop passed');
