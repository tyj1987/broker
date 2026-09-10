import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { createCipheriv, randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ControlPlaneStateCoordinator,
  EncryptedControlPlaneStateStore,
  loadControlPlaneStateKey,
} from '../broker/lib/control-plane-state-store.js';

function component(initial) {
  let state = structuredClone(initial);
  return {
    exportState: () => structuredClone(state),
    restoreState: (next) => {
      if (next?.reject === true) throw new Error('rejected state');
      state = structuredClone(next);
    },
  };
}

function code(expected) {
  return (error) => error?.code === expected;
}

function seal(key, payload, generation = 1) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(`secret-broker:control-plane-state:v1:g${generation}`));
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(payload)), cipher.final()]);
  return JSON.stringify({
    version: 1, generation, algorithm: 'A256GCM', iv: iv.toString('base64url'),
    tag: cipher.getAuthTag().toString('base64url'), ciphertext: ciphertext.toString('base64url'),
  });
}

const directory = mkdtempSync(join(tmpdir(), 'broker-state-'));
try {
  const statePath = join(directory, 'control-plane.state');
  const keyPath = join(directory, 'control-plane.key');
  const key = Buffer.alloc(32, 0x42);
  writeFileSync(keyPath, key, { mode: 0o600 });
  assert.deepEqual(loadControlPlaneStateKey(keyPath), key);

  const approvals = component({ version: 1, records: [{ id: 'approval-1' }] });
  const executionTokens = component({ version: 1, records: [{ id: 'execution-1' }] });
  const tasks = component({ version: 1, tasks: [{ id: 'task-1' }], idempotency: [], rate_limits: [] });
  const operations = component({ version: 1, operations: [{ id: 'operation-1' }], otp_tasks: [], used_nonces: [], browser_claims: [], browser_leases: [] });
  const coordinator = new ControlPlaneStateCoordinator({ approvals, executionTokens, tasks, operations, now: () => 1_700_000_000_000 });
  const store = new EncryptedControlPlaneStateStore({ path: statePath, key, coordinator });

  for (const options of [
    {},
    { approvals: { exportState() {} }, executionTokens, tasks, operations },
    { approvals, executionTokens: component({}), tasks: { exportState() {} }, operations },
    { approvals, executionTokens, tasks, operations: { exportState() {} } },
  ]) assert.throws(() => new ControlPlaneStateCoordinator(options), code('state_component_invalid'));
  assert.throws(() => new EncryptedControlPlaneStateStore({ path: 'relative', key, coordinator }), code('state_path_invalid'));
  assert.throws(() => new EncryptedControlPlaneStateStore({ path: statePath, key: 'not-a-buffer', coordinator }), code('state_key_invalid'));
  assert.throws(() => new EncryptedControlPlaneStateStore({ path: statePath, key, coordinator: {} }), code('state_component_invalid'));
  assert.throws(() => new EncryptedControlPlaneStateStore({ path: statePath, key, coordinator, syncDirectory: null }), code('state_component_invalid'));

  assert.equal(store.load({ required: false }), false);
  assert.throws(() => store.load(), code('state_unavailable'));
  const saved = store.save();
  assert.equal(saved.version, 1);
  assert.equal(saved.generation, 1);
  const serialized = readFileSync(statePath, 'utf8');
  assert.ok(!serialized.includes('approval-1'));
  assert.ok(!serialized.includes('execution-1'));
  assert.ok(!serialized.includes('task-1'));
  assert.ok(!serialized.includes('operation-1'));
  assert.deepEqual(readdirSync(directory).sort(), ['control-plane.key', 'control-plane.state']);

  approvals.restoreState({ version: 1, records: [] });
  executionTokens.restoreState({ version: 1, records: [] });
  tasks.restoreState({ version: 1, tasks: [], idempotency: [], rate_limits: [] });
  operations.restoreState({ version: 1, operations: [], otp_tasks: [], used_nonces: [], browser_claims: [], browser_leases: [] });
  assert.equal(store.load(), true);
  assert.deepEqual(approvals.exportState().records, [{ id: 'approval-1' }]);
  assert.deepEqual(executionTokens.exportState().records, [{ id: 'execution-1' }]);
  assert.deepEqual(tasks.exportState().tasks, [{ id: 'task-1' }]);
  assert.deepEqual(operations.exportState().operations, [{ id: 'operation-1' }]);

  store.save();
  assert.equal(JSON.parse(readFileSync(statePath, 'utf8')).generation, 2);
  assert.throws(
    () => coordinator.restoreState({ ...coordinator.exportState(), generation: 1 }),
    code('state_rollback_detected'),
  );
  assert.throws(
    () => coordinator.restoreState({ ...coordinator.exportState(), approvals: [] }),
    code('state_corrupt'),
  );
  const validSnapshot = coordinator.exportState();
  for (const corrupt of [
    null, [], { ...validSnapshot, extra: true }, { ...validSnapshot, version: 99 },
    { ...validSnapshot, generation: 0 }, { ...validSnapshot, captured_at: 'invalid' },
    { ...validSnapshot, execution_tokens: null }, { ...validSnapshot, tasks: [] },
    { ...validSnapshot, operations: [] },
  ]) assert.throws(() => coordinator.restoreState(corrupt), code('state_corrupt'));
  assert.throws(() => coordinator.commitGeneration(99), code('state_generation_invalid'));

  const beforeFailure = approvals.exportState();
  const invalidSnapshot = coordinator.exportState();
  invalidSnapshot.tasks = { reject: true };
  assert.throws(() => coordinator.restoreState(invalidSnapshot), code('state_restore_failed'));
  assert.deepEqual(approvals.exportState(), beforeFailure, 'failed restore must roll back earlier components');

  const tampered = JSON.parse(serialized);
  const tamperedCiphertext = Buffer.from(tampered.ciphertext, 'base64url');
  tamperedCiphertext[0] ^= 0x01;
  tampered.ciphertext = tamperedCiphertext.toString('base64url');
  writeFileSync(statePath, JSON.stringify(tampered));
  assert.throws(() => store.load(), code('state_decrypt_failed'));
  assert.deepEqual(approvals.exportState(), beforeFailure, 'tampered disk state must not alter memory');

  writeFileSync(statePath, serialized);
  assert.throws(() => store.load(), code('state_rollback_detected'));
  const wrongKeyStore = new EncryptedControlPlaneStateStore({
    path: statePath, key: Buffer.alloc(32, 0x24), coordinator,
  });
  assert.throws(() => wrongKeyStore.load(), code('state_decrypt_failed'));
  assert.throws(() => new EncryptedControlPlaneStateStore({ path: statePath, key: Buffer.alloc(31), coordinator }), code('state_key_invalid'));
  assert.throws(() => loadControlPlaneStateKey(join(directory, 'missing.key')), code('state_key_unavailable'));
  const encodedKeyPath = join(directory, 'encoded.key');
  writeFileSync(encodedKeyPath, `${key.toString('base64url')}\n`, { mode: 0o600 });
  assert.deepEqual(loadControlPlaneStateKey(encodedKeyPath), key);
  const invalidKeyPath = join(directory, 'invalid.key');
  writeFileSync(invalidKeyPath, 'not-a-key', { mode: 0o600 });
  assert.throws(() => loadControlPlaneStateKey(invalidKeyPath), code('state_key_invalid'));
  assert.throws(() => loadControlPlaneStateKey('relative.key'), code('state_key_invalid'));
  if (process.platform !== 'win32') {
    const keyLink = join(directory, 'encoded-link.key');
    symlinkSync(encodedKeyPath, keyLink);
    assert.throws(() => loadControlPlaneStateKey(keyLink), code('state_key_unavailable'));
    chmodSync(encodedKeyPath, 0o644);
    assert.throws(() => loadControlPlaneStateKey(encodedKeyPath), code('state_key_unavailable'));
  }
  assert.throws(() => store.load({ required: 'yes' }), code('invalid_request'));

  const freshCoordinator = new ControlPlaneStateCoordinator({
    approvals: component({ version: 1, records: [] }),
    executionTokens: component({ version: 1, records: [] }),
    tasks: component({ version: 1, tasks: [], idempotency: [], rate_limits: [] }),
    operations: component({ version: 1, operations: [], otp_tasks: [], used_nonces: [], browser_claims: [], browser_leases: [] }),
  });
  const legacyOperations = component({
    version: 1, operations: [{ id: 'must-be-cleared' }], otp_tasks: [], used_nonces: [],
    browser_claims: [], browser_leases: [],
  });
  const legacyCoordinator = new ControlPlaneStateCoordinator({
    approvals: component({ version: 1, records: [] }),
    executionTokens: component({ version: 1, records: [] }),
    tasks: component({ version: 1, tasks: [], idempotency: [], rate_limits: [] }),
    operations: legacyOperations,
  });
  legacyCoordinator.restoreState({
    version: 1, generation: 1, captured_at: new Date().toISOString(),
    approvals: { version: 1, records: [] },
    execution_tokens: { version: 1, records: [] },
    tasks: { version: 1, tasks: [], idempotency: [], rate_limits: [] },
  });
  assert.deepEqual(legacyOperations.exportState().operations, [], 'v1 snapshots migrate with empty operation state');
  assert.equal(legacyCoordinator.exportState().version, 2, 'the next checkpoint upgrades the snapshot schema');
  const indeterminatePath = join(directory, 'indeterminate.state');
  const indeterminateApprovals = component({ version: 1, records: [{ id: 'approval-indeterminate' }] });
  const indeterminateCoordinator = new ControlPlaneStateCoordinator({
    approvals: indeterminateApprovals,
    executionTokens: component({ version: 1, records: [] }),
    tasks: component({ version: 1, tasks: [], idempotency: [], rate_limits: [] }),
    operations: component({ version: 1, operations: [], otp_tasks: [], used_nonces: [], browser_claims: [], browser_leases: [] }),
  });
  const indeterminateStore = new EncryptedControlPlaneStateStore({
    path: indeterminatePath, key, coordinator: indeterminateCoordinator,
    syncDirectory: () => { throw new Error('directory fsync failed'); },
  });
  assert.throws(() => indeterminateStore.save(), code('state_commit_indeterminate'));
  assert.equal(indeterminateCoordinator.generation, 1, 'a replaced state file advances the in-memory generation');
  const recoveredApprovals = component({ version: 1, records: [] });
  const recoveredStore = new EncryptedControlPlaneStateStore({
    path: indeterminatePath, key,
    coordinator: new ControlPlaneStateCoordinator({
      approvals: recoveredApprovals,
      executionTokens: component({ version: 1, records: [] }),
      tasks: component({ version: 1, tasks: [], idempotency: [], rate_limits: [] }),
      operations: component({ version: 1, operations: [], otp_tasks: [], used_nonces: [], browser_claims: [], browser_leases: [] }),
    }),
  });
  assert.equal(recoveredStore.load(), true);
  assert.deepEqual(recoveredApprovals.exportState().records, [{ id: 'approval-indeterminate' }]);
  recoveredStore.close();
  indeterminateStore.close();
  const invalidStatePath = join(directory, 'invalid.state');
  const invalidStore = new EncryptedControlPlaneStateStore({ path: invalidStatePath, key, coordinator: freshCoordinator });
  for (const envelope of [
    'not-json', '{}',
    JSON.stringify({ version: 1, generation: 1, algorithm: 'A256GCM', iv: 'bad', tag: 'bad', ciphertext: 'bad' }),
    JSON.stringify({ version: 1, generation: 1, algorithm: 'A256GCM', iv: 'A'.repeat(16), tag: 'A'.repeat(22), ciphertext: 'A' }),
  ]) {
    writeFileSync(invalidStatePath, envelope);
    assert.throws(() => invalidStore.load(), code('state_corrupt'));
  }
  writeFileSync(invalidStatePath, seal(key, '{'));
  assert.throws(() => invalidStore.load(), code('state_corrupt'));
  const freshSnapshot = freshCoordinator.exportState();
  writeFileSync(invalidStatePath, seal(key, JSON.stringify({ ...freshSnapshot, generation: 2 }), 1));
  assert.throws(() => invalidStore.load(), code('state_corrupt'));
  const directoryStore = new EncryptedControlPlaneStateStore({ path: directory, key, coordinator: freshCoordinator });
  assert.throws(() => directoryStore.load(), code('state_unavailable'));
  if (process.platform !== 'win32') {
    const stateLink = join(directory, 'state-link');
    symlinkSync(statePath, stateLink);
    const linkedStore = new EncryptedControlPlaneStateStore({ path: stateLink, key, coordinator: freshCoordinator });
    assert.throws(() => linkedStore.load(), code('state_unavailable'));
  }
  const unwritableStore = new EncryptedControlPlaneStateStore({
    path: join(directory, 'missing-parent', 'state'), key, coordinator: freshCoordinator,
  });
  assert.throws(() => unwritableStore.save(), code('state_write_failed'));
  const oversized = new EncryptedControlPlaneStateStore({
    path: join(directory, 'oversized.state'), key,
    coordinator: new ControlPlaneStateCoordinator({
      approvals: component({ payload: 'x'.repeat(17 * 1024 * 1024) }),
      executionTokens: component({}), tasks: component({}), operations: component({}),
    }),
  });
  assert.throws(() => oversized.save(), code('state_too_large'));

  const rollbackFailure = new ControlPlaneStateCoordinator({
    approvals: { exportState: () => ({}), restoreState: () => { throw new Error('unavailable'); } },
    executionTokens: component({}), tasks: component({}), operations: component({}),
  });
  assert.throws(() => rollbackFailure.restoreState({
    version: 1, generation: 1, captured_at: new Date().toISOString(),
    approvals: {}, execution_tokens: {}, tasks: {},
  }), code('state_rollback_failed'));

  store.close();
  store.close();
  assert.throws(() => store.save(), code('state_store_closed'));
  assert.throws(() => store.load(), code('state_store_closed'));
} finally {
  rmSync(directory, { recursive: true, force: true });
}

console.log('control-plane state store: encrypted atomic persistence and fail-closed recovery passed');
