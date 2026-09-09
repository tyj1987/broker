import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createControlPlaneStateRuntime } from '../broker/lib/control-plane-state-runtime.js';

function component(initial) {
  let state = structuredClone(initial);
  return {
    exportState: () => structuredClone(state),
    restoreState: (next) => { state = structuredClone(next); },
    replace: (next) => { state = structuredClone(next); },
  };
}

const code = (expected) => (error) => error?.code === expected;
const directory = mkdtempSync(join(tmpdir(), 'broker-state-runtime-'));
try {
  const dependencies = () => ({
    approvals: component({ version: 1, records: [{ id: 'approval' }] }),
    executionTokens: component({ version: 1, records: [{ id: 'token' }] }),
    tasks: component({ version: 1, tasks: [{ id: 'task' }], idempotency: [], rate_limits: [] }),
  });
  const disabled = createControlPlaneStateRuntime({ env: {}, ...dependencies() });
  assert.equal(disabled.enabled, false);
  assert.equal(disabled.checkpoint(), false);
  disabled.close();

  assert.throws(
    () => createControlPlaneStateRuntime({ env: { NODE_ENV: 'production' }, ...dependencies() }),
    code('state_configuration_required'),
  );
  assert.throws(
    () => createControlPlaneStateRuntime({ env: { CONTROL_PLANE_STATE_PATH: join(directory, 'partial') }, ...dependencies() }),
    code('state_configuration_invalid'),
  );

  const keyPath = join(directory, 'state.key');
  const statePath = join(directory, 'state.enc');
  writeFileSync(keyPath, Buffer.alloc(32, 0x31), { mode: 0o600 });
  const firstComponents = dependencies();
  const first = createControlPlaneStateRuntime({
    env: { CONTROL_PLANE_STATE_PATH: statePath, CONTROL_PLANE_STATE_KEY_FILE: keyPath },
    ...firstComponents,
  });
  assert.equal(first.enabled, true);
  assert.equal(first.loaded, false);
  assert.equal(first.generation, 1);
  assert.ok(existsSync(statePath));
  firstComponents.approvals.replace({ version: 1, records: [{ id: 'updated' }] });
  assert.equal(first.checkpoint(), true);
  assert.equal(first.generation, 2);
  first.close();
  assert.throws(() => first.checkpoint(), code('state_store_closed'));

  const restoredComponents = dependencies();
  restoredComponents.approvals.replace({ version: 1, records: [] });
  const restored = createControlPlaneStateRuntime({
    env: { NODE_ENV: 'production', CONTROL_PLANE_STATE_PATH: statePath, CONTROL_PLANE_STATE_KEY_FILE: keyPath },
    ...restoredComponents,
  });
  assert.equal(restored.loaded, true);
  assert.equal(restored.generation, 2);
  assert.deepEqual(restoredComponents.approvals.exportState().records, [{ id: 'updated' }]);
  restored.close();

  assert.throws(() => createControlPlaneStateRuntime({
    env: {
      NODE_ENV: 'production',
      CONTROL_PLANE_STATE_PATH: join(directory, 'missing.enc'),
      CONTROL_PLANE_STATE_KEY_FILE: keyPath,
    },
    ...dependencies(),
  }), code('state_unavailable'));

  const serverSource = readFileSync(new URL('../broker/server.js', import.meta.url), 'utf8');
  assert.match(serverSource, /onCheckpoint: checkpointControlPlaneState/);
  assert.match(serverSource, /createControlPlaneStateRuntime\(\{/);
  assert.match(serverSource, /executionTokens: taskBroker\.executionTokens/);
  assert.match(serverSource, /onShutdown: \[\(\) => stopCronLoop\(\), closeControlPlaneState\]/);
} finally {
  rmSync(directory, { recursive: true, force: true });
}

console.log('control-plane state runtime: production fail-closed initialization and restart recovery passed');
