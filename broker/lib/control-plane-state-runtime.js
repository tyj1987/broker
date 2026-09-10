import { V2Error } from './operations-v2.js';
import { existsSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import {
  ControlPlaneStateCoordinator,
  EncryptedControlPlaneStateStore,
  loadControlPlaneStateKey,
} from './control-plane-state-store.js';

function disabledRuntime() {
  return Object.freeze({
    enabled: false,
    loaded: false,
    generation: 0,
    checkpoint: () => false,
    close: () => {},
  });
}

function configuredPaths(env) {
  const statePath = env?.CONTROL_PLANE_STATE_PATH;
  const keyPath = env?.CONTROL_PLANE_STATE_KEY_FILE;
  if (
    typeof statePath !== 'string' ||
    statePath.length < 1 ||
    !isAbsolute(statePath) ||
    typeof keyPath !== 'string' ||
    keyPath.length < 1 ||
    !isAbsolute(keyPath)
  ) {
    throw new V2Error(
      'state_configuration_invalid',
      'control-plane state path and key file must be configured together',
      503,
    );
  }
  return { statePath, keyPath };
}

function emptyStateComponent(snapshot) {
  return {
    exportState: () => structuredClone(snapshot),
    restoreState: () => {},
  };
}

export function initializeControlPlaneState({ env = process.env, now = () => Date.now() } = {}) {
  const { statePath, keyPath } = configuredPaths(env);
  if (existsSync(statePath)) {
    throw new V2Error('state_already_initialized', 'control-plane state already exists', 409);
  }
  const key = loadControlPlaneStateKey(keyPath);
  let store;
  try {
    const coordinator = new ControlPlaneStateCoordinator({
      approvals: emptyStateComponent({ version: 1, records: [] }),
      executionTokens: emptyStateComponent({ version: 1, records: [] }),
      tasks: emptyStateComponent({ version: 1, tasks: [], idempotency: [], rate_limits: [] }),
      operations: emptyStateComponent({
        version: 1, operations: [], otp_tasks: [], used_nonces: [], browser_claims: [], browser_leases: [],
      }),
      now,
    });
    store = new EncryptedControlPlaneStateStore({ path: statePath, key, coordinator });
    const result = store.save();
    return Object.freeze({ initialized: true, generation: result.generation });
  } finally {
    store?.close();
    key.fill(0);
  }
}

export function createControlPlaneStateRuntime({
  env = process.env,
  approvals,
  executionTokens,
  tasks,
  operations,
  now = () => Date.now(),
} = {}) {
  const statePath = env?.CONTROL_PLANE_STATE_PATH;
  const keyPath = env?.CONTROL_PLANE_STATE_KEY_FILE;
  const production = env?.NODE_ENV === 'production';
  if (!statePath && !keyPath) {
    if (production) {
      throw new V2Error(
        'state_configuration_required',
        'production requires encrypted control-plane state configuration',
        503,
      );
    }
    return disabledRuntime();
  }
  configuredPaths(env);

  const key = loadControlPlaneStateKey(keyPath);
  let store;
  try {
    const coordinator = new ControlPlaneStateCoordinator({
      approvals,
      executionTokens,
      tasks,
      operations,
      now,
    });
    store = new EncryptedControlPlaneStateStore({ path: statePath, key, coordinator });
    const loaded = store.load({ required: production });
    if (!loaded) store.save();
    let closed = false;
    return {
      enabled: true,
      loaded,
      get generation() {
        return coordinator.generation;
      },
      checkpoint() {
        if (closed)
          throw new V2Error('state_store_closed', 'control-plane state store is closed', 503);
        store.save();
        return true;
      },
      close() {
        if (closed) return;
        store.close();
        closed = true;
      },
    };
  } catch (error) {
    store?.close();
    throw error;
  } finally {
    key.fill(0);
  }
}
