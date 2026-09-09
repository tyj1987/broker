import { V2Error } from './operations-v2.js';
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

export function createControlPlaneStateRuntime({
  env = process.env,
  approvals,
  executionTokens,
  tasks,
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
  if (typeof statePath !== 'string' || statePath.length < 1
    || typeof keyPath !== 'string' || keyPath.length < 1) {
    throw new V2Error(
      'state_configuration_invalid',
      'control-plane state path and key file must be configured together',
      503,
    );
  }

  const key = loadControlPlaneStateKey(keyPath);
  let store;
  try {
    const coordinator = new ControlPlaneStateCoordinator({ approvals, executionTokens, tasks, now });
    store = new EncryptedControlPlaneStateStore({ path: statePath, key, coordinator });
    const loaded = store.load({ required: production });
    if (!loaded) store.save();
    let closed = false;
    return {
      enabled: true,
      loaded,
      get generation() { return coordinator.generation; },
      checkpoint() {
        if (closed) throw new V2Error('state_store_closed', 'control-plane state store is closed', 503);
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
