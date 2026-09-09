#!/usr/bin/env node

import { initializeControlPlaneState } from '../lib/control-plane-state-runtime.js';

try {
  const result = initializeControlPlaneState();
  console.log(
    `[state] initialized encrypted control-plane state (generation=${result.generation})`,
  );
} catch (error) {
  console.error(`[state] initialization failed (${error?.code || 'state_initialization_failed'})`);
  process.exitCode = 1;
}
