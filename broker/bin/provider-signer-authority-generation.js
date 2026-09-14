#!/usr/bin/env node

import { fileURLToPath } from 'node:url';

import { readProviderSignerAuthorityGenerations } from '../lib/provider-signer-authority-generation.js';

export async function runProviderSignerAuthorityGeneration({
  readGenerations = readProviderSignerAuthorityGenerations,
  writeOutput = (value) => process.stdout.write(`${value}\n`),
} = {}) {
  if (typeof readGenerations !== 'function' || typeof writeOutput !== 'function') {
    throw new TypeError('Provider signer generation command dependencies are invalid');
  }
  const generations = await readGenerations();
  writeOutput(JSON.stringify({ github: generations.github, aliyun: generations.aliyun }));
  return generations;
}

/* c8 ignore start -- exercised by process invocation */
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  runProviderSignerAuthorityGeneration().catch(() => {
    process.exitCode = 65;
  });
}
/* c8 ignore stop */
