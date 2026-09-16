#!/usr/bin/env node

import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { readProtectedInputFile } from '../lib/protected-input-file.js';
import { readAuditRecoveryChainSnapshot } from '../lib/audit-recovery-chain.js';
import { createLocalAuditAnchorStoreClient } from '../lib/local-audit-anchor-store-client.js';
import { AUDIT_RECOVERY_CHECK_LIMITS, parseAuditRecoveryConfig, parseAuditRecoveryCheckpoint,
  verifyAuditRecoveryCheckpoint, safeAuditRecoveryCheckCode } from '../lib/audit-recovery-check.js';

export async function runAuditRecoveryCheck(argv = process.argv.slice(2), {
  readFile = readProtectedInputFile,
  createStore = createLocalAuditAnchorStoreClient,
  createProofReader = readAuditRecoveryChainSnapshot,
  now = () => Date.now(),
  signal,
  writeOutput = value => process.stdout.write(value),
} = {}) {
  if (!Array.isArray(argv) || argv.length !== 4) throw new Error('Invalid recovery check arguments');
  const args = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    if (!['--config-file', '--checkpoint-file'].includes(name) || args.has(name)
      || typeof argv[index + 1] !== 'string') throw new Error('Invalid recovery check arguments');
    args.set(name, argv[index + 1]);
  }
  if (args.get('--config-file') === args.get('--checkpoint-file')) throw new Error('Invalid recovery check arguments');
  const config = parseAuditRecoveryConfig(readFile(args.get('--config-file'), 'Recovery configuration',
    AUDIT_RECOVERY_CHECK_LIMITS.config_bytes, { sensitive: true }));
  const checkpoint = parseAuditRecoveryCheckpoint(readFile(args.get('--checkpoint-file'), 'Recovery checkpoint',
    AUDIT_RECOVERY_CHECK_LIMITS.checkpoint_bytes, { sensitive: true }));
  // Store creation is lazy: checkpoint/time/signal checks precede even the first
  // socket operation. The adapter exposes only reads to the verifier.
  let client;
  let proofReader;
  const getClient = () => client ??= createStore({ streamId: config.streamId, timeoutMs: config.storeTimeoutMs });
  const report = await verifyAuditRecoveryCheckpoint({ config, checkpoint, now, signal,
    store: {
      readHead: request => getClient().readHead(request),
      readPage: request => getClient().readPage(request),
    },
    loadChainProof: async (count, options) => {
      proofReader ??= createProofReader(config.auditDirectory, { signal: options.signal, deadlineMs: config.deadlineMs });
      return proofReader(count);
    },
  });
  writeOutput(JSON.stringify(report) + '\n');
  return report;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  const shutdown = new AbortController();
  const stop = () => shutdown.abort();
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  try { await runAuditRecoveryCheck(process.argv.slice(2), { signal: shutdown.signal }); }
  catch (error) {
    console.error(JSON.stringify({ status: 'failed', code: safeAuditRecoveryCheckCode(error) }));
    process.exitCode = 1;
  } finally {
    process.removeListener('SIGINT', stop);
    process.removeListener('SIGTERM', stop);
  }
}
