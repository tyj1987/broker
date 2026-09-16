#!/usr/bin/env node
// One bounded iteration. The native parent owns timing, identity and readiness.
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { performance } from 'node:perf_hooks';
import { readAuditAnchorExporterConfig, createAuditAnchorExporterRuntime } from '../lib/audit-anchor-exporter-runtime.js';
import { readAuditRecoveryChainSnapshot } from '../lib/audit-recovery-chain.js';
import { createLocalAuditAnchorSignerClient } from '../lib/local-audit-anchor-signer-client.js';
import { createLocalAuditAnchorStoreClient } from '../lib/local-audit-anchor-store-client.js';

export const EXPORTER_CONFIG = '/etc/secret-broker/audit/exporter.json';
const unavailable = () => { throw new Error('Audit exporter iteration unavailable'); };

export async function runExporterServiceCheck(argv, {
  readConfig = readAuditAnchorExporterConfig,
  createSigner = createLocalAuditAnchorSignerClient,
  createStore = createLocalAuditAnchorStoreClient,
  readSnapshot = readAuditRecoveryChainSnapshot,
  now = () => Date.now(), signal,
  writeOutput = value => process.stdout.write(value),
} = {}) {
  if (!Array.isArray(argv) || argv.length !== 2 || argv[0] !== '--config' || argv[1] !== EXPORTER_CONFIG
    || (signal !== undefined && !(signal instanceof AbortSignal)) || signal?.aborted) unavailable();
  // The production reader accepts only the protected, root-managed fixed file.
  const config = await readConfig(EXPORTER_CONFIG);
  if (signal?.aborted) unavailable();
  const deadline = new AbortController();
  const combined = signal ? AbortSignal.any([signal, deadline.signal]) : deadline.signal;
  const endsAt = performance.now() + config.exportDeadlineMs;
  const timer = setTimeout(() => deadline.abort(), config.exportDeadlineMs);
  const check = () => { if (combined.aborted || performance.now() >= endsAt) unavailable(); };
  const bounded = operation => new Promise((accept, reject) => {
    const abort = () => reject(new Error('Audit exporter iteration unavailable'));
    if (combined.aborted) { abort(); return; }
    combined.addEventListener('abort', abort, { once: true });
    Promise.resolve().then(() => { check(); return operation(); }).then(accept, reject)
      .finally(() => combined.removeEventListener('abort', abort));
  });
  try {
    check();
    const proof = readSnapshot(config.auditDirectory, { signal: combined, deadlineMs: config.exportDeadlineMs });
    check();
    const { files, count, lastHash } = proof(0);
    const signer = createSigner({ algorithm: config.algorithm, keyId: config.activeKeyId, timeoutMs: config.signerTimeoutMs });
    const store = createStore({ streamId: config.streamId, timeoutMs: config.storeTimeoutMs });
    const runtime = createAuditAnchorExporterRuntime({ config, signer, store,
      loadChainState: async () => ({ files, count, lastHash }), loadChainProof: async n => proof(n), now });
    const result = await bounded(() => runtime.exportOnce({ signal: combined }));
    check();
    // A publish receipt alone is not readiness. Re-read the store once without
    // another signing/publish attempt and require the same verified envelope.
    const retained = await bounded(() => store.readHead({ streamId: config.streamId, signal: combined }));
    check();
    if (!isDeepStrictEqual(retained?.current, result.envelope)) unavailable();
    const sequence = result.envelope.payload.sequence;
    if (sequence === 1 ? retained.previous !== null
      : retained.previous?.payload_digest !== result.envelope.payload.previous_anchor_digest) unavailable();
    const report = Object.freeze({ status: 'anchor_verified', sequence, interval_ms: config.intervalMs });
    writeOutput(JSON.stringify(report) + '\n');
    return report;
  } catch { unavailable(); }
  finally { clearTimeout(timer); }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  const shutdown = new AbortController();
  const stop = () => shutdown.abort();
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  try { await runExporterServiceCheck(process.argv.slice(2), { signal: shutdown.signal }); }
  catch { console.error('{"status":"failed","code":"anchor_exporter_failed"}'); process.exitCode = 1; }
  finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
