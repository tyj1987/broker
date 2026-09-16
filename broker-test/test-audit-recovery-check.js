import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, chmodSync, symlinkSync, linkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { parseAuditRecoveryConfig, parseAuditRecoveryCheckpoint, verifyAuditRecoveryCheckpoint,
  safeAuditRecoveryCheckCode, AuditRecoveryCheckError, AUDIT_RECOVERY_CHECK_LIMITS } from '../broker/lib/audit-recovery-check.js';
import { readAuditRecoveryChainSnapshot, AUDIT_RECOVERY_CHAIN_LIMITS } from '../broker/lib/audit-recovery-chain.js';
import { runAuditRecoveryCheck } from '../broker/bin/audit-recovery-check.js';
import { createAuditAnchorRecoveryVerifier } from '../broker/lib/audit-anchor-recovery.js';
import { createAuditAnchorRequest, createAuditAnchorSigningInput, attachAuditAnchorSignature } from '../broker/lib/audit-anchor.js';
import { sealEvent, GENESIS_HASH, loadAuditChainProofSync } from '../broker/lib/audit-hash-chain.js';

let passed = 0;
async function test(name, run) { await run(); passed += 1; console.log(`PASS ${name}`); }
const json = value => Buffer.from(JSON.stringify(value));
const code = expected => error => error instanceof AuditRecoveryCheckError && error.code === expected
  && error.message === 'Audit recovery check failed';
const CLI = fileURLToPath(new URL('../broker/bin/audit-recovery-check.js', import.meta.url));
const T = 1_900_000_000_000;
const streamId = 'recovery-test';
const keyId = 'test-key';
const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const der = publicKey.export({ type: 'spki', format: 'der' });
const pin = bytes => ({ key_id: keyId, public_key_spki_der_base64: bytes.toString('base64'),
  public_key_sha256: createHash('sha256').update(bytes).digest('hex') });
const work = mkdtempSync(join(tmpdir(), 'broker-recovery-check-'));
const auditDir = join(work, 'audit');
mkdirSync(auditDir, { mode: 0o700 });
const document = { version: 1, purpose: 'secret-broker.audit-recovery-check', stream_id: streamId,
  audit_directory: auditDir, trusted_keys: [pin(der)], revoked_key_ids: [], store_timeout_ms: 100,
  deadline_ms: 5000, page_size: 2, max_anchors: 100 };
const config = parseAuditRecoveryConfig(json(document));
const events = [];
const anchors = [];
for (let index = 0; index < 3; index += 1) {
  events.push(sealEvent({ id: `event-${index}`, action: 'synthetic-event' }, events.at(-1)?.hash ?? GENESIS_HASH));
  const request = createAuditAnchorRequest({ files: 1, count: events.length, lastHash: events.at(-1).hash },
    { streamId, sequence: index + 1, previousAnchorDigest: anchors.at(-1)?.payload_digest ?? GENESIS_HASH, now: () => T - 3000 + index * 1000 });
  const algorithm = 'ecdsa-p256-sha256';
  anchors.push(attachAuditAnchorSignature(request, { algorithm, key_id: keyId,
    value: sign('sha256', createAuditAnchorSigningInput(request, { algorithm, keyId }), privateKey).toString('base64url') }));
}
const auditPath = join(auditDir, 'audit-chain-test.jsonl');
const auditBytes = events.map(event => JSON.stringify(event)).join('\n') + '\n';
writeFileSync(auditPath, auditBytes, { mode: 0o600 });
const checkpointDocument = { version: 1, purpose: 'secret-broker.audit-recovery-checkpoint', stream_id: streamId,
  sequence: 3, payload_digest: anchors.at(-1).payload_digest, issued_at_ms: T - 1000, expires_at_ms: T + 10_000 };
const checkpoint = parseAuditRecoveryCheckpoint(json(checkpointDocument));
function memoryStore(values = anchors) {
  return {
    readHead: async () => ({ current: values.at(-1) ?? null, previous: values.at(-2) ?? null }),
    readPage: async ({ afterSequence, throughSequence, limit }) => ({ anchors: values.filter(a => a.payload.sequence > afterSequence && a.payload.sequence <= throughSequence).slice(0, limit) }),
    publish() { assert.fail('read-only recovery must never publish'); },
  };
}
const defaults = { config, checkpoint, store: memoryStore(), now: () => T,
  loadChainProof: async count => loadAuditChainProofSync(auditDir, count) };
const run = overrides => verifyAuditRecoveryCheckpoint({ ...defaults, ...overrides });
try {
  await test('exact independent checkpoint and real local chain verify', async () => {
    const report = await run();
    assert.deepEqual(report, { status: 'checkpoint_verified', anchors_verified: 3, sequence: 3, checkpoint_match: true });
    assert.equal(Object.isFrozen(report), true);
    for (const secret of [streamId, keyId, auditDir, checkpoint.payload_digest, 'synthetic-event']) assert.equal(JSON.stringify(report).includes(secret), false);
  });
  await test('configuration and checkpoint snapshots are frozen and branded', async () => {
    assert.ok(Object.isFrozen(config) && Object.isFrozen(checkpoint));
    await assert.rejects(run({ config: { ...config } }), code('recovery_checkpoint_invalid'));
    await assert.rejects(run({ checkpoint: { ...checkpoint } }), code('recovery_checkpoint_invalid'));
    await assert.rejects(verifyAuditRecoveryCheckpoint(), code('recovery_checkpoint_invalid'));
  });
  for (const input of [null, '', Buffer.alloc(0), Buffer.alloc(32 * 1024 + 1), Buffer.from([0xff]), Buffer.from('{'), Buffer.from('version: 1'), Buffer.from('{"version":1,"version":1}')]) {
    await test('configuration syntax rejected', () => assert.throws(() => parseAuditRecoveryConfig(input), code('recovery_config_invalid')));
  }
  const invalidConfigs = [null, [], {}, { ...document, extra: 'forbidden' },
    ...Object.keys(document).map(key => ({ ...document, [key]: null })),
    { ...document, version: 2 }, { ...document, purpose: 'wrong' }, { ...document, stream_id: '' },
    ...['relative', auditDir + '/../audit', '/bad\npath', '/' + 'x'.repeat(4097)].map(audit_directory => ({ ...document, audit_directory })),
    { ...document, trusted_keys: [] }, { ...document, trusted_keys: Array(9).fill(pin(der)) },
    { ...document, trusted_keys: [pin(der), pin(der)] }, { ...document, revoked_key_ids: Array(9).fill('retired') },
    { ...document, revoked_key_ids: [''] }, { ...document, revoked_key_ids: ['retired', 'retired'] }];
  for (const [field, minimum, maximum] of [['store_timeout_ms', 100, 5000], ['deadline_ms', 100, 60_000], ['page_size', 1, 32], ['max_anchors', 1, 1_000_000]]) {
    for (const value of [minimum - 1, maximum + 1, minimum + 0.5, String(minimum)]) invalidConfigs.push({ ...document, [field]: value });
  }
  for (const invalid of invalidConfigs) await test('configuration schema/bound rejected', () => assert.throws(() => parseAuditRecoveryConfig(json(invalid)), code('recovery_config_invalid')));
  const otherKeyTypes = ['P-384', 'RSA'];
  const otherPins = otherKeyTypes.map(type => pin((type === 'RSA' ? generateKeyPairSync('rsa', { modulusLength: 2048 })
    : generateKeyPairSync('ec', { namedCurve: type })).publicKey.export({ type: 'spki', format: 'der' })));
  for (const entry of [null, [], {}, { ...pin(der), extra: true }, { ...pin(der), key_id: '' },
    { ...pin(der), public_key_spki_der_base64: null }, { ...pin(der), public_key_spki_der_base64: '' },
    { ...pin(der), public_key_spki_der_base64: 'A'.repeat(1025) },
    { ...pin(der), public_key_sha256: '0'.repeat(64) }, { ...pin(der), public_key_sha256: 'f'.repeat(64) },
    { ...pin(der), public_key_spki_der_base64: pin(der).public_key_spki_der_base64 + '\n' },
    { ...pin(der), public_key_spki_der_base64: '====' }, pin(Buffer.alloc(513, 1)), pin(Buffer.from('non-DER')), ...otherPins]) {
    await test('public key pin rejected', () => assert.throws(() => parseAuditRecoveryConfig(json({ ...document, trusted_keys: [entry] })), code('recovery_config_invalid')));
  }
  for (const input of [null, '', Buffer.alloc(0), Buffer.alloc(4097), Buffer.from([0xff]), Buffer.from('{'), Buffer.from('version: 1')]) {
    await test('checkpoint syntax rejected', () => assert.throws(() => parseAuditRecoveryCheckpoint(input), code('recovery_checkpoint_invalid')));
  }
  for (const invalid of [null, [], {}, ...Object.keys(checkpointDocument).map(key => ({ ...checkpointDocument, [key]: null })),
    { ...checkpointDocument, extra: 'forbidden' }, { ...checkpointDocument, version: 2 }, { ...checkpointDocument, purpose: 'wrong' },
    { ...checkpointDocument, sequence: 0 }, { ...checkpointDocument, sequence: 1_000_001 }, { ...checkpointDocument, sequence: '3' },
    { ...checkpointDocument, stream_id: '' }, { ...checkpointDocument, payload_digest: '0'.repeat(64) },
    { ...checkpointDocument, payload_digest: 'F'.repeat(64) }, { ...checkpointDocument, expires_at_ms: T - 2000 },
    { ...checkpointDocument, expires_at_ms: T + 3_600_001 }]) {
    await test('checkpoint schema/bound rejected', () => assert.throws(() => parseAuditRecoveryCheckpoint(json(invalid)), code('recovery_checkpoint_invalid')));
  }
  await test('nested duplicate public key property rejected', () => assert.throws(() => parseAuditRecoveryConfig(Buffer.from(JSON.stringify(document).replace('"key_id":"test-key"', '"key_id":"test-key","key_id":"test-key"'))), code('recovery_config_invalid')));
  await test('duplicate checkpoint field rejected', () => assert.throws(() => parseAuditRecoveryCheckpoint(Buffer.from(JSON.stringify(checkpointDocument).replace('"sequence":3', '"sequence":3,"sequence":3'))), code('recovery_checkpoint_invalid')));
  for (const now of [null, () => NaN, () => T - 2000, () => { throw new Error('synthetic detail'); }]) {
    await test('invalid/future clock fails before store I/O', async () => {
      let reads = 0;
      await assert.rejects(run({ now, store: { readHead: async () => { reads++; }, readPage() {} } }), code('recovery_checkpoint_invalid'));
      assert.equal(reads, 0);
    });
  }
  await test('expiry boundary is exclusive', () => assert.rejects(run({ now: () => checkpoint.expires_at_ms }), code('recovery_checkpoint_expired')));
  await test('checkpoint stream mismatch rejected', () => assert.rejects(run({ checkpoint: parseAuditRecoveryCheckpoint(json({ ...checkpointDocument, stream_id: 'other-stream' })) }), code('recovery_checkpoint_invalid')));
  await test('checkpoint exceeds anchor cap rejected', () => assert.rejects(run({ config: parseAuditRecoveryConfig(json({ ...document, max_anchors: 2 })) }), code('recovery_checkpoint_invalid')));
  for (const invalid of [{ store: null }, { store: {} }, { store: { readHead() {}, readPage: null } }, { loadChainProof: null }, { signal: {} }]) {
    await test('invalid verifier dependencies rejected', () => assert.rejects(run(invalid), code('recovery_check_failed')));
  }
  await test('old self-consistent chain is not independent freshness evidence', async () => {
    const oldStore = memoryStore(anchors.slice(0, 1));
    const legacy = createAuditAnchorRecoveryVerifier({ streamId, store: oldStore,
      loadChainProof: defaults.loadChainProof, trustedKeyIds: new Set([keyId]),
      verifySignature: ({ signingInput, signature }) => verify('sha256', signingInput, publicKey, signature) });
    assert.equal((await legacy.verifyRecovery()).status, 'verified');
    await assert.rejects(run({ store: oldStore }), code('recovery_checkpoint_mismatch'));
  });
  for (const head of [{ current: null, previous: null }, null, {},
    { current: anchors[0], previous: null },
    { current: { ...anchors[2], payload_digest: 'a'.repeat(64) }, previous: anchors[1] },
    { current: { ...anchors[2], payload: { ...anchors[2].payload, stream_id: 'other' } }, previous: anchors[1] }]) {
    await test('bad/replayed head stops before pagination', async () => {
      let pages = 0;
      await assert.rejects(run({ store: { readHead: async () => head, readPage: async () => { pages++; } } }), code('recovery_checkpoint_mismatch'));
      assert.equal(pages, 0);
    });
  }
  await test('provider error is generic', () => assert.rejects(run({ store: { readHead: async () => { throw new Error('synthetic detail'); }, readPage() {} } }), code('recovery_check_failed')));
  const changed = structuredClone(anchors); changed[1].signature.value = Buffer.alloc(64).toString('base64url');
  await test('corrupt signed anchor rejected', () => assert.rejects(run({ store: memoryStore(changed) }), code('recovery_check_failed')));
  await test('revoked signing key rejected', () => assert.rejects(run({ config: parseAuditRecoveryConfig(json({ ...document, revoked_key_ids: [keyId] })) }), code('recovery_check_failed')));
  await test('proof error never leaks detail', () => assert.rejects(run({ loadChainProof: async () => { throw new Error('synthetic detail'); } }), code('recovery_check_failed')));
  await test('missing intermediate page rejected', () => assert.rejects(run({ store: { ...memoryStore(), readPage: async () => ({ anchors: [] }) } }), code('recovery_check_failed')));
  await test('store mutation cannot change the frozen head or page', async () => {
    const values = structuredClone(anchors);
    const store = memoryStore(values);
    const report = await run({ store, loadChainProof: async count => {
      values[0].payload.stream_id = 'mutated-outside-snapshot';
      return defaults.loadChainProof(count);
    } });
    assert.equal(report.status, 'checkpoint_verified');
  });
  await test('expiry during local proof rejected', async () => {
    let now = T;
    await assert.rejects(run({ now: () => now, loadChainProof: async count => { now = checkpoint.expires_at_ms; return defaults.loadChainProof(count); } }), code('recovery_checkpoint_expired'));
  });
  await test('clock rollback during verification rejected', async () => {
    let now = T;
    await assert.rejects(run({ now: () => now, loadChainProof: async count => { now -= 100; return defaults.loadChainProof(count); } }), code('recovery_checkpoint_invalid'));
  });
  await test('already aborted request does not read', async () => {
    const controller = new AbortController(); controller.abort('synthetic reason');
    await assert.rejects(run({ signal: controller.signal }), code('recovery_check_aborted'));
  });
  for (const stage of ['head', 'page', 'proof']) {
    await test(`abort during ${stage} prevents success`, async () => {
      const controller = new AbortController();
      const store = memoryStore(); const methods = { head: 'readHead', page: 'readPage' };
      const abort = async () => { controller.abort('synthetic reason'); return new Promise(() => {}); };
      if (stage !== 'proof') store[methods[stage]] = abort;
      await assert.rejects(run({ store, signal: controller.signal, ...(stage === 'proof' ? { loadChainProof: abort } : {}) }), code('recovery_check_aborted'));
    });
    await test(`non-settling ${stage} is deadline bounded`, async () => {
      const store = memoryStore(); const methods = { head: 'readHead', page: 'readPage' };
      const hang = () => new Promise(() => {});
      if (stage !== 'proof') store[methods[stage]] = hang;
      await assert.rejects(run({ store, config: parseAuditRecoveryConfig(json({ ...document, deadline_ms: 100 })),
        ...(stage === 'proof' ? { loadChainProof: hang } : {}) }), code('recovery_check_timeout'));
    });
  }
  await test('safe diagnostic ignores spoofed errors', () => {
    assert.equal(safeAuditRecoveryCheckCode({ code: 'recovery_checkpoint_expired', message: 'synthetic detail' }), 'recovery_check_failed');
    assert.equal(safeAuditRecoveryCheckCode(new AuditRecoveryCheckError('bad-code')), 'recovery_check_failed');
    assert.equal(safeAuditRecoveryCheckCode(new AuditRecoveryCheckError('recovery_check_aborted')), 'recovery_check_aborted');
    assert.equal(AUDIT_RECOVERY_CHECK_LIMITS.grants_production_readiness, false);
  });

  const configPath = join(work, 'config.json'); const checkpointPath = join(work, 'checkpoint.json');
  writeFileSync(configPath, json(document), { mode: 0o600 });
  writeFileSync(checkpointPath, json(checkpointDocument), { mode: 0o600 });
  const argv = ['--config-file', configPath, '--checkpoint-file', checkpointPath];
  await test('CLI file boundary and real historical proof round trip', async () => {
    const output = []; let made = 0;
    const result = await runAuditRecoveryCheck(argv, { now: () => T, createStore: options => {
      assert.deepEqual(options, { streamId, timeoutMs: 100 }); made++; return memoryStore();
    }, writeOutput: value => output.push(value) });
    assert.equal(made, 1); assert.deepEqual(JSON.parse(output[0]), result); assert.equal(output.length, 1);
    for (const value of [streamId, keyId, auditDir, checkpoint.payload_digest]) assert.equal(output[0].includes(value), false);
    assert.equal(readFileSync(auditPath, 'utf8'), auditBytes);
  });
  for (const invalid of [[], null, ['--config-file', configPath], ['--config-file', configPath, '--config-file', configPath],
    ['--unknown', 'synthetic detail', '--checkpoint-file', checkpointPath], ['--config-file', configPath, '--checkpoint-file', configPath],
    ['--config-file', 42, '--checkpoint-file', checkpointPath], ['--config-file', 'relative', '--checkpoint-file', checkpointPath]]) {
    await test('CLI rejects invalid file-only arguments without transport', async () => {
      let made = 0;
      await assert.rejects(runAuditRecoveryCheck(invalid, { createStore: () => { made++; return memoryStore(); } }));
      assert.equal(made, 0);
    });
  }
  await test('CLI expiry rejected before constructing store', async () => {
    let made = 0;
    await assert.rejects(runAuditRecoveryCheck(argv, { now: () => checkpoint.expires_at_ms, createStore: () => { made++; return memoryStore(); } }), code('recovery_checkpoint_expired'));
    assert.equal(made, 0);
  });
  await test('missing checkpoint rejected without socket I/O', async () => {
    const input = ['--config-file', configPath, '--checkpoint-file', join(work, 'missing')];
    await assert.rejects(runAuditRecoveryCheck(input));
  });
  if (process.platform !== 'win32') {
    await test('writable or linked checkpoint rejected', async () => {
      chmodSync(checkpointPath, 0o666);
      await assert.rejects(runAuditRecoveryCheck(argv));
      chmodSync(checkpointPath, 0o600);
      const link = join(work, 'link'); symlinkSync(checkpointPath, link);
      await assert.rejects(runAuditRecoveryCheck(['--config-file', configPath, '--checkpoint-file', link]));
    });
  }
  await test('corrupt local recovery file fails closed', async () => {
    writeFileSync(auditPath, auditBytes.replace('synthetic-event', 'corrupt-event'));
    try { await assert.rejects(runAuditRecoveryCheck(argv, { now: () => T, createStore: () => memoryStore() }), code('recovery_check_failed')); }
    finally { writeFileSync(auditPath, auditBytes); }
  });
  await test('truncated local recovery chain rejected', async () => {
    writeFileSync(auditPath, JSON.stringify(events[0]) + '\n');
    try { await assert.rejects(run(), code('recovery_check_failed')); }
    finally { writeFileSync(auditPath, auditBytes); }
  });
  await test('real CLI process emits fixed failure, not raw arguments', () => {
    const child = spawnSync(process.execPath, [CLI, '--password', 'synthetic-argument-secret'], { encoding: 'utf8', timeout: 5000 });
    assert.equal(child.status, 1); assert.equal(child.stdout, '');
    assert.deepEqual(JSON.parse(child.stderr), { status: 'failed', code: 'recovery_check_failed' });
  });
  await test('real CLI defaults read protected inputs and fail on expired checkpoint', () => {
    writeFileSync(checkpointPath, json({ ...checkpointDocument, issued_at_ms: Date.now() - 2000, expires_at_ms: Date.now() - 1000 }));
    const child = spawnSync(process.execPath, [CLI, ...argv], { encoding: 'utf8', timeout: 5000 });
    assert.equal(child.status, 1); assert.equal(child.stdout, '');
    assert.deepEqual(JSON.parse(child.stderr), { status: 'failed', code: 'recovery_checkpoint_expired' });
    assert.equal(child.stderr.includes(checkpointPath), false);
  });
  await test('default verifier clock accepts a currently issued checkpoint', async () => {
    const current = Date.now();
    const fresh = parseAuditRecoveryCheckpoint(json({ ...checkpointDocument,
      issued_at_ms: current - 1000, expires_at_ms: current + 10_000 }));
    const report = await verifyAuditRecoveryCheckpoint({ config, checkpoint: fresh,
      store: memoryStore(), loadChainProof: defaults.loadChainProof });
    assert.equal(report.checkpoint_match, true);
  });
  await test('default CLI output emits only the safe report', async () => {
    writeFileSync(checkpointPath, json(checkpointDocument));
    const original = process.stdout.write;
    const output = [];
    process.stdout.write = value => { output.push(value); return true; };
    try { await runAuditRecoveryCheck(argv, { now: () => T, createStore: () => memoryStore() }); }
    finally { process.stdout.write = original; }
    assert.equal(output.length, 1);
    assert.equal(JSON.parse(output[0]).status, 'checkpoint_verified');
  });
  await test('CLI shutdown handler aborts before transport construction', () => {
    const current = Date.now();
    writeFileSync(checkpointPath, json({ ...checkpointDocument,
      issued_at_ms: current - 1000, expires_at_ms: current + 10_000 }));
    // Invoke the registered handler in a child only. No real signal race, live
    // socket, production directory or external service is needed for this test.
    const preload = "const once = process.once; process.once = function (name, callback) { " +
      "const result = once.call(this, name, callback); if (name === 'SIGTERM') this.emit(name); return result; };";
    const child = spawnSync(process.execPath, ['--import=data:text/javascript,' + encodeURIComponent(preload),
      CLI, ...argv], { encoding: 'utf8', timeout: 5000 });
    assert.equal(child.status, 1);
    assert.deepEqual(JSON.parse(child.stderr), { status: 'failed', code: 'recovery_check_aborted' });
  });
  await test('bounded snapshot matches historical Node proofs for every event count', () => {
    const proof = readAuditRecoveryChainSnapshot(auditDir);
    for (const count of [0, 1, 2, 3]) {
      assert.deepEqual(proof(count), loadAuditChainProofSync(auditDir, count));
      assert.equal(Object.isFrozen(proof(count)), true);
    }
    for (const invalid of [-1, 1.5, '1', 4]) assert.throws(() => proof(invalid), /Recovery chain snapshot is unavailable/);
  });
  const snapshotError = /Recovery chain snapshot is unavailable/;
  for (const options of [{ signal: {} }, { unknown: true }, { maxBytes: 0 }, { maxFiles: 513 },
    { maxEvents: '3' }, { deadlineMs: 60_001 }, { signal: AbortSignal.abort() }]) {
    await test('invalid snapshot limit/signal rejected', () => assert.throws(() => readAuditRecoveryChainSnapshot(auditDir, options), snapshotError));
  }
  for (const path of [null, 'relative', auditDir + '/../audit', join(work, 'absent'), auditPath]) {
    await test('invalid snapshot directory rejected', () => assert.throws(() => readAuditRecoveryChainSnapshot(path), snapshotError));
  }
  for (const limits of [{ maxBytes: 1 }, { maxFileBytes: 1 }, { maxLineBytes: 1 }, { maxEvents: 2 }]) {
    await test('snapshot resource cap is enforced', () => assert.throws(() => readAuditRecoveryChainSnapshot(auditDir, limits), snapshotError));
  }
  await test('empty snapshot has explicit genesis only', () => {
    const empty = join(work, 'empty'); mkdirSync(empty);
    const proof = readAuditRecoveryChainSnapshot(empty);
    assert.deepEqual(proof(0), { files: 0, count: 0, lastHash: GENESIS_HASH,
      anchoredEventCount: 0, hashAtAnchor: GENESIS_HASH, filesAtAnchor: 0 });
    assert.throws(() => proof(1), snapshotError);
  });
  await test('snapshot ignores unrelated files but bounds directory enumeration', () => {
    const unrelated = join(auditDir, 'unrelated.txt'); writeFileSync(unrelated, 'public');
    try {
      assert.equal(readAuditRecoveryChainSnapshot(auditDir)(3).count, 3);
      assert.throws(() => readAuditRecoveryChainSnapshot(auditDir, { maxDirectoryEntries: 1 }), snapshotError);
    } finally { rmSync(unrelated); }
  });
  await test('snapshot bounds matching-file count including empty files', () => {
    const extra = join(auditDir, 'audit-chain-empty.jsonl'); writeFileSync(extra, '');
    try {
      assert.equal(readAuditRecoveryChainSnapshot(auditDir)(1).filesAtAnchor, 2);
      assert.throws(() => readAuditRecoveryChainSnapshot(auditDir, { maxFiles: 1 }), snapshotError);
    } finally { rmSync(extra); }
  });
  for (const content of ['{', 'null\n', '[]\n', '{}\n', Buffer.from([0xff])]) {
    await test('malformed/invalid local chain content fails safely', () => {
      writeFileSync(auditPath, content);
      try { assert.throws(() => readAuditRecoveryChainSnapshot(auditDir), snapshotError); }
      finally { writeFileSync(auditPath, auditBytes); }
    });
  }
  await test('matching directory cannot masquerade as audit file', () => {
    const matching = join(auditDir, 'audit-chain-not-file.jsonl'); mkdirSync(matching);
    try { assert.throws(() => readAuditRecoveryChainSnapshot(auditDir), snapshotError); }
    finally { rmSync(matching, { recursive: true }); }
  });
  if (process.platform !== 'win32') {
    await test('snapshot refuses symbolic-link files and directories', () => {
      const linkedFile = join(auditDir, 'audit-chain-link.jsonl'); symlinkSync(auditPath, linkedFile);
      try { assert.throws(() => readAuditRecoveryChainSnapshot(auditDir), snapshotError); }
      finally { rmSync(linkedFile); }
      const linkedDir = join(work, 'audit-link'); symlinkSync(auditDir, linkedDir);
      try { assert.throws(() => readAuditRecoveryChainSnapshot(linkedDir), snapshotError); }
      finally { rmSync(linkedDir); }
    });
  }
  await test('snapshot refuses hard-linked audit files', () => {
    const linked = join(work, 'hard-linked'); linkSync(auditPath, linked);
    try { assert.throws(() => readAuditRecoveryChainSnapshot(auditDir), snapshotError); }
    finally { rmSync(linked); }
  });
  for (const mutation of ['file', 'directory', 'abort']) {
    await test(`snapshot detects ${mutation} change during parsing`, () => {
      const parse = JSON.parse; let once = false;
      const controller = new AbortController();
      const extra = join(auditDir, 'created-during-read');
      // A synchronous test hook triggers a real filesystem mutation at a
      // deterministic read/verify boundary. Restore the parser even on failure.
      JSON.parse = (...args) => {
        const event = parse(...args);
        if (!once) {
          once = true;
          if (mutation === 'file') writeFileSync(auditPath, auditBytes + '\n');
          if (mutation === 'directory') writeFileSync(extra, 'public');
          if (mutation === 'abort') controller.abort();
        }
        return event;
      };
      try { assert.throws(() => readAuditRecoveryChainSnapshot(auditDir, { signal: controller.signal }), snapshotError); }
      finally { JSON.parse = parse; writeFileSync(auditPath, auditBytes); rmSync(extra, { force: true }); }
    });
  }
  await test('synchronous proof work cannot silently overrun overall deadline', async () => {
    await assert.rejects(run({ config: parseAuditRecoveryConfig(json({ ...document, deadline_ms: 100 })),
      loadChainProof: async count => {
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 120);
        return defaults.loadChainProof(count);
      } }), code('recovery_check_timeout'));
    assert.equal(AUDIT_RECOVERY_CHAIN_LIMITS.maxBytes, 64 * 1024 * 1024);
  });
  console.log(`audit recovery check: ${passed} cases passed; synthetic inputs only`);
} finally { rmSync(work, { recursive: true, force: true }); }
