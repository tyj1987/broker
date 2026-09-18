// Synthetic regression for #33. Never reads a production audit directory.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { sealEvent, verifyChain, verifyAuditDir, loadAuditChainStateSync, createChainWriter, GENESIS_HASH } from '../broker/lib/audit-hash-chain.js';

// Freeze the historical writer independently of the implementation under test.
function historicalCanonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(historicalCanonical).join(',') + ']';
  return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + historicalCanonical(value[key])).join(',') + '}';
}
function historicalEvent(fields = {}, previous = GENESIS_HASH) {
  const body = { action: 'v2_request', status: 'denied', reason: 'synthetic-denial', path: '/api/v2/tasks', id: 'synthetic-event', request_id: 'synthetic-request', ts: '2026-09-01T00:00:00.000Z', cn: undefined, actor: undefined, ...fields, prev_hash: previous };
  return { ...body, hash: createHash('sha256').update(historicalCanonical(body)).digest('hex') };
}
const roundtrip = value => JSON.parse(JSON.stringify(value));
function fixture(t, events) {
  const dir = mkdtempSync(join(tmpdir(), 'broker-json-roundtrip-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'audit-chain-2026-09-01.jsonl');
  writeFileSync(file, events.map(event => JSON.stringify(event)).join('\n') + '\n');
  return { dir, file, bytes: readFileSync(file) };
}

for (const [name, fields] of [
  ['undefined identities', { cn: undefined, actor: undefined }],
  ['nested omitted fields', { details: { absent: undefined, keep: 1 } }],
  ['sparse and undefined array entries', { details: Object.assign(Array(3), { 2: 3 }) }],
  ['non-finite numbers', { details: [NaN, Infinity, -Infinity] }],
  ['Date wire representation', { details: new Date('2026-09-01T00:00:00.000Z') }],
  ['custom JSON representation', { details: { toJSON() { return { keep: 1 }; } } }],
  ['caller-supplied hash', { hash: 'not-a-stored-hash' }],
  ['omitted function and symbol', { callback() {}, value: Symbol('synthetic') }],
]) {
  test(`new writer persists its exact hash preimage: ${name}`, () => {
    const event = sealEvent({ action: 'synthetic', ...fields }, GENESIS_HASH);
    assert.deepEqual(verifyChain([roundtrip(event)]), { ok: true, count: 1 });
    assert.deepEqual(event, roundtrip(event));
  });
}
test('the raw verifier still rejects a lossy legacy object', () => {
  const event = historicalEvent();
  assert.equal(verifyChain([event]).ok, true);
  assert.equal(verifyChain([roundtrip(event)]).ok, false);
});
test('legacy cold start restores only the matching preimage without rewriting bytes', async t => {
  const old = historicalEvent();
  const f = fixture(t, [old]);
  assert.deepEqual(loadAuditChainStateSync(f.dir), { files: 1, count: 1, lastHash: old.hash });
  assert.deepEqual(await verifyAuditDir(f.dir), { ok: true, count: 1, files: 1 });
  assert.deepEqual(readFileSync(f.file), f.bytes);
});
test('mixed multi-file history resumes across repeated cold starts', async t => {
  const old = historicalEvent();
  const f = fixture(t, [old]);
  const next = sealEvent({ action: 'synthetic', details: { absent: undefined } }, old.hash);
  const nextFile = join(f.dir, 'audit-chain-2026-09-02.jsonl');
  writeFileSync(nextFile, '\n' + JSON.stringify(next) + '\n\n');
  const nextBytes = readFileSync(nextFile);
  for (let i = 0; i < 3; i++) {
    assert.deepEqual(loadAuditChainStateSync(f.dir, { chainOnly: true }), { files: 2, count: 2, lastHash: next.hash });
    assert.deepEqual(await verifyAuditDir(f.dir), { ok: true, count: 2, files: 2 });
  }
  assert.deepEqual(readFileSync(f.file), f.bytes);
  assert.deepEqual(readFileSync(nextFile), nextBytes);
});
test('current denied records with omitted identities remain valid', async t => {
  const event = sealEvent({ action: 'v2_request', status: 'denied' });
  const f = fixture(t, [event]);
  assert.equal(verifyChain([event]).ok, true);
  assert.equal(loadAuditChainStateSync(f.dir).lastHash, event.hash);
  assert.equal((await verifyAuditDir(f.dir)).ok, true);
  assert.deepEqual(readFileSync(f.file), f.bytes);
});
async function rejected(t, event) {
  const f = fixture(t, [event]);
  assert.throws(() => loadAuditChainStateSync(f.dir), /audit chain verification failed/);
  assert.equal((await verifyAuditDir(f.dir)).ok, false);
  assert.deepEqual(readFileSync(f.file), f.bytes);
}
for (const key of ['action', 'status', 'reason', 'path', 'id', 'request_id', 'ts', 'hash', 'prev_hash']) {
  test(`legacy record tampering remains rejected: ${key}`, async t => {
    const event = roundtrip(historicalEvent());
    event[key] = key.endsWith('hash') ? 'f'.repeat(64) : 'tampered';
    await rejected(t, event);
  });
}
for (const key of ['cn', 'actor']) {
  for (const value of ['inserted-identity', null, '']) {
    test(`inserted ${key} (${JSON.stringify(value)}) is not silently removed`, async t => {
      await rejected(t, { ...roundtrip(historicalEvent()), [key]: value });
    });
  }
}
for (const [name, fields] of [
  ['different action', { action: 'other' }],
  ['different status', { status: 'allowed' }],
  ['one missing identity only', { cn: 'synthetic-client' }],
  ['additional undefined field', { extra: undefined }],
  ['nested undefined preimage', { details: { extra: undefined } }],
]) {
  test(`unsupported historical shape fails closed: ${name}`, async t => {
    await rejected(t, roundtrip(historicalEvent(fields)));
  });
}
for (const [name, makeValue] of [
  ['BigInt', () => ({ value: 1n })],
  ['cycle', () => { const value = {}; value.self = value; return value; }],
]) {
  test(`unserializable ${name} does not advance the writer`, () => {
    const output = [];
    const writer = createChainWriter({ onEvent: event => output.push(event) });
    assert.throws(() => writer.write(makeValue()));
    assert.equal(writer.count, 0);
    assert.equal(writer.prevHash, GENESIS_HASH);
    assert.deepEqual(output, []);
  });
}
for (const content of ['{malformed}\n', 'null\n']) {
  test(`invalid persisted input remains rejected: ${content.trim()}`, async t => {
    const f = fixture(t, []);
    writeFileSync(f.file, content);
    assert.throws(() => loadAuditChainStateSync(f.dir), /invalid audit JSON/);
    await assert.rejects(verifyAuditDir(f.dir), /invalid audit JSON/);
    assert.equal(readFileSync(f.file, 'utf8'), content);
  });
}
