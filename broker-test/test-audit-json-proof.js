// Forward-port regression: preserve the newer proof loader with legacy JSON.
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { computeHash, sealEvent, loadAuditChainProofSync, GENESIS_HASH } from '../broker/lib/audit-hash-chain.js';

function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'broker-json-proof-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const body = { action: 'v2_request', status: 'denied', id: 'synthetic-legacy', cn: undefined, actor: undefined, prev_hash: GENESIS_HASH };
  const old = { ...body, hash: computeHash(body) };
  const next = sealEvent({ action: 'synthetic-current' }, old.hash);
  const files = ['audit-chain-2026-09-01.jsonl', 'audit-chain-2026-09-02.jsonl'].map(file => join(dir, file));
  [old, next].forEach((event, index) => writeFileSync(files[index], JSON.stringify(event) + '\n'));
  return { dir, old, next, files, bytes: files.map(file => readFileSync(file)) };
}
for (const anchor of [0, 1, 2, 3]) {
  test(`legacy proof preserves the exact anchor at ${anchor}`, t => {
    const f = fixture(t);
    const proof = loadAuditChainProofSync(f.dir, anchor);
    assert.deepEqual(proof, { files: 2, count: 2, lastHash: f.next.hash, anchoredEventCount: anchor,
      hashAtAnchor: [GENESIS_HASH, f.old.hash, f.next.hash, null][anchor],
      filesAtAnchor: [0, 1, 2, null][anchor] });
    f.files.forEach((file, index) => assert.deepEqual(readFileSync(file), f.bytes[index]));
  });
}
test('legacy identity insertion cannot be hidden by the proof loader', t => {
  const f = fixture(t);
  writeFileSync(f.files[0], JSON.stringify({ ...f.old, actor: 'forged' }) + '\n');
  const bytes = readFileSync(f.files[0]);
  assert.throws(() => loadAuditChainProofSync(f.dir, 1), /audit chain verification failed/);
  assert.deepEqual(readFileSync(f.files[0]), bytes);
});
test('tampering after the requested anchor is still rejected', t => {
  const f = fixture(t);
  writeFileSync(f.files[1], JSON.stringify({ ...f.next, action: 'tampered' }) + '\n');
  const bytes = readFileSync(f.files[1]);
  assert.throws(() => loadAuditChainProofSync(f.dir, 1), /audit chain verification failed/);
  assert.deepEqual(readFileSync(f.files[1]), bytes);
});
test('genesis proof does not bypass historical chain validation', t => {
  const f = fixture(t);
  writeFileSync(f.files[0], JSON.stringify({ ...f.old, hash: 'f'.repeat(64) }) + '\n');
  assert.throws(() => loadAuditChainProofSync(f.dir, 0), /audit chain verification failed/);
});
test('invalid requested anchor remains rejected before proof construction', t => {
  const f = fixture(t);
  for (const value of [-1, 0.5, NaN, Infinity, '1', Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => loadAuditChainProofSync(f.dir, value), /anchored audit event count is invalid/);
  }
});
