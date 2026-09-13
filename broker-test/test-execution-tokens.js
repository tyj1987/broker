import assert from 'node:assert/strict';
import { ExecutionTokenBroker } from '../broker/lib/execution-tokens.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const expectCode = (code) => (error) => error instanceof V2Error && error.code === code;
let now = 1_900_000_000_000;
const broker = new ExecutionTokenBroker({ now: () => now });
const binding = {
  actor: 'agent.build', tool: 'github.repository.read@1.0.0', target: 'repository',
  environment: 'production', request_binding: 'request-fingerprint-0000000001', ttl_ms: 5_000,
};

const issued = broker.issue(binding);
assert.match(issued.token, /^et1\./);
assert.ok(issued.nonce);
assert.ok(!JSON.stringify(issued).includes(binding.request_binding));
const grant = broker.consume(issued.token, issued.nonce, binding);
assert.equal(grant.execution_id, issued.execution_id);
assert.equal(grant.actor, binding.actor);
assert.equal(grant.request_binding, binding.request_binding);
assert.ok(!Object.hasOwn(grant, 'token'));
assert.ok(!Object.hasOwn(grant, 'nonce'));
assert.throws(() => broker.consume(issued.token, issued.nonce, binding), expectCode('execution_token_replay'));

for (const field of ['actor', 'tool', 'target', 'environment', 'request_binding']) {
  const candidate = broker.issue(binding);
  assert.throws(() => broker.consume(candidate.token, candidate.nonce, { ...binding, [field]: `${binding[field]}-tampered` }), expectCode('execution_token_mismatch'));
  assert.equal(broker.consume(candidate.token, candidate.nonce, binding).actor, binding.actor, 'a mismatch must not burn the valid capability');
}

const wrongNonce = broker.issue(binding);
const anotherNonce = broker.issue(binding);
assert.throws(() => broker.consume(wrongNonce.token, anotherNonce.nonce, binding), expectCode('execution_token_mismatch'));

const expired = broker.issue({ ...binding, ttl_ms: 1_000 });
now += 1_001;
assert.throws(() => broker.consume(expired.token, expired.nonce, binding), expectCode('execution_token_expired'));

const expiresBeforeRevoke = broker.issue({ ...binding, ttl_ms: 1_000 });
now += 1_001;
assert.throws(
  () => broker.revoke(expiresBeforeRevoke.execution_id),
  expectCode('invalid_state'),
  'revocation cannot overwrite an expired capability state',
);
assert.equal(
  broker.exportState().records.find((record) => record.id === expiresBeforeRevoke.execution_id).status,
  'EXPIRED',
  'durable snapshots materialize token expiry',
);

const revoked = broker.issue(binding);
assert.equal(broker.revoke(revoked.execution_id).execution_id, revoked.execution_id);
assert.throws(() => broker.consume(revoked.token, revoked.nonce, binding), expectCode('execution_token_replay'));
assert.throws(() => broker.revoke(revoked.execution_id), expectCode('invalid_state'));
assert.throws(() => broker.revoke('00000000-0000-4000-8000-000000000000'), expectCode('not_found'));

assert.throws(() => broker.consume('bad', 'bad', binding), expectCode('invalid_execution_token'));
assert.throws(() => broker.issue({ ...binding, actor: '' }), expectCode('invalid_request'));
assert.throws(() => broker.issue({ ...binding, ttl_ms: 999 }), expectCode('invalid_request'));
const full = new ExecutionTokenBroker({ maxRecords: 0 });
assert.throws(() => full.issue(binding), expectCode('capacity'));

const restartNow = 1_910_000_000_000;
const beforeRestart = new ExecutionTokenBroker({ now: () => restartNow });
const consumedBeforeRestart = beforeRestart.issue(binding);
beforeRestart.consume(consumedBeforeRestart.token, consumedBeforeRestart.nonce, binding);
const revokedBeforeRestart = beforeRestart.issue(binding);
beforeRestart.revoke(revokedBeforeRestart.execution_id);
const activeBeforeRestart = beforeRestart.issue(binding);
const durableState = beforeRestart.exportState();
const serializedState = JSON.stringify(durableState);
assert.equal(durableState.version, 1);
assert.equal(durableState.records.length, 3);
for (const capability of [consumedBeforeRestart, revokedBeforeRestart, activeBeforeRestart]) {
  assert.ok(!serializedState.includes(capability.token), 'durable state must not contain bearer tokens');
  assert.ok(!serializedState.includes(capability.nonce), 'durable state must not contain raw nonces');
}

const afterRestart = new ExecutionTokenBroker({ now: () => restartNow });
afterRestart.restoreState(durableState);
assert.throws(
  () => afterRestart.consume(consumedBeforeRestart.token, consumedBeforeRestart.nonce, binding),
  expectCode('execution_token_replay'),
  'consumed-token tombstones must survive restart',
);
assert.throws(
  () => afterRestart.consume(revokedBeforeRestart.token, revokedBeforeRestart.nonce, binding),
  expectCode('execution_token_replay'),
  'revoked-token tombstones must survive restart',
);
assert.equal(
  afterRestart.consume(activeBeforeRestart.token, activeBeforeRestart.nonce, binding).execution_id,
  activeBeforeRestart.execution_id,
  'an unexpired bound capability can be recovered without weakening its binding',
);

const restoreGuard = new ExecutionTokenBroker({ now: () => restartNow });
const guardCapability = restoreGuard.issue(binding);
const validDurableRecord = durableState.records[0];
for (const corrupt of [
  null,
  { version: 2, records: [] },
  { version: 1, records: 'not-an-array' },
  { version: 1, records: [{ ...validDurableRecord, actor: 42 }] },
  { version: 1, records: [{ ...validDurableRecord, id: 'not-a-uuid' }] },
  { version: 1, records: [{ ...validDurableRecord, tokenHash: 'not-a-digest' }] },
  { version: 1, records: [{ ...validDurableRecord, status: 'UNKNOWN' }] },
  { version: 1, records: [{ ...validDurableRecord, status: 'ACTIVE', consumedAt: restartNow }] },
  { version: 1, records: [{ ...validDurableRecord, issuedAt: '2026-01-01T00:00:00Z' }] },
  { version: 1, records: [{ ...validDurableRecord, consumedAt: new Date(restartNow - 1).toISOString() }] },
  { version: 1, records: [{ ...durableState.records[1], revokedAt: new Date(restartNow - 1).toISOString() }] },
  { version: 1, records: [{ ...durableState.records[1], revokedAt: durableState.records[1].expiresAt }] },
  { version: 1, records: [{ ...validDurableRecord, consumedAt: new Date(restartNow + 1).toISOString() }] },
  { version: 1, records: [validDurableRecord, validDurableRecord] },
  { ...durableState, unexpected: true },
]) {
  assert.throws(() => restoreGuard.restoreState(corrupt), expectCode('state_corrupt'));
}
assert.equal(
  restoreGuard.consume(guardCapability.token, guardCapability.nonce, binding).execution_id,
  guardCapability.execution_id,
  'a rejected restore must not replace the last valid in-memory state',
);

const expiredSnapshotBroker = new ExecutionTokenBroker({ now: () => restartNow });
const expiresForSnapshot = expiredSnapshotBroker.issue({ ...binding, ttl_ms: 1_000 });
const activeSnapshot = expiredSnapshotBroker.exportState();
const afterSnapshotExpiry = new ExecutionTokenBroker({ now: () => restartNow + 1_001 });
afterSnapshotExpiry.restoreState(activeSnapshot);
assert.equal(
  afterSnapshotExpiry.records.get(activeSnapshot.records[0].tokenHash).status,
  'EXPIRED',
  'restore materializes an ACTIVE record whose deadline has passed',
);
assert.throws(
  () => afterSnapshotExpiry.consume(expiresForSnapshot.token, expiresForSnapshot.nonce, binding),
  expectCode('execution_token_replay'),
);

assert.throws(() => new ExecutionTokenBroker({ now: null }), TypeError);
assert.throws(() => new ExecutionTokenBroker({ maxRecords: -1 }), TypeError);
assert.throws(
  () => new ExecutionTokenBroker({ now: () => Number.NaN }).issue(binding),
  expectCode('clock_invalid'),
);
assert.throws(
  () => new ExecutionTokenBroker({ now: () => { throw new Error('detail'); } }).issue(binding),
  expectCode('clock_invalid'),
);

now += 60_001;
broker.prune();
assert.ok(broker.records.size < 10, 'expired token tombstones are eventually pruned');

console.log('execution tokens: binding, replay, expiration and revocation checks passed');
