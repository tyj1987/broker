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

now += 60_001;
broker.prune();
assert.ok(broker.records.size < 10, 'expired token tombstones are eventually pruned');

console.log('execution tokens: binding, replay, expiration and revocation checks passed');
