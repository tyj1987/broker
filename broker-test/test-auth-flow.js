import assert from 'node:assert/strict';
import {
  createMfaPending,
  getMfaPending,
  consumeMfaPending,
  MFA_TOKEN_TTL_MS,
} from '../broker/auth-flow.js';

const realNow = Date.now;
try {
  Date.now = () => 1_000_000;
  const token = createMfaPending('client-1', 'fp');
  assert.equal(getMfaPending(token)?.clientName, 'client-1');
  Date.now = () => 1_000_000 + MFA_TOKEN_TTL_MS + 1;
  assert.equal(consumeMfaPending(token), false, 'expired token cannot be consumed directly');
  assert.equal(getMfaPending(token), null);
} finally {
  Date.now = realNow;
}
console.log('auth flow: expired MFA pending tokens fail closed');
