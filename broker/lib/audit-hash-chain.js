// Hash-chain primitives. Hash exactly the JSON value written to disk (including
// JSON's treatment of undefined, Dates and array holes), not an in-memory object.
// A local hash chain is NOT a signature: independently retain checkpoints to
// detect an attacker who can replace both the journal and its local checkpoint.
import { createHash } from 'node:crypto';

export const GENESIS_HASH = '0'.repeat(64);
export const HASH_RE = /^[a-f0-9]{64}$/;

function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  return (
    '{' +
    Object.keys(value)
      .sort()
      .map((key) => JSON.stringify(key) + ':' + canonicalize(value[key]))
      .join(',') +
    '}'
  );
}

export function jsonValue(value) {
  return JSON.parse(JSON.stringify(value));
}

export function computeHash(eventWithoutHash) {
  return createHash('sha256')
    .update(canonicalize(jsonValue(eventWithoutHash)))
    .digest('hex');
}

export function sealEvent(event, prevHash = GENESIS_HASH) {
  if (!event || typeof event !== 'object' || Array.isArray(event))
    throw new TypeError('Audit event must be an object');
  const previous = prevHash || GENESIS_HASH;
  if (!HASH_RE.test(previous)) throw new TypeError('Invalid previous audit hash');
  const clean = jsonValue(event);
  delete clean.hash;
  const withPrev = { ...clean, prev_hash: previous };
  return { ...withPrev, hash: computeHash(withPrev) };
}

export function verifyChain(events, { initialHash = GENESIS_HASH } = {}) {
  if (!Array.isArray(events) || !HASH_RE.test(initialHash))
    return { ok: false, reason: 'Invalid chain input' };
  let prevHash = initialHash;
  for (let i = 0; i < events.length; i++) {
    const event = events[i];
    if (!event || typeof event !== 'object' || Array.isArray(event))
      return { ok: false, broken_at: i, reason: 'Invalid event object' };
    if (event.prev_hash !== prevHash)
      return { ok: false, broken_at: i, reason: `prev_hash mismatch at index ${i}` };
    const { hash: stored, ...rest } = event;
    if (typeof stored !== 'string' || !HASH_RE.test(stored) || computeHash(rest) !== stored)
      return { ok: false, broken_at: i, reason: `hash mismatch at index ${i}` };
    prevHash = stored;
  }
  return { ok: true, count: events.length, last_hash: prevHash };
}

// Lazy import avoids a static dependency cycle with the durable ledger writer.
export async function verifyAuditDir(auditDir, options = {}) {
  const { verifyAuditDirectory } = await import('./audit-ledger.js');
  return verifyAuditDirectory(auditDir, options);
}

// For in-memory/unit-test consumers. The production writer is createAuditLedger.
export function createChainWriter(opts = {}) {
  const onEvent = opts.onEvent || (() => {});
  let prevHash = opts.initialHash || GENESIS_HASH;
  let count = 0;
  return {
    write(event) {
      const sealed = sealEvent(event, prevHash);
      const nextHash = sealed.hash;
      const result = onEvent(sealed);
      if (result && typeof result.then === 'function')
        throw new TypeError('Chain writer requires a synchronous sink');
      prevHash = nextHash;
      count++;
      return sealed;
    },
    get prevHash() {
      return prevHash;
    },
    get count() {
      return count;
    },
  };
}
