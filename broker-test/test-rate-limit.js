import assert from 'node:assert/strict';
import { consumeRateLimit } from '../broker/lib/rate-limit.js';

const buckets = new Map();
assert.equal(consumeRateLimit({ minute: 2, hour: 3 }, 'client', buckets, 1_000), true);
assert.equal(consumeRateLimit({ minute: 2, hour: 3 }, 'client', buckets, 2_000), true);
assert.equal(consumeRateLimit({ minute: 2, hour: 3 }, 'client', buckets, 3_000), false);
assert.equal(consumeRateLimit({ minute: 2, hour: 3 }, 'other', buckets, 3_000), true);
assert.equal(consumeRateLimit({ minute: 2, hour: 3 }, 'client', buckets, 61_001), true);
assert.equal(consumeRateLimit('2/minute', 'string', buckets, 1_000), true);
assert.equal(consumeRateLimit('2/minute', 'string', buckets, 2_000), true);
assert.equal(consumeRateLimit('2/minute', 'string', buckets, 3_000), false);
for (const invalid of [{}, { unknown: 1 }, { minute: Infinity }, { hour: -1 }, { day: '2' }, [], 'invalid']) {
  assert.equal(consumeRateLimit(invalid, `invalid-${String(invalid)}`, buckets, 1_000), false);
}
assert.equal(consumeRateLimit('unlimited', 'unlimited', buckets, 1_000), true);
console.log('rate limit: string and multi-dimensional fail-closed checks passed');
