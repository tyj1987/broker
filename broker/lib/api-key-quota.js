// Per-process delegated-key quotas. A request is counted once by the cached
// identity resolver; existing active buckets are never evicted to admit new IDs.
import { normalizeRateLimit } from '../api-keys.js';
const WINDOWS = { minute: 60_000, hour: 3_600_000, day: 86_400_000 };

function limitsFor(value) {
  const configured = value ?? '100/hour';
  let normalized = normalizeRateLimit(configured);
  if (!normalized && typeof configured === 'string') {
    const match = /^(\d+)\/(minute|hour|day)$/.exec(configured);
    if (!match || !Number.isSafeInteger(Number(match[1]))) return false;
    normalized = { [match[2]]: Number(match[1]) };
  }
  if (!normalized || typeof normalized !== 'object' || Array.isArray(configured)) return false;
  if (typeof configured === 'object' && (Object.keys(configured).some(name => !Object.hasOwn(WINDOWS, name))
    || Object.values(configured).some(value => value != null && (!Number.isSafeInteger(value) || value < 0)))) return false;
  const limits = [];
  for (const [name, duration] of Object.entries(WINDOWS)) {
    const max = normalized[name];
    if (max == null) continue;
    if (!Number.isSafeInteger(max) || max < 0) return false;
    limits.push({ max, duration });
  }
  return limits;
}

export function createApiKeyQuota({ now = Date.now, maxBuckets = 10_000, maxEvents = 10_000 } = {}) {
  if (typeof now !== 'function' || !Number.isSafeInteger(maxBuckets) || maxBuckets <= 0
      || !Number.isSafeInteger(maxEvents) || maxEvents <= 0) throw new TypeError('Invalid API-key quota options');
  const buckets = new Map();
  let operations = 0;
  function prune(timestamp) {
    for (const [id, bucket] of buckets) {
      if (!bucket.events.length || timestamp - bucket.events.at(-1) >= bucket.window) buckets.delete(id);
    }
  }
  return function check(key) {
    if (!key || typeof key.id !== 'string' || !key.id) return false;
    const limits = limitsFor(key.rate_limit);
    if (limits === false) return false;
    if (!limits.length) return true;
    if (limits.some(limit => limit.max === 0)) return false;
    const timestamp = now();
    if (!Number.isFinite(timestamp)) return false;
    operations++;
    if (operations % 256 === 0 || (!buckets.has(key.id) && buckets.size >= maxBuckets)) prune(timestamp);
    if (!buckets.has(key.id) && buckets.size >= maxBuckets) return false;
    const window = Math.max(...limits.map(limit => limit.duration));
    const events = (buckets.get(key.id)?.events || []).filter(time => timestamp - time < window);
    buckets.set(key.id, { events, window });
    if (events.length >= maxEvents || limits.some(limit => events.filter(time => timestamp - time < limit.duration).length >= limit.max)) return false;
    events.push(timestamp);
    return true;
  };
}
