// broker/lib/rate-limit.js — bounded in-memory sliding-window rate limiters

/**
 * Parse "5/second" | "100/hour" | "10/minute" | "1000/day" | "unlimited".
 * @param {string} limit
 * @returns {{ max: number, windowMs: number }|null} null = unlimited / missing / invalid
 */
export function parseRateLimit(limit) {
  if (!limit || limit === 'unlimited') return null;
  const m = String(limit).match(/^(\d+)\/(second|minute|hour|day)$/);
  if (!m) return null;
  const max = Number.parseInt(m[1], 10);
  if (!Number.isSafeInteger(max)) return null;
  const windowMs =
    m[2] === 'second'
      ? 1_000
      : m[2] === 'minute'
        ? 60_000
        : m[2] === 'day'
          ? 86_400_000
          : 3_600_000;
  return { max, windowMs };
}

/**
 * Build a stable bucket key for all supported identity types. Password-only
 * sessions have no certificate fingerprint, so clientName must be used rather
 * than collapsing every such session into the same `null` bucket.
 */
export function rateLimitKey(ctx = {}) {
  if (ctx.fp) return `fp:${ctx.fp}`;
  if (ctx.clientName) return `client:${ctx.clientName}`;
  if (ctx.cn) return `cn:${ctx.cn}`;
  return 'anonymous';
}

/**
 * Create a bounded rate-limit checker with its own bucket map.
 * Invalid non-empty limits fall back to a conservative default instead of
 * silently disabling throttling because of a configuration typo.
 *
 * New high-cardinality identities fail closed once capacity is exhausted;
 * active buckets are never evicted because that would reset their limits.
 *
 * @param {{
 *   defaultLimit?: string,
 *   now?: () => number,
 *   maxBuckets?: number,
 *   maxEventsPerBucket?: number,
 *   cleanupEvery?: number,
 * }} [opts]
 * @returns {((key: string, limit: string) => boolean) & {
 *   prune: (now?: number) => number,
 *   size: () => number,
 * }}
 */
export function createRateLimiter(opts = {}) {
  const buckets = new Map();
  const defaultLimit = opts.defaultLimit || '100/hour';
  const nowFn = typeof opts.now === 'function' ? opts.now : Date.now;
  const maxBuckets = positiveInteger(opts.maxBuckets, 10_000);
  const maxEventsPerBucket = positiveInteger(opts.maxEventsPerBucket, 100_000);
  const cleanupEvery = positiveInteger(opts.cleanupEvery, 256);
  let checks = 0;

  function prune(now = nowFn()) {
    let removed = 0;
    for (const [key, bucket] of buckets) {
      const fresh = bucket.timestamps.filter((timestamp) => now - timestamp < bucket.windowMs);
      if (fresh.length === 0) {
        buckets.delete(key);
        removed += 1;
      } else {
        bucket.timestamps = fresh;
      }
    }
    return removed;
  }

  function check(key, limit) {
    let parsed = parseRateLimit(limit);
    if (!parsed) {
      if (!limit || limit === 'unlimited') {
        buckets.delete(key);
        return true;
      }
      parsed = parseRateLimit(defaultLimit);
      if (!parsed) return false;
    }

    const { max, windowMs } = parsed;
    const now = nowFn();
    checks += 1;
    if (checks % cleanupEvery === 0 || (!buckets.has(key) && buckets.size >= maxBuckets)) {
      prune(now);
    }
    if (!buckets.has(key) && buckets.size >= maxBuckets) return false;

    const existing = buckets.get(key);
    const fresh = (existing?.timestamps || []).filter((timestamp) => now - timestamp < windowMs);
    if (fresh.length >= max || fresh.length >= maxEventsPerBucket) {
      buckets.set(key, { timestamps: fresh, windowMs });
      return false;
    }
    fresh.push(now);
    buckets.set(key, { timestamps: fresh, windowMs });
    return true;
  }

  check.prune = prune;
  check.size = () => buckets.size;
  return check;
}

function positiveInteger(value, fallback) {
  return Number.isSafeInteger(value) && value > 0 ? value : fallback;
}
