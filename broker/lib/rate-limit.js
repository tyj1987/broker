// broker/lib/rate-limit.js — in-memory sliding-window rate limiters
// Phase B extraction from server.js.

/**
 * Parse "100/hour" | "10/minute" | "1000/day" | "unlimited".
 * @param {string} limit
 * @returns {{ max: number, windowMs: number }|null} null = unlimited / invalid → allow
 */
export function parseRateLimit(limit) {
  if (!limit || limit === 'unlimited') return null;
  const m = String(limit).match(/^(\d+)\/(hour|minute|day)$/);
  if (!m) return null;
  const max = parseInt(m[1], 10);
  const windowMs = m[2] === 'minute' ? 60_000 : m[2] === 'day' ? 86_400_000 : 3_600_000;
  return { max, windowMs };
}

/**
 * Create a rate-limit checker with its own bucket map.
 * @returns {(key: string, limit: string) => boolean}
 */
export function createRateLimiter() {
  const buckets = new Map();
  return function check(key, limit) {
    const parsed = parseRateLimit(limit);
    if (!parsed) return true;
    const { max, windowMs } = parsed;
    const now = Date.now();
    const bucket = buckets.get(key) || [];
    const fresh = bucket.filter(t => now - t < windowMs);
    if (fresh.length >= max) {
      buckets.set(key, fresh);
      return false;
    }
    fresh.push(now);
    buckets.set(key, fresh);
    return true;
  };
}
