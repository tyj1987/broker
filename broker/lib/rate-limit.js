const WINDOWS_MS = {
  minute: 60_000,
  hour: 3_600_000,
  day: 86_400_000,
};

function dimensions(limit) {
  if (limit === 'unlimited' || limit == null) return [];
  if (typeof limit === 'string') {
    const match = /^(\d+)\/(hour|minute|day)$/.exec(limit);
    if (!match) return null;
    return [{ max: Number(match[1]), windowMs: WINDOWS_MS[match[2]] }];
  }
  if (limit === null || typeof limit !== 'object' || Array.isArray(limit)) return null;
  const keys = Object.keys(limit);
  // An explicit object must name at least one supported dimension.  Treating
  // {} or an object containing only unknown fields as unlimited would turn a
  // malformed persisted policy into a fail-open configuration.
  if (keys.length === 0 || keys.some((name) => !Object.hasOwn(WINDOWS_MS, name))) return null;
  const result = [];
  for (const name of Object.keys(WINDOWS_MS)) {
    const value = limit[name];
    if (value == null) continue;
    if (!Number.isSafeInteger(value) || value < 0) return null;
    result.push({ max: value, windowMs: WINDOWS_MS[name] });
  }
  return result;
}

/**
 * Consume one request from a string or multi-dimensional rate limit.
 * Invalid configuration fails closed; successful consumption is atomic for all dimensions.
 */
export function consumeRateLimit(limit, key, buckets, now = Date.now()) {
  if (!(buckets instanceof Map) || typeof key !== 'string' || key.length === 0
    || !Number.isFinite(now)) return false;
  const configured = dimensions(limit);
  if (configured === null) return false;
  if (configured.length === 0) return true;
  const previous = buckets.get(key) || [];
  const oldestWindow = Math.max(...configured.map((entry) => entry.windowMs));
  const fresh = previous.filter((timestamp) => Number.isSafeInteger(timestamp) && now - timestamp < oldestWindow);
  for (const entry of configured) {
    const count = fresh.filter((timestamp) => now - timestamp < entry.windowMs).length;
    if (count >= entry.max) {
      buckets.set(key, fresh);
      return false;
    }
  }
  fresh.push(now);
  buckets.set(key, fresh);
  return true;
}

export const _rateLimitDimensions = dimensions;
