// broker/lib/sse-cap.js — V4.8.0
// Per-admin concurrent SSE connection cap (REVIEW.md §3 P6).
// Extracted from server.js for unit-testability.
//
// State is process-local (in-memory). Not replicated. On broker restart
// counts reset to zero, which is acceptable since the cap protects against
// a single client opening many simultaneous connections during one session.

const SSE_ADMIN_CONN_COUNT = new Map(); // adminKey → count
const SSE_MAX_CONCURRENT_PER_ADMIN = 3;

/**
 * Create a fresh SSE-cap instance bound to its own counter Map.
 * Used by the broker (server.js) and by tests. Both the module-level
 * helpers (`tryAcquireSseSlot`, etc.) and factory-created instances
 * share the same Map; the factory exists for test isolation if needed.
 */
export function createSseCap() {
  return {
    adminSseKey,
    tryAcquireSseSlot,
    releaseSseSlot,
    _resetSseCapForTests,
    _getSseCountForTests,
  };
}

/**
 * Build the per-admin key used to count concurrent connections.
 * @param {string} clientName  admin client name (preferred) or cn
 */
export function adminSseKey(clientName) {
  return `audit-stream:${clientName || 'unknown'}`;
}

/**
 * Try to acquire one of the concurrent SSE slots for an admin client.
 * @param {string} adminKey  result of adminSseKey()
 * @returns {{ acquired: boolean, current: number, limit: number }}
 *   - acquired: true if slot granted; false if at limit (caller returns 429)
 *   - current: current count BEFORE this acquisition attempt (for logging)
 *   - limit: configured maximum
 */
export function tryAcquireSseSlot(adminKey) {
  const current = SSE_ADMIN_CONN_COUNT.get(adminKey) || 0;
  if (current >= SSE_MAX_CONCURRENT_PER_ADMIN) {
    return { acquired: false, current, limit: SSE_MAX_CONCURRENT_PER_ADMIN };
  }
  SSE_ADMIN_CONN_COUNT.set(adminKey, current + 1);
  return { acquired: true, current, limit: SSE_MAX_CONCURRENT_PER_ADMIN };
}

/**
 * Release one SSE slot when a connection closes.
 * @param {string} adminKey
 */
export function releaseSseSlot(adminKey) {
  const n = (SSE_ADMIN_CONN_COUNT.get(adminKey) || 1) - 1;
  if (n <= 0) SSE_ADMIN_CONN_COUNT.delete(adminKey);
  else SSE_ADMIN_CONN_COUNT.set(adminKey, n);
}

/** Test-only: clear all counters. */
export function _resetSseCapForTests() {
  SSE_ADMIN_CONN_COUNT.clear();
}

/** Test-only: get current count for a key. */
export function _getSseCountForTests(adminKey) {
  return SSE_ADMIN_CONN_COUNT.get(adminKey) || 0;
}
