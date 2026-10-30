// broker/lib/health-visibility.js — least-privilege healthcheck views.
//
// Full healthcheck state can contain secret names and provider/account details.
// Non-admin identities receive only checks they are authorized to resolve.

const SUMMARY_KEYS = [
  'ok',
  'expired',
  'unreachable',
  'misconfigured',
  'fail',
  'skipped',
  'unknown',
];

export function summarizeHealthChecks(checks = {}) {
  const summary = Object.fromEntries(SUMMARY_KEYS.map((key) => [key, 0]));
  for (const check of Object.values(checks || {})) {
    const status = SUMMARY_KEYS.includes(check?.status) ? check.status : 'unknown';
    summary[status] += 1;
  }
  summary.total = Object.keys(checks || {}).length;
  return summary;
}

export function filteredHealthStatus(state, canSeeSecret, { admin = false } = {}) {
  const src = state && typeof state === 'object' ? state : {};
  if (admin) return src;

  const checks = {};
  for (const [name, check] of Object.entries(src.checks || {})) {
    if (typeof canSeeSecret === 'function' && canSeeSecret(name)) checks[name] = check;
  }

  const summary = summarizeHealthChecks(checks);
  let lastStatus = 'unknown';
  if (summary.total > 0) {
    lastStatus =
      summary.expired ||
      summary.unreachable ||
      summary.misconfigured ||
      summary.fail ||
      summary.unknown
        ? 'degraded'
        : 'ok';
  }

  return {
    last_run_at: src.last_run_at || null,
    last_status: lastStatus,
    duration_ms: src.duration_ms ?? null,
    summary,
    checks,
    _source: src._source || undefined,
  };
}

export { SUMMARY_KEYS };
