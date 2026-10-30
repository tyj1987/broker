// broker-test/test-health-visibility.js — least-privilege healthcheck views

import { filteredHealthStatus, summarizeHealthChecks } from '../broker/lib/health-visibility.js';
import { readFileSync } from 'node:fs';

let pass = 0;
let fail = 0;

function ok(name, cond) {
  if (cond) {
    pass++;
    console.log(`  PASS  ${name}`);
  } else {
    fail++;
    console.error(`  FAIL  ${name}`);
  }
}

const state = {
  last_run_at: '2026-09-22T10:00:00.000Z',
  last_status: 'degraded',
  duration_ms: 123,
  summary: { ok: 1, expired: 1, total: 2 },
  checks: {
    GITHUB_PAT: { status: 'ok', detail: 'github user=alice', latency_ms: 10 },
    ADMIN_ONLY: { status: 'expired', detail: 'sensitive account detail', latency_ms: 20 },
  },
  _source: 'local',
};

console.log('[summary]');
{
  const s = summarizeHealthChecks(state.checks);
  ok('total=2', s.total === 2);
  ok('ok=1', s.ok === 1);
  ok('expired=1', s.expired === 1);
}

console.log('\n[filtered view]');
{
  const v = filteredHealthStatus(state, (name) => name === 'GITHUB_PAT');
  ok('only visible secret remains', Object.keys(v.checks).length === 1 && !!v.checks.GITHUB_PAT);
  ok('hidden secret name absent', !Object.prototype.hasOwnProperty.call(v.checks, 'ADMIN_ONLY'));
  ok(
    'summary is recalculated without hidden totals',
    v.summary.total === 1 && v.summary.ok === 1 && v.summary.expired === 0,
  );
  ok('status recalculated to ok', v.last_status === 'ok');
  ok('timing metadata preserved', v.duration_ms === 123);
}
{
  const v = filteredHealthStatus(state, () => false);
  ok('no permission returns zero checks', Object.keys(v.checks).length === 0);
  ok('no permission leaks no total', v.summary.total === 0);
  ok('empty visible set status unknown', v.last_status === 'unknown');
}
{
  const v = filteredHealthStatus(state, () => false, { admin: true });
  ok('admin receives original full state', v === state);
}

console.log('\n[dashboard self-audit wiring]');
{
  const home = readFileSync(new URL('../broker/dashboard/home.js', import.meta.url), 'utf8');
  ok('non-admin home uses self audit endpoint', home.includes("'/api/v1/me/audit?limit=200'"));
  ok(
    'non-admin home no longer uses global audit endpoint',
    !home.includes(": '/api/v1/audit?limit=200'"),
  );
}

console.log(`\n=== Total: ${pass} passed, ${fail} failed ===`);
process.exit(fail > 0 ? 1 : 0);
