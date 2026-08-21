// broker-test/test-phase-c-obs.js
import {
  inc, observeMs, snapshot, prometheusText, timedRequest, getCounter, _resetMetricsForTests,
} from '../broker/lib/metrics.js';
import { log } from '../broker/lib/log.js';
import { handleHealth } from '../broker/routes/health.js';
import { handleMetrics } from '../broker/routes/metrics.js';
import { BROKER_VERSION } from '../broker/version.js';

let passed = 0, failed = 0;
function assert(c, m) {
  if (c) { passed++; console.log('  OK  ', m); }
  else { failed++; console.error('  FAIL', m); }
}

_resetMetricsForTests();

console.log('=== counters / histogram ===');
{
  inc('test_total', 2);
  inc('test_labeled', 1, { route: 'health' });
  observeMs('test_latency_ms', 12);
  observeMs('test_latency_ms', 120);
  assert(getCounter('test_total') === 2, 'counter');
  const snap = snapshot();
  assert(snap.histograms.test_latency_ms.count === 2, 'hist count');
  assert(snap.histograms.test_latency_ms.avg_ms > 0, 'avg');
  const text = prometheusText({ version: '3.5.0' });
  assert(text.includes('broker_up'), 'prom up');
  assert(text.includes('test_total'), 'prom counter');
  assert(text.includes('test_latency_ms_bucket'), 'prom hist');
}

console.log('=== timedRequest ===');
{
  _resetMetricsForTests();
  await timedRequest('unit', async () => {});
  assert(getCounter('broker_http_requests_total{route="unit"}') === 1, 'timed counter');
}

console.log('=== log ===');
{
  assert(typeof log.info === 'function', 'log.info');
  log.info('test_phase_c', { ok: true }); // visible JSON line
}

console.log('=== /ready /live ===');
{
  const res = { status: 0, body: null };
  const send = (r, s, b) => { r.status = s; r.body = b; };
  handleHealth({}, res, { method: 'GET', pathname: '/live' }, { send, secretCache: new Map(), config: {} });
  assert(res.body?.status === 'live', 'live');
  handleHealth({}, res, { method: 'GET', pathname: '/ready' }, {
    send, secretCache: new Map([['a', 1]]), config: { services: {} }, requireSops: true,
  });
  assert(res.status === 200 && res.body?.status === 'ready', 'ready');
  handleHealth({}, res, { method: 'GET', pathname: '/ready' }, {
    send, secretCache: new Map(), config: {}, requireSops: true,
  });
  assert(res.status === 503, 'not ready');
}

console.log('=== /metrics ===');
{
  const res = {
    status: 0, body: null, headers: {},
    writeHead(s, h) { this.status = s; this.headers = h; },
    end(b) { this.body = b; },
  };
  handleMetrics({}, res, { method: 'GET', pathname: '/metrics' }, {
    send: (r, s, b) => { r.status = s; r.body = b; },
    version: BROKER_VERSION,
  });
  assert(res.status === 200 && String(res.body).includes('broker_up'), 'metrics text');
  handleMetrics({}, res, { method: 'GET', pathname: '/metrics.json' }, {
    send: (r, s, b) => { r.status = s; r.body = b; },
    version: BROKER_VERSION,
  });
  assert(res.body?.counters !== undefined, 'metrics json');
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
