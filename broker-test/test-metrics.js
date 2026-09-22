// broker-test/test-metrics.js — V4.7.0 lib/metrics.js 单元测试
// 覆盖 inc / getCounter / observeMs / snapshot / prometheusText /
// _resetMetricsForTests / timedRequest

import {
  inc,
  getCounter,
  observeMs,
  snapshot,
  prometheusText,
  _resetMetricsForTests,
  timedRequest,
} from '../broker/lib/metrics.js';

let pass = 0,
  fail = 0;
function ok(name, cond, detail) {
  if (cond) {
    pass++;
    console.log(`  PASS  ${name}`);
  } else {
    fail++;
    console.error(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`);
  }
}
function section(t) {
  console.log(`\n[${t}]`);
}

_resetMetricsForTests();

// ============================================================
// inc / getCounter
// ============================================================
section('inc / getCounter');
{
  inc('plain');
  ok('inc adds default 1', getCounter('plain') === 1);
  inc('plain', 5);
  ok('inc adds explicit amount', getCounter('plain') === 6);
  inc('plain', 4);
  ok('inc adds another explicit amount', getCounter('plain') === 10);

  inc('labeled', 2, { route: 'GET /api/v1/me' });
  inc('labeled', 3, { route: 'GET /api/v1/me' });
  ok('labeled counter increments separately', getCounter('labeled{route="GET /api/v1/me"}') === 5);

  inc('labeled', 1, { route: 'POST /api/v1/secrets' });
  ok(
    'different labels are separate counters',
    getCounter('labeled{route="POST /api/v1/secrets"}') === 1,
  );

  ok('unknown counter returns 0', getCounter('does-not-exist') === 0);

  // Label with quote / backslash escaping
  inc('tricky', 1, { msg: 'has "quote" and \\back' });
  ok(
    'label with quote and backslash does not throw',
    getCounter('tricky{msg="has \\"quote\\" and \\\\back"}') === 1,
  );
}

// ============================================================
// observeMs
// ============================================================
section('observeMs');
{
  _resetMetricsForTests();
  // DEFAULT_BUCKETS = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000]
  observeMs('lat', 3);
  observeMs('lat', 7);
  observeMs('lat', 50);
  observeMs('lat', 500);
  observeMs('lat', 5000);
  observeMs('lat', 99999); // 远超最大 bucket
  const s = snapshot();
  ok('histogram count tracks observations', s.histograms.lat.count === 6);
  ok(
    'histogram sum tracks total',
    Math.abs(s.histograms.lat.sum_ms - (3 + 7 + 50 + 500 + 5000 + 99999)) < 0.01,
  );
  // bucket 5 应有 1 (lat=7 > 5,所以不计入;重新算:7>5 不计入,50>10 不计入 5,但 ≤ 10? 我们的 buckets 是 [5,10,...], 7 > 5 不计入 5
  ok(
    'bucket le=5 captures ms<=5 (cumulative)',
    s.histograms.lat.buckets[0].le === 5 && s.histograms.lat.buckets[0].count === 1,
  );
  ok(
    'bucket le=100 captures ms<=100 (cumulative)',
    s.histograms.lat.buckets[4].le === 100 && s.histograms.lat.buckets[4].count === 3,
  );
  ok('bucket le=+Inf (=count) captures all', s.histograms.lat.count === 6);
}

// ============================================================
// custom bucket boundaries
// ============================================================
section('observeMs with custom buckets');
{
  _resetMetricsForTests();
  // custom [1, 5, 10]; observeMs 累积:counts[i] 累加 ms<=buckets[i] 的次数
  observeMs('custom', 0, [1, 5, 10]); // ≤ 1, ≤ 5, ≤ 10 → bucket counts += 1
  observeMs('custom', 3, [1, 5, 10]); // 3>1 不计; ≤5, ≤10 → += 1
  observeMs('custom', 8, [1, 5, 10]); // 8>1, 8>5 不计; ≤10 → += 1
  observeMs('custom', 100, [1, 5, 10]); // 远超,均不计
  const s = snapshot();
  ok('custom buckets length respected', s.histograms.custom.buckets.length === 3);
  ok('custom bucket le=1 counts only ms<=1', s.histograms.custom.buckets[0].count === 1);
  ok('custom bucket le=5 counts ms<=5 (cumulative)', s.histograms.custom.buckets[1].count === 2);
  ok('custom bucket le=10 counts ms<=10 (cumulative)', s.histograms.custom.buckets[2].count === 3);
  ok('histogram count tracks total observations', s.histograms.custom.count === 4);
}

// ============================================================
// snapshot
// ============================================================
section('snapshot');
{
  _resetMetricsForTests();
  inc('test_counter');
  const s = snapshot();
  ok('snapshot has started_at', typeof s.started_at === 'string' && s.started_at.endsWith('Z'));
  ok('snapshot has uptime_seconds', typeof s.uptime_seconds === 'number' && s.uptime_seconds >= 0);
  ok('snapshot has process_uptime_seconds', typeof s.process_uptime_seconds === 'number');
  ok('snapshot has memory', typeof s.memory.rss === 'number');
  ok('snapshot counters include test_counter', s.counters.test_counter === 1);
}

// ============================================================
// prometheusText
// ============================================================
section('prometheusText');
{
  _resetMetricsForTests();
  inc('http_requests', 3);
  observeMs('http_duration_ms', 25);
  const text = prometheusText({ service: 'broker' });
  ok('contains broker_up gauge', text.includes('broker_up{service="broker"} 1'));
  ok('contains broker_uptime_seconds', text.includes('broker_uptime_seconds{service="broker"}'));
  ok('contains counter # TYPE', text.includes('# TYPE http_requests counter'));
  ok('contains counter value', text.includes('http_requests{service="broker"} 3'));
  ok('contains histogram # TYPE', text.includes('# TYPE http_duration_ms histogram'));
  ok(
    'contains histogram bucket le=10',
    text.includes('http_duration_ms_bucket{service="broker",le="10"}'),
  );
  ok(
    'contains histogram +Inf bucket',
    text.includes('http_duration_ms_bucket{service="broker",le="+Inf"}'),
  );
  ok('contains histogram sum', text.includes('http_duration_ms_sum{service="broker"}'));
  ok('contains histogram count', text.includes('http_duration_ms_count{service="broker"}'));
  // no extra labels
  const text2 = prometheusText();
  ok(
    'no labels → plain name',
    text2.includes('# TYPE http_requests counter') && text2.includes('http_requests 3'),
  );
}

// ============================================================
// _resetMetricsForTests
// ============================================================
section('_resetMetricsForTests');
{
  inc('will_reset');
  observeMs('will_reset_hist', 10);
  ok('counter exists before reset', getCounter('will_reset') === 1);
  _resetMetricsForTests();
  ok('counter cleared after reset', getCounter('will_reset') === 0);
  ok('histogram cleared after reset', snapshot().histograms.will_reset_hist === undefined);
}

// ============================================================
// timedRequest
// ============================================================
section('timedRequest');
{
  _resetMetricsForTests();
  const result = await timedRequest('GET /api/v1/me', async () => {
    await new Promise((r) => setTimeout(r, 5));
    return 'ok';
  });
  ok('timedRequest returns handler result', result === 'ok');
  ok(
    'timedRequest records duration',
    getCounter('broker_http_requests_total{route="GET /api/v1/me"}') === 1,
  );
  const s = snapshot();
  ok(
    'timedRequest observes latency histogram',
    s.histograms.broker_http_request_duration_ms.count === 1,
  );

  // Error path still records
  let threw = false;
  try {
    await timedRequest('BAD', async () => {
      throw new Error('boom');
    });
  } catch {
    threw = true;
  }
  ok('timedRequest propagates error', threw);
  ok(
    'timedRequest still records on error',
    getCounter('broker_http_requests_total{route="BAD"}') === 1,
  );
}

console.log(`\n=== Total: ${pass} passed, ${fail} failed ===`);
process.exit(fail > 0 ? 1 : 0);
