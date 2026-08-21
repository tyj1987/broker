// broker/lib/metrics.js — in-process counters + latency histograms (no deps)
// Phase C observability. Prometheus text exposition optional.

const STARTED_AT = Date.now();

/** @type {Map<string, number>} */
const counters = new Map();

/**
 * Simple fixed-bucket latency histogram (ms).
 * buckets: le values in milliseconds
 */
const DEFAULT_BUCKETS = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000];

/** @type {Map<string, { buckets: number[], counts: number[], sum: number, count: number }>} */
const histograms = new Map();

export function inc(name, by = 1, labels = null) {
  const key = labels ? `${name}{${formatLabels(labels)}}` : name;
  counters.set(key, (counters.get(key) || 0) + by);
}

export function getCounter(name) {
  return counters.get(name) || 0;
}

/**
 * Observe latency in milliseconds.
 * @param {string} name
 * @param {number} ms
 * @param {number[]} [bucketBounds]
 */
export function observeMs(name, ms, bucketBounds = DEFAULT_BUCKETS) {
  let h = histograms.get(name);
  if (!h) {
    h = {
      buckets: bucketBounds.slice(),
      counts: bucketBounds.map(() => 0),
      sum: 0,
      count: 0,
    };
    histograms.set(name, h);
  }
  h.sum += ms;
  h.count += 1;
  for (let i = 0; i < h.buckets.length; i++) {
    if (ms <= h.buckets[i]) h.counts[i] += 1;
  }
}

function formatLabels(labels) {
  return Object.entries(labels)
    .map(([k, v]) => `${k}="${String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`)
    .join(',');
}

/** Snapshot for JSON /health extras or /metrics.json */
export function snapshot() {
  const counterObj = Object.fromEntries(counters.entries());
  const histObj = {};
  for (const [name, h] of histograms) {
    histObj[name] = {
      count: h.count,
      sum_ms: Math.round(h.sum * 1000) / 1000,
      avg_ms: h.count ? Math.round((h.sum / h.count) * 1000) / 1000 : 0,
      buckets: h.buckets.map((le, i) => ({ le, count: h.counts[i] })),
    };
  }
  return {
    started_at: new Date(STARTED_AT).toISOString(),
    uptime_seconds: Math.floor((Date.now() - STARTED_AT) / 1000),
    process_uptime_seconds: Math.floor(process.uptime()),
    memory: process.memoryUsage(),
    counters: counterObj,
    histograms: histObj,
  };
}

/** Prometheus text format (subset) */
export function prometheusText(extraLabels = {}) {
  const lines = [];
  const el = formatLabels(extraLabels);
  const suffix = el ? `{${el}}` : '';

  lines.push('# HELP broker_up Broker process up');
  lines.push('# TYPE broker_up gauge');
  lines.push(`broker_up${suffix} 1`);

  lines.push('# HELP broker_uptime_seconds Uptime since metrics module load');
  lines.push('# TYPE broker_uptime_seconds gauge');
  lines.push(`broker_uptime_seconds${suffix} ${Math.floor((Date.now() - STARTED_AT) / 1000)}`);

  for (const [key, val] of counters) {
    // key may already contain labels
    if (key.includes('{')) {
      const base = key.slice(0, key.indexOf('{'));
      const lab = key.slice(key.indexOf('{'));
      lines.push(`# TYPE ${base} counter`);
      lines.push(`${base}${lab} ${val}`);
    } else {
      lines.push(`# TYPE ${key} counter`);
      lines.push(`${key}${suffix} ${val}`);
    }
  }

  for (const [name, h] of histograms) {
    lines.push(`# TYPE ${name} histogram`);
    let cumulative = 0;
    // re-read: counts[i] is already cumulative "le" style if we increment all matching
    // Our observeMs increments every bucket where ms <= le, so counts are cumulative.
    for (let i = 0; i < h.buckets.length; i++) {
      const le = h.buckets[i];
      const lab = el
        ? `{${el},le="${le}"}`
        : `{le="${le}"}`;
      lines.push(`${name}_bucket${lab} ${h.counts[i]}`);
    }
    const infLab = el ? `{${el},le="+Inf"}` : `{le="+Inf"}`;
    lines.push(`${name}_bucket${infLab} ${h.count}`);
    lines.push(`${name}_sum${suffix} ${h.sum}`);
    lines.push(`${name}_count${suffix} ${h.count}`);
  }

  return lines.join('\n') + '\n';
}

/** Reset (tests only) */
export function _resetMetricsForTests() {
  counters.clear();
  histograms.clear();
}

/**
 * Wrap async handler timing: records broker_http_request_duration_ms + counter.
 */
export function timedRequest(routeKey, fn) {
  const t0 = Date.now();
  return Promise.resolve()
    .then(() => fn())
    .finally(() => {
      const ms = Date.now() - t0;
      observeMs('broker_http_request_duration_ms', ms);
      inc('broker_http_requests_total', 1, { route: routeKey });
    });
}
