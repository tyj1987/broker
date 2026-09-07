# Phase C — Observability

**Version**: 3.5.0  
**Constraint**: zero new npm dependencies.

## Endpoints

| Path | Purpose |
|------|---------|
| `GET /health` (public HTTPS) | `{ "status": "ok" }` only — probes and load balancers |
| `GET /api/v1/health` (auth) | version, sops_loaded, services_count, uptime |
| Local socket `/health` `/ready` `/live` | Full ops / readiness (loopback or unix, mode 0600) |
| `GET /live` / `/healthz` | Liveness (process up). Public body is `{status:live}` |
| `GET /ready` / `/readyz` | Readiness — **local socket only** (config + optional SOPS + probes) |
| `GET /metrics` | Prometheus text — **local or admin** by default |
| `GET /metrics.json` | JSON snapshot (counters, histograms, memory) |

Anonymous metrics scrape (old default):

```bash
METRICS_PUBLIC=1
```

## Library

```js
import { inc, observeMs, timedRequest, snapshot } from './lib/metrics.js';
import { log } from './lib/log.js';

inc('broker_proxy_total', 1, { service: 'github' });
observeMs('broker_http_request_duration_ms', 42);
log.info('proxy_ok', { service: 'github', ms: 42 });
```

Log level: `BROKER_LOG_LEVEL=debug|info|warn|error` (default `info`).

## Wire into server.js (manual / later)

After identity + route match:

```js
import { inc, observeMs } from './lib/metrics.js';
import { log } from './lib/log.js';
import { handleMetrics } from './routes/metrics.js';

// early public:
if (handleMetrics(req, res, route, deps)) return;

// end of handle():
observeMs('broker_http_request_duration_ms', Date.now() - t0);
inc('broker_http_requests_total', 1, { route: p });
```

## Tests

```bash
cd broker && npm run test:obs
# or
npm run test:modular
```

## Next (Phase D ideas)

- Distributed tracing headers (traceparent) propagation on proxy
- Audit log sampling + retention policy helpers
- Multi-instance metrics via shared store (Redis) — would add a dep or stay per-node
