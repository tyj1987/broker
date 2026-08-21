# Phase C — Observability

**Version**: 3.5.0  
**Constraint**: zero new npm dependencies.

## Endpoints

| Path | Purpose |
|------|---------|
| `GET /health` | Status + version + services + uptime |
| `GET /live` / `/healthz` | Liveness (process up) |
| `GET /ready` / `/readyz` | Readiness (config; optional SOPS) |
| `GET /metrics` | Prometheus text |
| `GET /metrics.json` | JSON snapshot (counters, histograms, memory) |

Lock metrics behind admin:

```bash
METRICS_REQUIRE_AUTH=1
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
