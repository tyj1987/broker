# Phase D — Tracing & audit policy

**Version**: 3.6.0  
**Constraint**: zero new npm dependencies.

## Trace context (W3C)

```js
import { continueOrCreateTrace, outboundTraceHeaders } from './lib/trace.js';
import { runWithRequestContext, setResponseTraceHeaders } from './lib/request-context.js';

// Around handle(req, res):
runWithRequestContext(req.headers, async () => {
  setResponseTraceHeaders(res);
  // ... existing handle logic
});

// When proxying upstream:
const headers = {
  ...upstreamHeaders,
  ...outboundTraceHeaders({
    traceparent: getTraceparent(),
    requestId: getRequestId(),
  }),
};
```

Incoming `traceparent` is continued (same `trace-id`, new `span-id`).  
Also accepts/propagates `x-request-id` / `x-correlation-id`.

## Audit sampling & retention

```js
import { withAuditSampling, pruneAuditFiles, auditPolicyFromEnv } from './lib/audit-policy.js';

const policy = auditPolicyFromEnv();
const audit = withAuditSampling(rawAudit, policy);

// cron / startup:
pruneAuditFiles(AUDIT_DIR, policy.retainDays);
```

| Env | Default | Meaning |
|-----|---------|---------|
| `AUDIT_SAMPLE_RATE` | `1` | 0–1; login/denied/error always kept |
| `AUDIT_RETAIN_DAYS` | `30` | delete older `audit-YYYY-MM-DD.jsonl` |

## Tests

```bash
cd broker && npm run test:trace
npm run test:modular
```

## Wire checklist (server.js)

1. Wrap `handle` body in `runWithRequestContext(req.headers, ...)`
2. `setResponseTraceHeaders(res)` early
3. Merge `outboundTraceHeaders` in proxy upstream fetch
4. Optional: `withAuditSampling` around `audit`
5. Daily `pruneAuditFiles` in existing cron-tasks

## Next (Phase E ideas)

- Config schema validation hardening
- Graceful shutdown + drain
- Optional OpenTelemetry exporter (would add dependency — opt-in package)
