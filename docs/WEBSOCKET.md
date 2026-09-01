# WebSocket Events (V4.1)

> **Goal**: real-time event stream so AI clients and dashboards see broker
> activity without polling.

## Endpoint

`wss://broker.example.com:8443/ws`

- mTLS client certificate required (same as REST)
- 30-second server-initiated ping
- 60-second client activity timeout (any inbound message resets timer)

## Subscribe protocol

Client sends:
```json
{
  "action": "subscribe",
  "events": ["alerts", "secret_rotated", "audit"],
  "filter": { "severity_eq": "critical" }
}
```

Server replies:
```json
{
  "type": "ack",
  "ack_type": "subscribed",
  "events": ["alerts", "secret_rotated", "audit"],
  "ts": "2026-09-01T08:35:00.123Z"
}
```

Other actions: `unsubscribe`, `ping`, `list_events`.

## Event types

| Event | Payload example |
|-------|-----------------|
| `audit` | `{ action: "secret.resolve", cn: "ai-agent-1", status: "ok", ... }` |
| `healthcheck` | `{ status: "ok", version: "4.1.0" }` |
| `alerts` | `{ severity: "critical", title: "secret.expired", detail: "github.pat is 3 days past rotation" }` |
| `secret_rotated` | `{ name: "github.pat", type: "github_pat", ts: "..." }` |
| `mfa_enrolled` | `{ cn: "user1", factor: "webauthn", ts: "..." }` |
| `config_reloaded` | `{ source: "broker.yaml", ts: "..." }` |
| `*` | wildcard — receives all events |

## Filter

```json
{ "severity_eq": "critical" }       // exact match
{ "severity_gte": "high" }         // info < warning < medium < high < critical
```

## Event format

Server pushes:
```json
{
  "type": "event",
  "event_type": "alerts",
  "ts": "2026-09-01T08:35:00.123Z",
  "data": {
    "severity": "critical",
    "title": "secret.expired",
    "detail": "github.pat last rotated 2026-05-01 (>90d)"
  },
  "request_id": "..."   // optional, present if event tied to a request
}
```

All fields in `data` are auto-redacted by the broker's redact engine before
serialization. So if a payload accidentally contains `ghp_xxxx`, the
client receives `[REDACTED_GITHUB]`.

## Client examples

### Python (asyncio)

```python
import asyncio
from secret_broker import BrokerClient

async def watch():
    c = BrokerClient(endpoint="...", client_cert="...", client_key="...", ca_cert="...")
    async with await c.async_client().connect_ws() as ws:
        await ws.subscribe(["alerts", "secret_rotated"])
        async for event in ws:
            print(event)

asyncio.run(watch())
```

### Go

```go
ws, _ := broker.WSConnect("https://broker:8443", "/ws", nil)
defer ws.Close()
ws.Subscribe([]string{"alerts", "secret_rotated"}, nil)
for {
    msg, err := ws.Recv()
    if err != nil { break }
    fmt.Printf("[%s] %s\n", msg.EventType, msg.Data)
}
```

### Browser JavaScript

```javascript
const ws = new WebSocket('wss://broker:8443/ws', {
  // mTLS via custom transport — use a proxy that adds the client cert
});
ws.onopen = () => {
  ws.send(JSON.stringify({ action: 'subscribe', events: ['alerts'] }));
};
ws.onmessage = (e) => {
  const event = JSON.parse(e.data);
  console.log(event);
};
```

(Note: browser WebSocket does not support mTLS natively; use a TLS-terminating
proxy like nginx with `ssl_client_certificate` + `ssl_verify_client on`.)

### Node (using `ws` package)

```javascript
import WebSocket from 'ws';
import { readFileSync } from 'fs';

const ws = new WebSocket('wss://broker:8443/ws', {
  cert: readFileSync('client.crt'),
  key: readFileSync('client.key'),
  ca: readFileSync('ca.crt'),
  rejectUnauthorized: true,
});
ws.on('open', () => {
  ws.send(JSON.stringify({ action: 'subscribe', events: ['alerts'] }));
});
ws.on('message', (data) => console.log(JSON.parse(data.toString())));
```

## Health & status

Inspect active subscribers:
```bash
curl --cert client.crt --key client.key --cacert ca.crt \
  https://broker:8443/api/v1/ws-stats
# (admin endpoint, not yet implemented — see TODO)
```

For now, the broker exposes subscriber count and event subscriptions via
Prometheus metrics:
- `broker_ws_subscribers` (gauge, current count)
- `broker_ws_broadcasts_total` (counter, total events broadcast)

## Backpressure

If a client is slow to consume, the broker drops the connection after 60
seconds of inactivity. The client should reconnect with exponential backoff
and replay missed events via REST audit log.

## Testing

`broker-test/test-ws.js` (27 tests):
- pub/sub mechanics
- wildcard subscription
- unsubscribe
- event filter (severity_eq / severity_gte)
- zero credential leakage in broadcast payload
- end-to-end WS connection via real port
- stats + list metadata

## Limits

- Max 1000 concurrent subscribers per broker instance (raise via env `WS_MAX_SUBSCRIBERS`)
- Max 10 MB per event payload (raise via `WS_MAX_PAYLOAD_BYTES`)
- No message ordering guarantee across publishers; events are FIFO per-publisher

## Why not SSE?

Server-Sent Events are unidirectional (server → client) and don't allow
subscriptions to specific event types. WebSocket is bidirectional and lets
the client dynamically adjust its filter without reconnecting.
