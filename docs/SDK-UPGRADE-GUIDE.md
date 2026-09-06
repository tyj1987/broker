# SDK Upgrade Guide — V4.1.0 → V4.1.1

> **For users of broker V4.1.0 SDKs (Python, Go, Node CLI, VSCode) who are
> upgrading to V4.1.1.** This guide covers only what changed. For complete
> API docs, see [SDK-REFERENCE.md](SDK-REFERENCE.md).

**TL;DR**: V4.1.1 SDK changes are **backward-compatible**. Your V4.1.0 SDK code
continues to work unchanged. New fields are additive; old error classes
(`BrokerAuthError` / `ErrAuth` / etc.) are deprecated but still exported for
one release.

**Recommended actions** (in order):

1. **No code changes required** — your existing V4.1.0 SDK code works.
2. **(Optional) Switch to the new `BrokerError` pattern** for richer error
   context (`code`, `requestId`, `retryAfter`).
3. **(Optional) Enable built-in retry** with `maxRetries=2` (default) — gives
   you free 5xx / 429 / connection retries.
4. **Run the new tests** to verify your integration still works.

---

## What changed (at a glance)

| Aspect | V4.1.0 | V4.1.1 |
|--------|--------|--------|
| Error model | 6 typed classes per SDK (`BrokerAuthError`, etc.) | 1 unified `BrokerError` + `BrokerConnectionError` |
| Error fields | `op`, `status`, `body` | + `code`, `requestId`, `retryAfter`, `isRetryable` (getter) |
| Error methods | `message` only | + `toString()`, `toJSON()` (body omitted) |
| Body redaction | Caller responsible | **Auto-redact on construction** (defense in depth) |
| Retry | Manual / none | Built-in `maxRetries` + exponential backoff + `Retry-After` override |
| Factory | None | `parseBrokerError(status, headers, body, op)` |
| Backward compat | – | ✅ V4.1.0 code works; old classes deprecated but exported |

---

## Python

### Before (V4.1.0)

```python
from secret_broker import BrokerClient, BrokerAuthError, BrokerRateLimitError

c = BrokerClient("https://broker:8443", ca_cert="ca.pem")

try:
    secret = c.get_secret("github.pat")
    print(secret)
except BrokerAuthError as e:
    print(f"auth failed: {e}")
except BrokerRateLimitError as e:
    print(f"rate limited: {e}")
```

### After (V4.1.1) — same code still works

```python
from secret_broker import BrokerClient, BrokerError, BrokerConnectionError

c = BrokerClient("https://broker:8443", ca_cert="ca.pem")

try:
    secret = c.get_secret("github.pat")
    print(secret)
except BrokerError as e:
    # e.code, e.request_id, e.retry_after, e.is_retryable now available
    if e.status == 401 or e.code == "auth_failed":
        print(f"auth failed: {e} (request_id={e.request_id})")
    elif e.is_retryable:
        # SDK already retried up to max_retries; surface for upper layers
        print(f"retryable: {e}")
except BrokerConnectionError as e:
    # network-level failure (TLS, ECONNREFUSED, ETIMEDOUT, ...)
    print(f"connection failed: {e} cause={e.cause}")
```

### New: opt-in to structured error context

```python
# Inspect a raw response (useful for middleware)
from secret_broker import parse_broker_error

err = parse_broker_error(
    status=429,
    headers={"x-request-id": "req-abc", "retry-after": "30"},
    body={"error": {"code": "rate_limited", "message": "slow down"}},
    op="get_secret",
)
assert err.status == 429
assert err.code == "rate_limited"
assert err.request_id == "req-abc"
assert err.retry_after == 30
assert err.is_retryable is True
assert "request_id=req-abc" in str(err)
```

### New: enable built-in retry

```python
# Default: max_retries=2 (3 total attempts), retry_backoff_ms=500
c = BrokerClient("https://broker:8443", ca_cert="ca.pem")

# Customize:
c = BrokerClient(
    "https://broker:8443",
    ca_cert="ca.pem",
    max_retries=5,           # retry up to 5 times (6 total attempts)
    retry_backoff_ms=1000,   # start with 1s, double each retry
)

# Disable:
c = BrokerClient("https://broker:8443", ca_cert="ca.pem", max_retries=0)
```

### Deprecation timeline

- V4.1.1 (this release): `BrokerAuthError` / `BrokerRateLimitError` / etc.
  **still exported**, but emit a `DeprecationWarning` on import.
- V4.2.0 (Q2 2027): old classes removed. Migrate to `BrokerError` + `status` /
  `code` checks.

---

## Go

### Before (V4.1.0)

```go
package main

import (
    "errors"
    "fmt"
    broker "github.com/tyj1987/broker-sdk-go"
)

func main() {
    c := broker.New("https://broker:8443", broker.Config{CACert: "ca.pem"})
    val, err := c.GetSecret("github.pat")
    if errors.Is(err, broker.ErrAuth) {
        fmt.Println("auth failed")
        return
    }
    if err != nil {
        fmt.Println("error:", err)
        return
    }
    fmt.Println(val)
}
```

### After (V4.1.1) — same code still works

```go
package main

import (
    "errors"
    "fmt"
    broker "github.com/tyj1987/broker-sdk-go"
)

func main() {
    c := broker.New("https://broker:8443", broker.Config{
        CACert:         "ca.pem",
        MaxRetries:     2,    // V4.1.1: built-in retry
        RetryBackoffMs: 500,  // V4.1.1: start with 500ms, double each retry
    })
    val, err := c.GetSecret("github.pat")
    var berr *broker.BrokerError
    if errors.As(err, &berr) {
        // berr.Code, berr.RequestID, berr.RetryAfter, berr.IsRetryable()
        if berr.Status == 401 || berr.Code == "auth_failed" {
            fmt.Printf("auth failed: %s (request_id=%s)\n", berr, berr.RequestID)
            return
        }
        if berr.IsRetryable() {
            fmt.Printf("retryable error: %s\n", berr)
        }
    }
    var cerr *broker.BrokerConnectionError
    if errors.As(err, &cerr) {
        fmt.Printf("connection failed: %s cause=%v\n", cerr, cerr.Cause)
    }
    if err != nil {
        fmt.Println("error:", err)
        return
    }
    fmt.Println(val)
}
```

### New: opt-in to structured error context

```go
err := broker.ParseBrokerError(
    429,
    map[string][]string{
        "x-request-id": {"req-abc"},
        "retry-after":  {"30"},
    },
    []byte(`{"error":{"code":"rate_limited","message":"slow down"}}`),
    "get_secret",
)
fmt.Println(err.Status())    // 429
fmt.Println(err.Code())      // rate_limited
fmt.Println(err.RequestID()) // req-abc
fmt.Println(err.RetryAfter()) // 30
fmt.Println(err.IsRetryable()) // true
fmt.Println(err.ToMap())      // map[code:rate_limited ...]
```

### New: enable built-in retry

```go
c := broker.New("https://broker:8443", broker.Config{
    CACert:         "ca.pem",
    MaxRetries:     2,    // default; up to 3 total attempts
    RetryBackoffMs: 500,  // default; doubled each retry (500ms → 1s → 2s)
})

// Disable:
c := broker.New("https://broker:8443", broker.Config{
    CACert:     "ca.pem",
    MaxRetries: 0,
})
```

### Deprecation timeline

- V4.1.1 (this release): `ErrAuth` / `ErrPermission` / `ErrNotFound` / etc.
  **still exported** but documented as deprecated in godoc.
- V4.2.0 (Q2 2027): old error sentinels removed. Migrate to
  `errors.As(err, &berr)` + `berr.Status` / `berr.Code` checks.

---

## Node CLI (Mavis / mavis / AI agents)

### Before (V4.1.0)

```javascript
import { BrokerClient, BrokerAuthError } from './secret-broker.js';

const c = new BrokerClient({
  endpoint: 'https://broker:8443',
  caCert: 'ca.pem',
});

try {
  const secret = await c.getSecret('github.pat');
  console.log(secret);
} catch (e) {
  if (e instanceof BrokerAuthError) {
    console.error('auth failed:', e.message);
  } else {
    console.error('error:', e.message);
  }
}
```

### After (V4.1.1) — same code still works (BrokerAuthError re-exported)

```javascript
import { BrokerClient, BrokerError, BrokerConnectionError, parseBrokerError } from './secret-broker.js';

const c = new BrokerClient({
  endpoint: 'https://broker:8443',
  caCert: 'ca.pem',
  maxRetries: 2,        // V4.1.1: built-in retry (default)
  retryBackoffMs: 500,  // V4.1.1: start with 500ms, double each retry
});

try {
  const secret = await c.getSecret('github.pat');
  console.log(secret);
} catch (e) {
  if (e instanceof BrokerError) {
    if (e.status === 401 || e.code === 'auth_failed') {
      console.error(`auth failed: ${e} (request_id=${e.requestId})`);
    } else if (e.isRetryable) {
      // SDK already retried up to maxRetries; surface for upper layers
      console.error(`retryable: ${e}`);
    } else {
      console.error(`error: ${e}`);
    }
  } else if (e instanceof BrokerConnectionError) {
    console.error(`connection failed: ${e} cause=${e.cause}`);
  }
}
```

### New: opt-in to structured error context

```javascript
const err = parseBrokerError(
  429,
  { 'x-request-id': 'req-abc', 'retry-after': '30' },
  { error: { code: 'rate_limited', message: 'slow down' } },
  'get_secret'
);
console.log(err.status);       // 429
console.log(err.code);         // rate_limited
console.log(err.requestId);    // req-abc
console.log(err.retryAfter);   // 30
console.log(err.isRetryable);  // true
console.log(err.toString());   // BrokerError: slow down [status=429 code=rate_limited request_id=req-abc retry_after=30s]
console.log(err.toJSON());     // { error_type: 'BrokerError', ... body omitted }
```

### New: enable built-in retry

```javascript
const c = new BrokerClient({
  endpoint: 'https://broker:8443',
  caCert: 'ca.pem',
  // Defaults (no need to set):
  // maxRetries: 2,
  // retryBackoffMs: 500,
});

// Disable:
const cNoRetry = new BrokerClient({
  endpoint: 'https://broker:8443',
  caCert: 'ca.pem',
  maxRetries: 0,
});
```

### CLI exit code mapping (V4.1.1)

| Exit code | Meaning |
|-----------|---------|
| 0 | Success |
| 1 | Generic error |
| 2 | Auth error (401/403) |
| 3 | Rate limited (429) |
| 4 | Server error (5xx) |
| 5 | Connection error |

---

## VS Code extension (Cursor / Windsurf / VSCodium)

### Before (V4.1.0)

```typescript
import { BrokerClient, BrokerError } from './client';

const c = new BrokerClient({
  endpoint: 'https://broker:8443',
  caCert: 'ca.pem',
});

try {
  const secret = await c.getSecret('github.pat');
  vscode.window.showInformationMessage(`Got: ${secret}`);
} catch (e) {
  if (e instanceof BrokerError) {
    vscode.window.showErrorMessage(`broker error: ${e.message}`);
  }
}
```

### After (V4.1.1) — same code still works (BrokerError signature compatible)

```typescript
import { BrokerClient, BrokerError, BrokerConnectionError, parseBrokerError } from './client';

const c = new BrokerClient({
  endpoint: 'https://broker:8443',
  caCert: 'ca.pem',
  maxRetries: 2,        // V4.1.1: built-in retry
  retryBackoffMs: 500,  // V4.1.1: start with 500ms, double each retry
});

try {
  const secret = await c.getSecret('github.pat');
  vscode.window.showInformationMessage(`Got: ${secret}`);
} catch (e) {
  if (e instanceof BrokerError) {
    if (e.status === 401 || e.code === 'auth_failed') {
      vscode.window.showErrorMessage(`Auth failed (request_id=${e.requestId})`);
    } else if (e.isRetryable) {
      vscode.window.showWarningMessage(`Transient: ${e}`);
    } else {
      vscode.window.showErrorMessage(`broker error: ${e}`);
    }
  } else if (e instanceof BrokerConnectionError) {
    vscode.window.showErrorMessage(`Cannot reach broker: ${e.message}`);
  }
}
```

### New: opt-in to structured error context

```typescript
const err = parseBrokerError(
  429,
  { 'x-request-id': 'req-abc', 'retry-after': '30' },
  { error: { code: 'rate_limited', message: 'slow down' } },
  'get_secret'
);
console.log(err.status);        // 429
console.log(err.code);          // rate_limited
console.log(err.requestId);     // req-abc
console.log(err.retryAfter);    // 30
console.log(err.isRetryable);   // true
console.log(err.toString());    // BrokerError: slow down [status=429 ...]
console.log(err.toJSON());      // { error_type: 'BrokerError', op, status, code, ... }
```

### New: enable built-in retry

```typescript
const c = new BrokerClient({
  endpoint: 'https://broker:8443',
  caCert: 'ca.pem',
  // Defaults:
  // maxRetries: 2,
  // retryBackoffMs: 500,
});
```

### Deprecation timeline

- V4.1.1 (this release): old `new BrokerError(op, status, body)` constructor
  signature **still works** (extra fields default to empty). New options
  parameter is optional.
- V4.2.0 (Q2 2027): no breaking change planned; old signature continues to
  work but the deprecation note in TSDoc recommends the new
  `parseBrokerError` factory.

---

## Test your integration

Each SDK now ships a richer test suite you can run against your own broker
endpoint to verify your integration still works after the upgrade.

### Python

```bash
cd sdk/python
pip install -e ".[test]"
pytest tests/ -q
# Expected: 54 passed
```

### Go

```bash
cd sdk/go
go test ./...
# Expected: ok   ... 33 passed (1 SKIP)
```

### Node CLI

```bash
cd cli
node --test test-error.js
# Expected: tests 21, pass 21
```

### VS Code

```bash
cd sdk/vscode
npm install
npm run build
node ./out/test/error.test.js
# Expected: 38 passed, 0 failed
```

---

## Common pitfalls

### 1. "My retry loop is double-retrying"

If you had your own retry loop, you may now be retrying on top of the SDK's
built-in retry. Either:

- Set `maxRetries=0` to disable SDK retry, or
- Remove your own retry loop and let the SDK handle it.

### 2. "I caught `BrokerAuthError` but now it doesn't catch"

V4.1.1 throws `BrokerError` with `status === 401` instead of
`BrokerAuthError`. Either:

- Catch `BrokerError` and check `e.status === 401`, or
- Catch `BrokerError` and check `e.code === 'auth_failed'`.

The old `BrokerAuthError` class is still exported (V4.1.1) for backward
compat but is a thin wrapper that just re-exports `BrokerError` with a
fixed `status === 401` filter. Best practice: migrate to the new pattern.

### 3. "Retry-After header is now respected (was ignored before)"

The broker has always returned `Retry-After: <seconds>` on 429 responses.
V4.1.0 SDKs ignored it. V4.1.1 SDKs honor it. If you have rate-limit logic
that depended on fixed delays, your effective wait time may now match the
broker's hint (longer than your hardcoded value). This is the intended
behavior — it prevents thundering herd.

### 4. "Body is no longer in toString() output"

V4.1.0: `e.toString()` or `str(e)` could include raw response body (with
secrets redacted at point of receipt, but if redaction missed something,
it'd leak).

V4.1.1: `toString()` includes only `status` / `code` / `request_id` /
`retry_after`. `body` is still accessible via `e.body` (redacted on
construction) but is **omitted from `toJSON()` entirely** (logging / audit
safety). If you need to debug response body, log `e.body` explicitly.

---

## When to migrate (vs. stay on V4.1.0)

| Your situation | Recommendation |
|----------------|----------------|
| Using V4.1.0 SDK, integration works fine | Stay on V4.1.0 indefinitely; SDK auto-upgrade is safe but not required. |
| Need richer error context (e.g. for monitoring / audit) | Upgrade to V4.1.1; switch to `BrokerError` pattern. |
| Hitting transient 5xx / 429 frequently | Upgrade to V4.1.1; enable built-in retry. |
| Maintaining your own retry / backoff logic | Upgrade to V4.1.1; consider removing your logic in favor of built-in. |
| Mission-critical, cannot risk any SDK change | Stay on V4.1.0; V4.1.1 server-side is forward-compatible. |

---

## Reference

- [SDK-REFERENCE.md](SDK-REFERENCE.md) — complete API reference (V4.1.1)
- [RELEASE-NOTES-v4.1.1.md](../RELEASE-NOTES-v4.1.1.md) — server-side release notes
- [CHANGELOG.md](../CHANGELOG.md) — V4.1.1 server-side + SDK entry
- [AWAITING-USER.md V13](../AWAITING-USER.md) — 24 PR + merge order

---

**Document version**: 2026-09-06 (V4.1.1 release prep)
**Applies to**: broker V4.1.0 SDK users upgrading to V4.1.1
