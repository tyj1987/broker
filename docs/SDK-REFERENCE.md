# SDK Reference (V4.1.1)

> Quick reference for all 4 official Secret Broker SDKs.
> V4.1.1 added a **unified error contract** across all 4 SDKs (Python, Go, Node CLI, VSCode) — see [V4.1.1 SDK parity](#v411-sdk-parity) below.

## Common API surface

All 3 SDKs implement the same 8 calling surfaces:

| # | Surface | Method (all SDKs) |
|---|---------|-------------------|
| 1 | Single secret | `getSecret(name)` |
| 1 | Bulk secrets | `resolveSecrets(names)` / `resolve_bulk(names)` |
| 1 | List secrets | `listSecrets()` |
| 2 | Proxy | `proxy(service, method, path, body, query)` |
| 3 | Exec | `exec(env_names, command, args)` |
| 4 | SSH exec | `sshExec(target, command, secretName, timeoutMs)` |
| 4 | SSH tunnel | `sshTunnel(target, localPort, remoteHost, remotePort, secretName)` |
| 5 | Workload identity | `assumeWorkloadIdentity(provider, oidcToken, roleArn, audience)` |
| 6 | Login | `login(username, password, mfaToken, mfaCode)` |
| 7 | Self / Health | `me()` / `health()` |
| 8 | WebSocket | subscribe / unsubscribe / recv (async) |

## Authentication

| Mechanism | Config |
|-----------|--------|
| **mTLS client cert** (recommended) | `client_cert` / `client_cert` / `ClientCert` |
| **mTLS client key** | `client_key` / `client_key` / `ClientKey` |
| **CA cert (server verification)** | `ca_cert` / `ca_cert` / `CACert` |
| **Verify TLS** (default true) | `verify_tls` / `verifyTls` / `VerifyTLS` |
| **Password login + session cookie** | `login()` returns `session_token`, SDK auto-uses for subsequent calls |
| **Workload identity** | `workload_identity` constructor arg |

## Common patterns

### Bulk resolve for environment injection

=== "Node"
    ```javascript
    const env = await client.resolveSecrets(['github.pat', 'openai.key']);
    const child = spawn('git', ['push'], { env: { ...process.env, ...env } });
    ```

=== "Python"
    ```python
    env = c.resolve_secrets(['github.pat', 'openai.key'])
    subprocess.run(['git', 'push'], env={**os.environ, **env})
    ```

=== "Go"
    ```go
    env, _ := c.ResolveSecrets(ctx, []string{"github.pat", "openai.key"})
    // Exec appends to os.Environ() automatically
    rc, _ := c.Exec(ctx, []string{"github.pat", "openai.key"}, []string{"git", "push"})
    ```

### Workload identity (K8s Pod)

=== "Node"
    ```javascript
    import { BrokerClient, WorkloadIdentity } from '@tyj1987/broker-sdk';
    const wi = new WorkloadIdentity({
      provider: 'k8s',
      roleArn: process.env.BROKER_ROLE_ARN,
    });
    const client = new BrokerClient({
      endpoint: 'https://broker:8443',
      cert: fs.readFileSync('/var/run/secrets/tls/client.crt'),
      key: fs.readFileSync('/var/run/secrets/tls/client.key'),
      ca: fs.readFileSync('/var/run/secrets/tls/ca.crt'),
      workloadIdentity: wi,
    });
    const creds = await client.assumeWorkloadIdentity('aws');
    ```

=== "Python"
    ```python
    from secret_broker import BrokerClient, WorkloadIdentity
    wi = WorkloadIdentity("k8s", role_arn=os.environ["BROKER_ROLE_ARN"])
    c = BrokerClient(
        endpoint="https://broker:8443",
        client_cert="/var/run/secrets/tls/client.crt",
        client_key="/var/run/secrets/tls/client.key",
        ca_cert="/var/run/secrets/tls/ca.crt",
        workload_identity=wi,
    )
    creds = c.assume_workload_identity("aws")
    ```

=== "Go"
    ```go
    wi := broker.NewWorkloadIdentity(broker.ProviderK8S, os.Getenv("BROKER_ROLE_ARN"))
    c, _ := broker.NewClient(broker.Config{
        Endpoint: "https://broker:8443",
        WorkloadIdentity: wi,
        // ... certs
    })
    creds, _ := c.AssumeWorkloadIdentity(ctx, "aws", "", "", "")
    ```

### WebSocket event subscription

=== "Node"
    ```javascript
    import { BrokerClient } from '@tyj1987/broker-sdk';
    const client = new BrokerClient({ endpoint: 'wss://broker:8443', ... });
    const ws = await client.connectWS('/ws');
    await ws.subscribe(['alerts', 'secret_rotated']);
    for await (const event of ws) {
      console.log(event.event_type, event.data);
    }
    ```

=== "Python"
    ```python
    import asyncio
    from secret_broker import BrokerClient

    async def watch():
        c = BrokerClient(...)
        async with await c.async_client().connect_ws() as ws:
            await ws.subscribe(["alerts", "secret_rotated"])
            async for event in ws:
                print(event)

    asyncio.run(watch())
    ```

=== "Go"
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

## Typed errors

### V4.1.1 SDK parity

**V4.1.1 changed the error model.** All 4 SDKs now expose a **single `BrokerError` class**
with structured fields (instead of 6 different typed subclasses per SDK). This makes
cross-SDK error handling uniform and unlocks common infrastructure (audit log enrichment,
metrics, retry logic).

| Field | Type | Description |
|-------|------|-------------|
| `op` | `string` | Logical operation that failed (e.g. `"get_secret"`, `"login"`) |
| `status` | `int` | HTTP status code (`0` for connection errors) |
| `code` | `string` | Broker-specific error code from response body (e.g. `"auth_failed"`, `"rate_limited"`) |
| `requestId` | `string` | `X-Request-Id` response header (correlate with broker audit logs) |
| `retryAfter` | `int` | `Retry-After` response header in seconds (`0` if absent) |
| `body` | `string` | Redacted response body (never contains secrets) |
| `isRetryable` | `bool` (getter) | `true` for 5xx / 429 / connection errors |
| `toString()` | `string` | `BrokerError: <message> [status=N code=X request_id=Y retry_after=Zs]` |
| `toJSON()` | `object` | Structured representation; `body` is **omitted** (may contain secrets) |

### Per-language error class names

| Language | Class | Module | Auto-redact body on construction? |
|----------|-------|--------|-----------------------------------|
| Python | `BrokerError` | `secret_broker.exceptions` | Yes |
| Go | `BrokerError` (struct) | `broker/errors.go` | Yes (redact before store) |
| Node CLI | `BrokerError` (class) | `cli/secret-broker.js` | Yes |
| VS Code | `BrokerError` (class) | `sdk/vscode/src/client.ts` | Yes |

### Connection errors

Connection-level failures (TLS, ECONNREFUSED, ETIMEDOUT, EAI_AGAIN) are surfaced as
a separate `BrokerConnectionError` class with `isRetryable=true` (always):

| Language | Class | Fields |
|----------|-------|--------|
| Python | `BrokerConnectionError` | `op`, `cause`, `request_id` |
| Go | `BrokerConnectionError` (struct) | `Op`, `Cause`, `RequestID` |
| Node CLI | `BrokerConnectionError` | `op`, `cause`, `requestId` |
| VS Code | `BrokerConnectionError` | `op`, `cause`, `requestId`, `isRetryable` (always `true`) |

### Migration from V4.1.0 (6-class model)

If you were using `BrokerAuthError` / `ErrAuth` etc.:

=== "Python (V4.1.0 → V4.1.1)"
    ```python
    # V4.1.0
    try:
        c.get_secret("github.pat")
    except secret_broker.BrokerAuthError as e:
        ...

    # V4.1.1
    try:
        c.get_secret("github.pat")
    except secret_broker.BrokerError as e:
        if e.status == 401 or e.code == "auth_failed":
            ...  # your auth handling
    ```

=== "Go (V4.1.0 → V4.1.1)"
    ```go
    // V4.1.0
    val, err := c.GetSecret("github.pat")
    if errors.Is(err, broker.ErrAuth) { ... }

    // V4.1.1
    val, err := c.GetSecret("github.pat")
    var berr *broker.BrokerError
    if errors.As(err, &berr) && berr.Status == 401 { ... }
    ```

=== "Node / VSCode (V4.1.0 → V4.1.1)"
    ```javascript
    // V4.1.0
    try { await c.getSecret("github.pat"); }
    catch (e) { if (e instanceof BrokerAuthError) { ... } }

    // V4.1.1
    try { await c.getSecret("github.pat"); }
    catch (e) { if (e instanceof BrokerError && e.status === 401) { ... } }
    ```

## Retry behavior (V4.1.1)

All 4 SDKs automatically retry **retryable errors** (5xx / 429 / connection failures)
with exponential backoff. Honors the broker's `Retry-After` response header when present.

### Defaults

| Setting | Default | Configurable via |
|---------|---------|------------------|
| `maxRetries` | `2` (so up to 3 total attempts) | `Config.max_retries` / `Config.MaxRetries` / `config.maxRetries` |
| `retryBackoffMs` | `500` ms (doubled each retry) | `Config.retry_backoff_ms` / `Config.RetryBackoffMs` / `config.retryBackoffMs` |

### Backoff curve (default settings)

| Attempt | Wait |
|---------|------|
| 1 → 2 | 500 ms |
| 2 → 3 | 1000 ms |
| 3 → 4 | 2000 ms |

If the broker returns `Retry-After: 30`, the SDK waits 30 seconds (overrides exponential backoff).

### What gets retried

| Status | Retry? | Why |
|--------|--------|-----|
| 200-399 | – | (no error) |
| 400 | ❌ no | Client error; retrying won't help |
| 401 | ❌ no | Auth error; needs re-login |
| 403 | ❌ no | Permission error; needs policy change |
| 404 | ❌ no | Resource gone; retrying won't help |
| 429 | ✅ yes | Rate-limited; backoff and try again |
| 5xx | ✅ yes | Server transient; may recover |
| Connection error (TLS, ECONNREFUSED, ETIMEDOUT, EAI_AGAIN) | ✅ yes | Network transient; usually recovers |

### Disable retry

Set `maxRetries=0` to disable automatic retry:

=== "Python"
    ```python
    c = BrokerClient("https://broker:8443", ca_cert="ca.pem", max_retries=0)
    ```

=== "Go"
    ```go
    c := broker.New("https://broker:8443", broker.Config{CACert: "ca.pem", MaxRetries: 0})
    ```

=== "Node CLI"
    ```javascript
    const c = new BrokerClient({ endpoint, caCert, maxRetries: 0 });
    ```

=== "VS Code"
    ```typescript
    const c = new BrokerClient({ endpoint, caCert, maxRetries: 0 });
    ```

## Zero credential leakage

All SDKs run **incoming** error messages through a redaction engine before
returning them. Patterns scrubbed:

- `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` (GitHub PAT)
- `github_pat_` (GitHub Container Registry)
- `sk-` (OpenAI)
- `sk-proj-` (OpenAI project-scoped)
- `sk-ant-` (Anthropic)
- `sk_(live|test)_` (Stripe)
- `AKIA`, `ASIA` (AWS)
- `STS.` (Aliyun STS)
- `xoxb-`, `xoxp-`, `xapp-`, `xoxa-` (Slack)
- `AIza` (Google API key)
- `LTAI` (Aliyun AccessKey)
- `eyJ*.eyJ*.eyJ*` (JWT)
- UUID v4 in header context
- `-----BEGIN .* PRIVATE KEY-----`
- `Authorization: <value>`, `X-API-Key: <value>`, `token=<value>`, `password=<value>` in headers/queries

This is enforced **on every code path**:
- Python: `_redact()` in `secret_broker/client.py`
- Go: `redact()` in `broker/errors.go`
- Node: `redact()` in `sdk/node/src/redact.ts`
- Plus server-side: `broker/lib/redact.js` scrubs **outgoing** audit log + alert payload

## Hard dependencies

| SDK | Runtime deps | Build/dev deps |
|-----|--------------|-----------------|
| Node | `ws` (WebSocket only) | TypeScript |
| Python | **none** (stdlib only: ssl, urllib, asyncio, json) | pytest, cryptography (test only) |
| Go | **none** (stdlib only: net/http, crypto/tls, encoding/json) | – |

## Test counts

| SDK | Tests (V4.1.0) | Tests (V4.1.1) | V4.1.1 delta | Status |
|-----|---------------|---------------|--------------|--------|
| Python | 28 | 54 | +26 (exception parity) | ✅ 100% pass |
| Go | 15 (test cases) | 33 (+1 SKIP) | +18 (error parity) | ✅ 100% pass (Go 1.21+) |
| Node CLI | (covered by broker/tests) | 21 | +21 (BrokerError + parseBrokerError + retry) | ✅ 100% pass |
| VS Code extension | 11 test cases | 48 (+10 pre-existing) | +38 (BrokerError + parseBrokerError + mtlsRequest retry) | ✅ 100% pass |
| **Total** | – | **166** | **+103** | ✅ all green |

V4.1.1 added **103 new tests** covering the unified error contract + retry behavior,
validating that all 4 SDKs are behaviorally consistent.

## Compatibility matrix

| Python | Node (CLI) | Go | VS Code | Status |
|--------|-----------|-----|---------|--------|
| 3.9+ | 20+ | 1.21+ | 1.85+ | supported |
| 3.8 | 18 | 1.20 | 1.80 | best-effort (no CI) |
| 3.7- | 16- | 1.19- | 1.74- | EOL — please upgrade |

CLI tool runs on Node 18+ (no transpilation needed; ESM-only since V4.1.0).
VS Code extension targets `vscode ^1.85.0` (also works in Cursor, Windsurf, VSCodium).

## Summary — V4.1.1 SDK parity

V4.1.1 is the **first release where all 4 SDKs implement the same error contract**.
Before V4.1.1, each SDK had its own 6-class hierarchy (`BrokerAuthError` / `ErrAuth` /
`BrokerPermissionError` / etc.) with subtle behavior differences. After V4.1.1:

1. **Single `BrokerError` class** with structured fields (`status`, `code`, `requestId`,
   `retryAfter`, `body`, `isRetryable`, `toString`, `toJSON`).
2. **Single `BrokerConnectionError` class** for network-level failures (always retryable).
3. **Built-in retry** with `maxRetries` (default 2) + `retryBackoffMs` (default 500ms),
   honoring the broker's `Retry-After` response header.
4. **Auto-redact body on construction** (defense in depth — secrets never leak even if
   caller forgot to redact).
5. **103 new tests** across all 4 SDKs validating behavioral consistency.

This unlocks future work:

- **Cross-SDK audit log enrichment** — same fields, same names, same JSON shape.
- **Cross-SDK metrics** — `broker_error_total{op,code,is_retryable}` from any SDK.
- **Documentation** — one error reference, four language examples (see this file).
- **Future SDKs** (mobile: iOS Swift, Android Kotlin) can adopt the same contract
  verbatim from the V4.2.0 design spec.

### Reference

- Python SDK errors: [`sdk/python/secret_broker/exceptions.py`](https://github.com/tyj1987/broker/blob/main/sdk/python/secret_broker/exceptions.py)
- Go SDK errors: [`sdk/go/broker/errors.go`](https://github.com/tyj1987/broker/blob/main/sdk/go/broker/errors.go)
- Node CLI errors: [`cli/secret-broker.js`](https://github.com/tyj1987/broker/blob/main/cli/secret-broker.js)
- VS Code extension errors: [`sdk/vscode/src/client.ts`](https://github.com/tyj1987/broker/blob/main/sdk/vscode/src/client.ts)

## Where to get help

- GitHub: https://github.com/tyj1987/broker/issues
- Discord: #broker channel
- Email: broker@local
- Docs site: https://docs.broker.example.com
