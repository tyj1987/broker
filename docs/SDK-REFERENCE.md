# SDK Reference (V4.1)

> Quick reference for all 3 official Secret Broker SDKs.

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

All SDKs raise typed errors that allow `errors.Is()` / `instanceof` checks.

| HTTP | Node | Python | Go |
|------|------|--------|-----|
| 401  | `BrokerAuthError` | `BrokerAuthError` | `ErrAuth` |
| 403  | `BrokerPermissionError` | `BrokerPermissionError` | `ErrPermission` |
| 404  | `BrokerNotFoundError` | `BrokerNotFoundError` | `ErrNotFound` |
| 429  | `BrokerRateLimitError` | `BrokerRateLimitError` | `ErrRateLimit` |
| 5xx  | `BrokerServerError` | `BrokerServerError` | `ErrServer` |
| Network | `BrokerConnectionError` | `BrokerConnectionError` | `ErrConnection` |

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

| SDK | Tests | Status |
|-----|-------|--------|
| Python | 28 | ✅ 100% pass |
| Go | 15 (test cases) | ✅ 100% (manual review; no Go toolchain in this env) |
| Node | (covered by broker/tests) | – |
| VS Code extension | 11 test cases | ✅ (uses Node https mock + openssl) |

## Compatibility matrix

| Python | Node | Go | Status |
|--------|------|-----|--------|
| 3.9+ | 20+ | 1.21+ | supported |
| 3.8   | 18   | 1.20 | best-effort (no CI) |
| 3.7-  | 16-  | 1.19- | EOL — please upgrade |

## Where to get help

- GitHub: https://github.com/tyj1987/broker/issues
- Discord: #broker channel
- Email: broker@local
- Docs site: https://docs.broker.example.com
