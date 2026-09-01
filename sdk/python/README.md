# secret-broker Python SDK

Official Python client for [Secret Broker V4](https://github.com/tyj1987/broker).
**Zero hard dependencies** — stdlib only (`ssl`, `urllib`, `asyncio`, `json`).
Compatible with Python 3.9 - 3.13.

## 8 calling surfaces

| # | Method | Purpose |
|---|--------|---------|
| 1 | `get_secret(name)` / `resolve_secrets(names)` / `list_secrets()` | Secret resolution (bulk + env-var binding) |
| 2 | `proxy(service, method, path, body?, query?)` | Forward request through broker to upstream |
| 3 | `exec(env_names, command, args)` | Spawn subprocess with secrets in env vars |
| 4 | `ssh_exec(target, command)` / `ssh_tunnel(target, lp, rh, rp)` | Broker-mediated SSH (private key stays in broker) |
| 5 | `assume_workload_identity(provider, ...)` | K8s/ECS/GKE OIDC → STS short-lived creds |
| 6 | `login(user, pass, mfa_token?, mfa_code?)` | Password / MFA authentication |
| 7 | `identity()` / `health()` | Self / liveness |
| 8 | `async_client().subscribe(events)` | WebSocket event stream |

## Install

```bash
pip install secret-broker
```

Or from source:

```bash
git clone https://github.com/tyj1987/broker.git
cd broker/sdk/python
pip install -e .
```

## Quick start

```python
from secret_broker import BrokerClient, WorkloadIdentity

c = BrokerClient(
    endpoint="https://broker.example.com:8443",
    client_cert="client.crt",
    client_key="client.key",
    ca_cert="ca.crt",
)

# 1. Single secret
token = c.get_secret("github.pat")

# 2. Bulk + env binding
env = c.resolve_secrets(["github.pat", "openai.key"])

# 3. Proxy
status, body = c.proxy("github", "GET", "/repos/owner/repo")

# 4. exec (spawn subprocess)
c.exec(["github.pat"], ["git", "push", "origin", "main"])

# 5. SSH via broker (private key never leaves broker)
result = c.ssh_exec("app@10.0.1.5", "systemctl status nginx")
print(result["stdout"])

# 6. Workload identity (K8s)
wi = WorkloadIdentity(provider="k8s", role_arn="acs:ram::123:role/app",
                      audience="broker.example.com")
creds = c.assume_workload_identity("aliyun", audience="broker.example.com")
# creds = { "access_key_id": "STS.xxx", "access_key_secret": "...", "expiration": "..." }
```

## Async (WebSocket subscriptions)

```python
import asyncio
from secret_broker import BrokerClient

async def watch_alerts():
    c = BrokerClient(endpoint="...", client_cert="...", client_key="...", ca_cert="...")
    async with await c.async_client().connect_ws() as ws:
        await ws.subscribe(["alerts", "secret_rotated"])
        async for event in ws:
            print(event)

asyncio.run(watch_alerts())
```

## Zero credential leakage

All error messages, log lines, and audit records are auto-redacted by the SDK
to prevent accidental credential leakage:

```python
try:
    c.get_secret("github.pat")
except Exception as e:
    # e.message is safe to log: "ghp_xxxxxxx" becomes "[REDACTED_GITHUB]"
    logger.error("fetch failed: %s", e)
```

## License

MIT
