# secret-broker Go SDK

Official Go client for [Secret Broker V4](https://github.com/tyj1987/broker).
**Zero hard dependencies** — stdlib only (`net/http`, `crypto/tls`, `encoding/json`, `sync`).
Compatible with Go 1.21+.

## 8 calling surfaces

| # | Method | Purpose |
|---|--------|---------|
| 1 | `GetSecret(name)` / `ResolveSecrets(names)` / `ListSecrets()` | Secret resolution |
| 2 | `Proxy(service, method, path, body, query)` | Forward through broker |
| 3 | `Exec(envNames, command)` | Subprocess with secrets in env |
| 4 | `SSHExec(target, command, secretName, timeoutMs)` / `SSHTunnel(target, lp, rh, rp, secretName)` | Broker-mediated SSH |
| 5 | `AssumeWorkloadIdentity(provider, oidcToken, roleArn, audience)` | K8s/ECS/GKE OIDC → STS |
| 6 | `Login(username, password, mfaToken, mfaCode)` | Password + MFA |
| 7 | `Me()` / `Health()` | Self / liveness |
| 8 | `WSConnect(...)` + `Subscribe` / `Unsubscribe` / `Ping` / `Recv` | WebSocket events |

## Install

```bash
go get github.com/tyj1987/broker/sdk/go
```

## Quick start

```go
import "github.com/tyj1987/broker/sdk/go/broker"

c, _ := broker.NewClient(broker.Config{
    Endpoint:   "https://broker.example.com:8443",
    ClientCert: "client.crt",
    ClientKey:  "client.key",
    CACert:     "ca.crt",
})

// 1. Single secret
tok, _ := c.GetSecret(ctx, "github.pat")

// 2. Bulk + env binding
vals, _ := c.ResolveSecrets(ctx, []string{"github.pat", "openai.key"})

// 3. Proxy
status, body, _ := c.Proxy(ctx, "github", "GET", "/repos/owner/repo", nil, nil)

// 4. Exec
rc, _ := c.Exec(ctx, []string{"github.pat"}, []string{"git", "push", "origin", "main"})

// 5. SSH via broker
ssh, _ := c.SSHExec(ctx, "app@10.0.1.5", "systemctl status nginx", "ssh.connection", 0)
fmt.Println(ssh.Stdout)

// 6. Workload identity
wi := broker.NewWorkloadIdentity(broker.ProviderK8S, "acs:ram::1:role/app").
    WithAudience("broker.example.com")
c, _ = broker.NewClient(broker.Config{
    Endpoint: "https://broker.example.com:8443",
    ClientCert: "client.crt", ClientKey: "client.key", CACert: "ca.crt",
    WorkloadIdentity: wi,
})
creds, _ := c.AssumeWorkloadIdentity(ctx, "aliyun", "", "", "")
// creds.AccessKeyID, creds.AccessKeySecret, creds.SecurityToken, creds.Expiration
```

## WebSocket

```go
ws, _ := broker.WSConnect("https://broker.example.com:8443", "/ws", nil)
defer ws.Close()
ws.Subscribe([]string{"alerts", "secret_rotated"}, nil)
for {
    msg, err := ws.Recv()
    if err != nil { break }
    fmt.Printf("[%s] %s\n", msg.EventType, msg.Data)
}
```

## Typed errors

```go
_, err := c.GetSecret(ctx, "missing")
if errors.Is(err, broker.ErrNotFound) { ... }
if errors.Is(err, broker.ErrAuth) { ... }
if errors.Is(err, broker.ErrRateLimit) { ... }

var be *broker.BrokerError
if errors.As(err, &be) {
    fmt.Println(be.Status, be.Op)
}
```

## Zero credential leakage

All error messages, log lines, and response bodies are auto-redacted to
prevent accidental credential leakage. Known patterns (GitHub PAT, OpenAI
`sk-`, Anthropic `sk-ant-`, AWS `AKIA`/`ASIA`, JWTs, `Authorization:`,
`X-API-Key:`, `token=`, `password=`) are scrubbed to `[REDACTED_*]`.

## License

MIT
