# Secret Broker — VS Code / Cursor extension

Official VS Code (and Cursor) extension for [Secret Broker V4](https://github.com/tyj1987/broker).
**Zero npm runtime dependencies** — only TypeScript build tools and the
official `vsce` packager.

## 7 commands

| Command | Title | Purpose |
|---------|-------|---------|
| `secretBroker.health` | Secret Broker: Health Check | Quick broker liveness |
| `secretBroker.list` | Secret Broker: List Secrets | Browse secrets visible to current mTLS client |
| `secretBroker.get` | Secret Broker: Get Secret | Resolve a secret (UI-redacted by default) |
| `secretBroker.resolve` | Secret Broker: Resolve to Env | Bulk resolve → opens `.env` document |
| `secretBroker.proxy` | Secret Broker: Proxy Request | Forward a request to an upstream service |
| `secretBroker.sshExec` | Secret Broker: SSH Exec | Run a command on a remote host (broker holds the key) |
| `secretBroker.login` | Secret Broker: Login | Password + optional MFA login |

Plus: status bar item shows broker health, refreshes every 60s.

## Zero-credential UI

- All secret values are redacted by default. To reveal: type `YES` in the
  confirmation dialog. Auto-cleared from clipboard after 60s.
- All error messages and logs are scrubbed via the `redact()` engine (same
  patterns as Python/Go SDKs).
- Network errors are wrapped in `BrokerConnectionError`; HTTP errors carry
  the original status code for typed handling.

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `secretBroker.endpoint` | `https://127.0.0.1:8443` | Broker URL |
| `secretBroker.clientCert` | (empty) | mTLS client cert (PEM path) |
| `secretBroker.clientKey` | (empty) | mTLS client key (PEM path) |
| `secretBroker.caCert` | (empty) | Broker CA cert (PEM path) |
| `secretBroker.redactInUI` | `true` | Always redact values in UI; require explicit reveal |
| `secretBroker.statusBarEnabled` | `true` | Show broker health in status bar |

## Build & Install

```bash
cd sdk/vscode
npm install
npm run build
npx vsce package    # produces secret-broker-4.2.0.vsix
code --install-extension secret-broker-4.2.0.vsix
```

Or for development:

```bash
npm run watch
# In VS Code: F5 to launch Extension Development Host
```

## Test

```bash
npm run build
node ./out/test/run.js
```

Tests use a built-in mock HTTPS broker (cert generated via `openssl`).

## Architecture

- `src/client.ts` — BrokerClient (Node https + tls, zero npm)
- `src/extension.ts` — VS Code command registrations + status bar
- `src/test/client.test.ts` — unit + integration tests

## License

MIT
