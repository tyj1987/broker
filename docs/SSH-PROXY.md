# SSH Proxy (V4.1)

> **Goal**: AI agents execute commands on remote hosts via broker. Private
> keys NEVER leave the broker process.

## Why

Traditional `secret-broker exec --env "SSH_KEY" -- ssh ...` would inject the
private key as an env var, where it can be captured by:
- shell history (`/proc/self/environ`)
- core dumps
- audit logs
- accidentally-printed env in error messages

The SSH proxy keeps the private key on the broker's tmpfs (0600) for the
duration of the command, then `rm -rf` immediately. AI receives only
stdout/stderr/exit code.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/ssh/exec` | Run a command on a remote host |
| `POST` | `/api/v1/ssh/tunnel` | Open a local port forward |
| `POST` | `/api/v1/ssh/tunnel/stop` | Close a tunnel by ID |
| `GET`  | `/api/v1/ssh/tunnels` | List active tunnels (admin) |

## sshExec

Request:
```json
{
  "target": "app@10.0.1.5",
  "command": "systemctl status nginx",
  "secret_name": "ssh.connection",  // default
  "timeout_ms": 30000
}
```

Response:
```json
{
  "ok": true,
  "exitCode": 0,
  "stdout": "● nginx.service - The nginx HTTP and reverse proxy server\n   Active: active (running)...",
  "stderr": "",
  "duration_ms": 47,
  "target": "app@10.0.1.5"
}
```

The private key **never appears** in any field of the response.

## sshTunnel

Request:
```json
{
  "target": "app@bastion.example.com",
  "local_port": 5432,
  "remote_host": "db.internal",
  "remote_port": 5432,
  "secret_name": "ssh.bastion"
}
```

Response:
```json
{
  "ok": true,
  "id": "uuid-here",
  "localPort": 5432,
  "remote": "db.internal:5432",
  "target": "app@bastion.example.com",
  "startedAt": "2026-09-01T08:35:00Z"
}
```

The broker runs `ssh -N -L 5432:db.internal:5432 ...`. Connect to
`localhost:5432` and traffic is forwarded over the broker.

## CLI

```bash
# Exec
secret-broker ssh-exec \
  --target app@10.0.1.5 \
  --command "uptime"

# Tunnel (foreground, Ctrl-C to stop)
secret-broker ssh-tunnel \
  --target app@bastion.example.com \
  --local-port 5432 \
  --remote-host db.internal \
  --remote-port 5432
```

## Security

### Target validation

`target` must match `user@host[:port]` with strict regex. Rejected:
- shell metacharacters: `; & | \` $ ' " \`
- ports outside 1-65535
- invalid hostnames

### Command validation

`command` must:
- be a non-empty string
- be ≤ 4096 chars
- contain no newline / NUL

The command is passed to `ssh` as a **single argument** (after `--`), so
shell expansion does not happen on the broker.

### Output limits

stdout and stderr are capped at 10 MB each to prevent memory exhaustion
from runaway commands. Excess is silently dropped.

### Timeout

Default 5 minutes. Configurable per-request via `timeout_ms`.

### Private key lifecycle

```
1. mkdtempSync('/tmp/broker-ssh-XXXXXX')     # 0700
2. writeFileSync('id_key', privateKey)        # 0600
3. spawn('ssh', ['-i', 'id_key', ...])        # broker-controlled
4. wait for command to finish
5. rm -rf('/tmp/broker-ssh-XXXXXX')          # finally block
```

If broker process crashes, tmpfs is wiped on next boot (or by cron).

## Secret type

Use the `ssh_jump_host` type (V4) or store a custom secret with fields:
- `private_key` (required) — PEM-encoded RSA/ECDSA/Ed25519 key
- `username` (optional, derived from target)
- `passphrase` (optional, used by ssh-keygen decrypt)

Example `secrets/secrets-detail.json` entry:
```json
{
  "name": "ssh.bastion",
  "type": "ssh_jump_host",
  "value": {
    "jump_host": "bastion.example.com",
    "jump_user": "bastion",
    "jump_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n..."
  }
}
```

## Testing

`broker-test/test-ssh-proxy.js` (53 tests):
- target / command validation
- sshExec happy path with injected executor
- sshExec error paths
- key file lifecycle (mkdtemp / write / chmod / rm)
- tunnel start/stop, in-flight cleanup
- zero credential leakage (return values never include private_key)

## Comparison to alternatives

| Approach | Private key lifetime | AI exposure | Risk |
|----------|---------------------|-------------|------|
| `env var` (legacy) | entire subprocess | yes | high (history, logs) |
| `ssh-agent` (legacy) | agent lifetime | yes (when `SSH_AUTH_SOCK` env leaked) | medium |
| `sshpass` (legacy) | entire command | yes | high |
| **broker sshExec** | 100ms around command | **no** | low |
