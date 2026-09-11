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

The SSH proxy keeps the private key and a separately verified `known_hosts`
file on the broker's tmpfs (0600) for the duration of the command, then removes
both immediately. AI receives only stdout/stderr/exit code.

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

`target` must match `user@host[:port]` with strict regex and must exactly match
the `host`, `port`, and `username` stored in the selected `ssh_connection`.
One credential therefore cannot be redirected to an arbitrary host. Rejected:
- shell metacharacters: `; & | \` $ ' " \`
- ports outside 1-65535
- invalid hostnames

### Host identity validation

Each `ssh_connection` must contain a complete OpenSSH `known_hosts` entry that
was verified through an independent trusted channel. The broker writes it to a
private temporary file and invokes SSH with `StrictHostKeyChecking=yes`.
Missing, malformed, changed, or mismatched host keys fail closed. The broker
never uses `accept-new`, `StrictHostKeyChecking=no`, or an empty known-hosts
database.

### Passphrase-protected keys (v4.1.9+)

If `ssh_connection.passphrase` is set, the broker invokes
`ssh-keygen -p -f <key> -P "<passphrase>" -N ""` **inside the same tmpfs**
right after writing the encrypted private key. The decrypted key still lives
only in the 0600 tmpfs and is removed together with the encrypted file when
the connection closes.

Properties:
- Passphrase is delivered to `ssh-keygen` as argv (`-P`), not via env or stdin.
  No shell interpolation, no prompt capture.
- The decrypted key never persists outside the broker process; the broker
  does not cache the passphrase, and the decrypted key is overwritten in
  place by `ssh-keygen -p` itself (the original encrypted file is replaced).
- Passphrase is **never** written to audit, log, error messages, or return
  values. The `ssh-keygen` failure message is truncated and contains no
  passphrase content (ssh-keygen itself never echoes it back).
- Passphrase is capped at 1 KB; longer values are rejected before any spawn.
- Wrong passphrase is reported as a generic decrypt failure; the broker
  cleans up the tmpfs immediately and does not retry.

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
3. writeFileSync('known_hosts', verifiedKey)  # 0600
4. spawn('ssh', ['-i', 'id_key', ...])        # strict host-key checking
5. wait for command to finish
6. rm -rf('/tmp/broker-ssh-XXXXXX')          # finally block
```

If broker process crashes, tmpfs is wiped on next boot (or by cron).

## Secret type

Use the `ssh_connection` type with fields:
- `private_key` (required) — PEM-encoded RSA/ECDSA/Ed25519 key
- `host`, `port`, `username` (required connection target)
- `known_hosts` (required, independently verified OpenSSH host-key entry)
- `passphrase` (optional, used by ssh-keygen decrypt)

Example `secrets/secrets-detail.json` entry:
```json
{
  "name": "ssh.bastion",
  "type": "ssh_connection",
  "fields": {
    "host": "10.0.1.5",
    "port": 22,
    "username": "app",
    "known_hosts": "10.0.1.5 ssh-ed25519 AAAA...",
    "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n..."
  }
}
```

## Testing

`broker-test/test-ssh-proxy.js` (77 tests):
- target / command validation
- sshExec happy path with injected executor
- sshExec error paths
- key file lifecycle (mkdtemp / write / chmod / rm)
- strict host-key pinning and secret-bound targets
- tunnel start/stop, in-flight cleanup
- zero credential leakage (return values never include private_key)
- passphrase decryption via injected ssh-keygen; failure cleanup

## Comparison to alternatives

| Approach | Private key lifetime | AI exposure | Risk |
|----------|---------------------|-------------|------|
| `env var` (legacy) | entire subprocess | yes | high (history, logs) |
| `ssh-agent` (legacy) | agent lifetime | yes (when `SSH_AUTH_SOCK` env leaked) | medium |
| `sshpass` (legacy) | entire command | yes | high |
| **broker sshExec** | 100ms around command | **no** | low |
