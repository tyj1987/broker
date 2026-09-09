# SSH proxy compatibility interface

## Strict typed capability

`ssh.host.inspect@1.0.0` is the first strict replacement for the compatibility
proxy. Its only caller-controlled field is an opaque registered `resource_ref`.
The adapter does not accept a hostname, port, login name, command, shell input,
private key, certificate or arbitrary environment value.

The Broker passes a bound request to an isolated runner capability containing
only the operation ID, account reference, environment, target reference and
cancellation signal. The runner returns a closed, bounded health record:
hostname, uptime, one-minute load, disk-use percentage and service state. Any
unexpected field, wrong target, malformed value or runner error fails closed;
raw stdout, stderr and credential material are never returned to the caller.

Production remains disabled until an isolated target contract proves all of
the following:

- the target registry resolves the opaque reference to one fixed host, port,
  principal and allowed operation;
- `StrictHostKeyChecking=yes` uses an independently verified host key or host
  certificate authority; first-use acceptance is forbidden;
- a short-lived user certificate or hardware-backed agent is restricted to a
  forced inspection command, with all forwarding disabled;
- the runner is separately isolated, has bounded output and time, redacts its
  logs, and cannot return credential handles or raw process output;
- revocation, wrong target, wrong principal, host-key change, timeout and
  concurrent execution tests pass.

OpenSSH documents that strict host-key checking refuses unknown or changed
keys, `IdentitiesOnly` restricts offered identities, and server-side
`ForceCommand` must be paired with `DisableForwarding` when other channels are
not allowed. The exact production CA, registry and runner ownership is tracked
in the decision queue.

The v1 SSH proxy is a compatibility feature. It accepts a free-form remote
command and therefore is **disabled for strict-profile identities**. It is not
a substitute for `/api/v2` typed operations and must not be exposed to AI in a
strict deployment.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/ssh/exec` | Run one compatibility-mode remote command |
| `POST` | `/api/v1/ssh/tunnel` | Open a compatibility-mode local forward |
| `POST` | `/api/v1/ssh/tunnel/stop` | Stop a forward by opaque ID |
| `GET` | `/api/v1/ssh/tunnels` | List active tunnel metadata |

The implementation validates `user@host[:port]`, bounds command and output
sizes, starts OpenSSH without a local shell, writes temporary key material with
mode `0600`, and removes it in a `finally` path. These controls reduce local
injection and leakage risk, but they do not make an arbitrary remote command
safe: OpenSSH sends the command to the remote login shell, where shell syntax
can be interpreted.

## Deployment requirements

- Bind the compatibility listener separately from the strict API and keep it
  private.
- Permit only named compatibility clients, fixed target hosts, fixed source
  networks and narrowly scoped service records.
- Provision any private key through the server's protected secret deployment
  channel. Do not paste or upload a private key through the dashboard, SDK,
  issue tracker, CI log or chat.
- Prefer a locked server-side key path, SSH certificate, hardware-backed agent,
  or workload identity over a long-lived private-key value.
- Use a forced command and restricted `authorized_keys` options on the target;
  do not grant an unrestricted administrative shell.
- Disable core dumps, place the temporary directory on private memory-backed
  storage, and alert if cleanup fails.

The API response contains exit status and bounded output only; it must never
contain a key, key path, passphrase or secret record. Logs and audit events are
subject to the common redaction rules.

## Strict replacement

A strict SSH-backed action must be registered as a named `/api/v2` operation.
Its server-side adapter fixes the host, port, remote account and command
template, accepts only schema-validated parameters, applies Node and Go policy
decisions, and records mandatory audit intent before execution. No production
operation is enabled until its isolated-target contract test has passed.

## Verification

`broker-test/test-ssh-proxy.js` covers compatibility parsing, executor argument
construction, output handling, temporary-file cleanup, tunnel lifecycle and
credential non-disclosure. Passing those tests validates the compatibility
implementation only; it does not approve the feature for a strict profile or
for production.
