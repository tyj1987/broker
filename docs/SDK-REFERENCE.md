# SDK reference

The Go, Python, and VS Code clients use the same `/api/v2` typed-operation
contract. An automation supplies an allowlisted operation identifier and typed
parameters; it never supplies an arbitrary URL, authentication header, command,
or long-lived credential.

## Preferred API

| Capability | Python | Go | TypeScript |
|---|---|---|---|
| Create operation | `create_operation(...)` | `CreateOperation(...)` | `createOperation(...)` |
| Read redacted state/result | `get_operation(id)` | `GetOperation(id)` | `getOperation(id)` |
| Create approval request | `create_approval(...)` | `CreateApproval(...)` | `createApproval(...)` |
| List visible approvals | `list_approvals()` | `ListApprovals(...)` | `listApprovals()` |
| Cancel owned approval | `cancel_approval(id)` | `CancelApproval(...)` | `cancelApproval(id)` |
| Create task | `create_task(...)` | `CreateTask(...)` | `createTask(...)` |
| Read task | `get_task(id)` | `GetTask(...)` | `getTask(id)` |
| Run task | `run_task(id)` | `RunTask(...)` | `runTask(id)` |
| Read task events | `task_events(id)` | `TaskEvents(...)` | `taskEvents(id)` |
| Cancel task | `cancel_task(id)` | `CancelTask(...)` | `cancelTask(id)` |
| Health check | `health()` | `Health()` | `health()` |

An operation request contains exactly:

```json
{
  "provider": "github",
  "operation_id": "repo.read",
  "account_ref": "personal",
  "environment": "production",
  "typed_parameters": {
    "resource_ref": "repository-name"
  }
}
```

The Broker evaluates the subject, provider, operation, account, environment,
resource, approval state, rate, time and API-key constraints. Unknown fields
are rejected by the operation schema. A completed response contains only the
business result allowed by that operation; it must not contain injected
credentials, cookies, signing material, internal paths, or browser state.

An accepted operation is not published to the caller until its creation audit
has been durably accepted. If that mandatory audit fails, the unpublished
operation, any waiting OTP task and its serialization lock are rolled back, and
an unused approval claim is released. This rollback applies only before an
executor or isolated browser worker has received the operation.

Approval requests use the same publication boundary. A newly created request is
returned only after its mandatory creation audit is accepted; otherwise the
unpublished request is removed. The rollback is rejected once any approver has
acted on the request.

Approval decisions and cancellations also require a mandatory result audit. The
in-memory transition and its audit commit are synchronous: if the audit commit
fails, the exact prior status and approver set are restored before the caller can
observe success. A durable multi-node implementation remains gated on the state
store transaction decision in DQ-001.

Device enrollment challenges are likewise unpublished until their mandatory
creation audit succeeds. An audit failure deletes the unused challenge and
releases the dual-control approval claim, so a caller cannot receive an
unaudited pairing capability.

Device OTP submission is committed with its mandatory result audit in the same
synchronous transition. If the audit commit fails, the OTP code, task state and
operation state are restored to their pre-submission values; the device must use
a fresh signed request nonce to retry.

An isolated browser lease is not released to a worker until its mandatory claim
audit succeeds. Audit failure deletes the unpublished receipt and lease, then
restores the operation to its prior waiting or OTP-received state.

OTP release to an isolated browser worker follows the same rule. The mandatory
result audit contains only device, lease and status metadata. If it fails, the
code remains server-side, the OTP task returns to `received`, and the lease may
retry with a fresh signed request without an unaudited disclosure.

Browser completion reports are fully validated before their mandatory result
audit is committed. The lease and operation enter a terminal state only after
that audit succeeds. On audit outage, the lease remains active for a bounded,
signed retry; the worker must not repeat the upstream provider action.

The assisted browser-extension OTP claim has the same mandatory intent and
result audit boundary as an isolated worker. If the result audit fails, the
unpublished receipt is removed and the code, task and operation are restored to
the pre-claim state.

The extension completion callback is validated and mandatorily audited before
the receipt is consumed or the OTP operation becomes terminal. During an audit
outage the bounded receipt remains active for a status-only retry; the extension
must not repeat page submission.

A successful WebAuthn assertion does not create a browser session until its
mandatory authentication audit has been accepted. If audit storage is
unavailable, no session record or cookie is created and the client must start a
new WebAuthn ceremony.

Authentication and registration challenges are also unpublished until their
mandatory creation audit succeeds. On audit failure the exact flow, ceremony
type and client binding are checked before the challenge is removed.

A WebAuthn registration result is verified and mandatorily audited before the
credential is added to the client configuration. Audit failure consumes the
one-time ceremony but leaves the credential set unchanged, requiring a new
registration challenge.

Device proof of possession is likewise mandatorily audited before the verified
device is added to the registry. If the audit commit fails, the pairing
challenge remains valid for its original bounded lifetime and no device record
is created.

Device state changes enforce the closed OpenAPI request shape before intent
audit or approval lookup. Only `state` and a UUID `approval_request_id` are
accepted, and `state` is limited to `active`, `suspended`, or `revoked`.

An operation policy may additionally set `source_cidrs`, `not_before`, and
`not_after`. CIDRs support IPv4 and IPv6. Time values use RFC 3339 and the end
is exclusive. Missing source identity, malformed CIDRs, malformed or inverted
time windows, and requests outside the window are denied by both the Node
transition layer and the Go policy service.

For orchestrators, the task API wraps that policy decision in an idempotent
state machine. A task refers to an exact `tool@version` from the registry and
returns only output allowed by that tool's closed schema. High-risk tasks route
through the approval lifecycle, and every run performs a fresh authorization
check. See [Automation tasks](AUTOMATION-TASKS.md).

## Authentication

- Human control-plane access uses mTLS and WebAuthn. Strict profiles require
  two non-synced hardware-bound credentials.
- Browser sessions are delivered only as `Secure`, `HttpOnly`,
  `SameSite=Strict` cookies with a ten-minute absolute lifetime. Login responses
  do not repeat the session token in JSON.
- Workloads use OIDC/SPIFFE-style short-lived identities where available.
- An API key, when a compatibility integration still requires one, must be a
  short-lived child key constrained by service, operation, account,
  environment, resource, secret references, IP and rate. Empty constraint
  lists deny typed operations.
- TLS verification is enabled by default. Disabling it is not a supported
  production configuration.

Approval decisions are intentionally absent from the network-capable SDK
surface. The compatibility methods `decide_approval`, `DecideApproval`, and
`decideApproval` fail locally without sending a request. A human must use the
same-origin `/approvals` browser workbench so the Broker can verify a fresh
WebAuthn factor and the configured HTTPS origin.

Approval lifecycle states are `REQUESTED`, `APPROVED`, `EXECUTING`,
`SUCCEEDED`, `DENIED`, `FAILED`, `EXPIRED`, and `CANCELLED`. Once execution is
claimed, failure is terminal; the approval cannot be returned to an executable
state. The requester may cancel before execution. An administrator cancelling
another request needs a WebAuthn-stepped-up browser session.

## Legacy API surface

The SDKs retain v1 resolve, proxy, exec and SSH methods for isolated migration
environments. Strict profiles deny these routes. New integrations must not use
them, and examples must not export resolved secrets to environment variables or
command arguments.

The compatibility surface will be removed only after downstream users have
migrated to versioned provider operations. Its presence is not evidence that a
provider adapter is production-ready.

## Error and logging rules

SDK errors contain an operation name, HTTP status and stable redacted code.
They never include request authorization, response bodies that may contain a
credential, private key paths, OTP values or session cookies. Client logs must
apply the shared canary-secret tests before release.

## Release verification

Run each SDK's tests from a clean checkout:

```sh
python -m pytest sdk/python/tests -q
go test -race ./...
npm --prefix sdk/vscode ci
npm --prefix sdk/vscode test
```

The Python command assumes the pinned test requirements have been installed;
the Go race test is a Linux CI gate. A package is released only from a signed
release artifact whose commit, SBOM and provenance match the source tree.
