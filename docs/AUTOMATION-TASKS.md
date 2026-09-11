# Automation tasks

The `/api/v2/tasks` API is the orchestration boundary for Codex, CI and other
agents. A caller names a registered tool and supplies schema-checked parameters;
it cannot supply a URL, authentication header, credential, command or adapter
implementation.

## Implementation and rollout status

The task model, lifecycle, typed MCP bridge, risk routing, approval binding,
single-use execution capability, durable single-node checkpoint and structured
transition audit are implemented, regression-tested and deployed in
`master@fdf0ada1976c5762f7373725f3b0502c76ecdf2b`. The deployed executable
catalog is intentionally smaller than the source registry: a registered
manifest is not visible until a runtime executor and reviewed policy are both
available.

The current safe acceptance operation is
`broker.tools.inspect@1.0.0`. The next rollout checkpoint is a seven-day,
file-delivered MCP key constrained to that one operation, the `control-plane`
account, the `tool-registry` resource and the production environment, followed
by live `initialize`, `tools/list`, allowed execution and wrong
account/resource/environment denial tests. Provider operations remain disabled
until their isolated account binding and real contract evidence are available.

The development branch also contains a Go implementation of the local
short-lived credential protocol used by the Cloudflare, Docker and DeepSeek
runtimes. It validates the Linux peer and the complete requested binding before
calling an injected lease issuer, then constrains the returned capability to a
five-minute maximum lifetime. It has no production credential backend and does
not change the deployed executable catalog.

Protocol version 2 also binds each lease exchange to the consumed task
`execution_id` and canonical `request_binding`. The adapter, local client and Go
service independently validate these values, and the service echoes them in its
response so the client rejects a swapped lease. A production credential
authority must additionally validate the execution against durable control-plane
state before issuing a capability.

The GitHub signer protocol now applies the same execution binding before the
non-exportable backend signs a GitHub App JWT. Its version 2 response echoes the
binding, and the local client rejects substitution before the installation-token
request can run.

The source branch also registers `github.pull-request.create@1.0.0` as a HIGH
risk, draft-by-default operation. Its deterministic end-to-end test proves that
the requester cannot execute before a separate WebAuthn-stepped-up human
approval, and that a completed task cannot replay the upstream call. The
operation is not production-enabled while DQ-004 and the isolated GitHub App
contract test remain open.

The source branch now also registers
`cloudflare.dns.records.list@1.0.0` as a bounded read-only inventory operation.
It requires the same exact 32-character zone identifier in the task resource
and typed parameters, enforces an account allowlist before acquiring an
execution-bound credential lease, and fixes the outbound request to Cloudflare's
HTTPS DNS-records endpoint. Only record identifiers, type, name, TTL, proxied
state and bounded pagination metadata may leave the adapter; record content,
comments, tags and settings are deliberately excluded. It remains source-only
and `contract_required` until the isolated Cloudflare account test and
production credential authority are accepted.

The source branch also wires `openai.models.list@1.0.0` through an isolated
credential lease and a project-bound runtime. The fixed `GET /v1/models`
request accepts no free URL or headers and releases model identifiers only.
The preferred authority is OpenAI workload identity federation mapped to a
dedicated project service account; a bounded project service-account token is
the fallback. The operation remains source-only and `contract_required` until
the identity exchange and isolated project contract are verified.

This changes the active implementation plan from building another task model
to validating the deployed orchestration boundary, then enabling providers one
bounded read-only operation at a time. It does not authorize a second task API,
an arbitrary proxy compatibility route, a remote MCP listener, or bulk provider
activation.

This typed boundary supersedes the early `/api/v1/tools/:name/invoke`
placeholder in the P0 tracking issue. The unrestricted compatibility route is
intentionally not implemented.

Registry schemas use an explicitly validated JSON Schema subset. Unsupported
keywords are rejected at startup instead of being silently ignored. Object
closure, primitive constants and enums, string lengths, array item/count bounds
and numeric ranges are enforced again on task input and adapter output.

## Lifecycle

```text
REQUESTED -> READY -> EXECUTING -> SUCCEEDED
          |                    `-> FAILED
          `-> PENDING_APPROVAL -> READY

REQUESTED, PENDING_APPROVAL or READY -> CANCELLED
Any non-terminal task past its absolute deadline -> EXPIRED
```

`HIGH` and `CRITICAL` tools enter `PENDING_APPROVAL`. The existing approval
broker binds approvals to the provider, operation, account, environment and
parameter hash. `CRITICAL` execution requires two distinct WebAuthn-stepped-up
approvers and cannot be initiated by an agent identity. Authorization is
evaluated again immediately before an executor starts, so revocation and policy
changes take effect on queued tasks.

Approval discovery is requester-bound. Only an administrator using a current
WebAuthn browser session can review another requester's queue; an administrator
API key or unstepped-up session cannot enumerate it. Approval expiry prevents a
new execution claim. Once a claim has atomically entered `EXECUTING`, concurrent
replay or expiry checks cannot rewrite it; the bound task deadline owns the
terminal success, failure or expiry transition.

An unused task approval is cancelled when task creation rolls back, the caller
cancels the task or its absolute deadline expires. A mandatory audit outage
before adapter invocation releases the approval claim and any reserved execution
rate slot, so the same task can be retried after recovery without bypassing the
registered limit. No reservation is released after adapter invocation.

A requester API key must also retain the exact operation scope and provider,
operation, account, environment and resource grants to list, cancel or claim an
approval. A narrowed or revoked key is rejected before the approval state can
change, so it cannot recover old metadata or poison an approved request.

Every creation requires a caller-selected idempotency key. Reusing the key with
the same request returns the original task; reusing it with different parameters
is rejected. Execution and failure are terminal. The broker does not retry an
operation whose result is uncertain.

If the mandatory terminal audit cannot be committed after an adapter has been
invoked, the task and its approval remain `EXECUTING`. The result is not
released and another run is rejected, because the upstream side effect may
already have occurred. An operator must reconcile the execution against the
provider and audit store. Automating that recovery depends on the delivery and
idempotency decision in DQ-002.

Execution is bounded by the smaller of the registered tool timeout and the
task's absolute remaining lifetime. At the deadline the task becomes
`FAILED/executor_timeout` or `EXPIRED`, the adapter receives an aborted
`AbortSignal`, and late output cannot commit. In-process cancellation is
cooperative; production adapters still require an isolated worker that can be
terminated at the process boundary.

After the final authorization check, the Broker issues and immediately consumes
a short-lived capability bound to the actor, exact tool version, target,
environment and request fingerprint. The adapter receives verified claims but
never the bearer token or nonce. See [Single-use execution tokens](EXECUTION-TOKENS.md).

## API

- `POST /api/v2/tasks` creates a task and returns `READY` or
  `PENDING_APPROVAL`.
- `POST /api/v2/tasks/{id}/run` performs the fresh policy check and runs the
  registered adapter once.
- `GET /api/v2/tasks/{id}` returns redacted state and, only after success, the
  schema-validated business result.
- `GET /api/v2/tasks/{id}/events` returns a bounded, ordered transition stream.
- `POST /api/v2/tasks/{id}/cancel` terminally cancels a task before execution.

## Emergency stop

`GET /api/v2/emergency-stop` and `POST /api/v2/emergency-stop` expose the
global automation kill switch. Both require an interactive strict-admin session
with a current WebAuthn factor. A state change additionally requires two
independent approvals bound to `broker:emergency.stop`, the requested state and
the reason code. The mutation also passes the trusted same-origin check.

The switch is included in the encrypted control-plane checkpoint. While it is
engaged, task and typed-operation creation, extension OTP consumption, and
isolated-browser lease claim, OTP consumption, and completion all fail closed.
If activation occurs while a task adapter is running, its eventual upstream
result is discarded and the task fails with `emergency_stop`. A normal
checkpoint failure rolls the change back; an indeterminate durable write
retains the in-memory stop until operator reconciliation. Clearing the switch
requires the same WebAuthn and dual-control ceremony and increments its
persisted generation.

Mutation intent events are durably written before the broker is called and use
`status=attempt`. They are availability and trace evidence, not an authorization
decision. The task broker's policy result and bounded state-transition events
remain the authoritative decision trail.

Task status, events, execution and cancellation are owner-bound. Cross-owner
administration requires an authenticated browser session for an administrator
with a current WebAuthn factor; an API key, workload identity or unstepped-up
session cannot acquire this authority merely by inheriting the `admin` role.

Each transition emits credential-free audit metadata containing the actor,
identity method, role, exact tool and target, environment, risk, policy
decision, approval and execution identifiers, terminal outcome, latency and a
safe error code. The production audit envelope adds the current validated
request ID and seals the redacted event into the hash chain.

The registered Tool rate limit is enforced again at execution time using an
in-process fixed window keyed by actor, exact tool version and environment.
Changing task IDs, idempotency keys, accounts or targets cannot create a fresh
execution bucket. Rate-limited tasks fail terminally before an execution token
is issued or an adapter is invoked. Durable, distributed rate limiting remains
part of DQ-001 and is required before multi-node production scheduling.

The Go, Python and TypeScript SDKs expose the same five operations. The initial
runnable adapter, `broker.tools.inspect@1.0.0`, returns only public tool-registry
metadata and provides a credential-free end-to-end acceptance path.

Tool discovery returns only adapters that have an executor registered in the
running Broker process. Task creation also rejects an unavailable executor
before allocating state or reserving an idempotency key. The execution path
checks again immediately before use, so an executor removed after task creation
fails terminally without issuing an upstream request. A catalog or provider
manifest therefore cannot be mistaken for a runnable capability.

The strict `ssh.host.inspect@1.0.0` test path also crosses this full lifecycle:
policy authorization, schema validation, a target-bound single-use execution
grant, the credential-isolated runner, output-schema validation and terminal
audit events. The runner receives no bearer grant, command or credential. This
is deterministic integration evidence only; it does not replace the isolated
production-target contract required by the SSH provider manifest.

## Current production boundary

The current single-process Broker restores task, approval, execution-token
tombstone, idempotency, rate-limit, typed operation, OTP replay, browser claim
and browser lease state from an authenticated encrypted state file. Raw browser
receipts are not persisted; only their SHA-256 bindings are stored. Legacy v1
snapshots load with an empty operation component and are upgraded to the v2
root schema at the next checkpoint. An unleased operation that was consuming
an OTP when the process stopped is restored as `execution_state_indeterminate`
and is never retried automatically. Task creation is returned only after a `created` checkpoint;
cancellation is returned only after a `cancelled` checkpoint. Execution is
checkpointed before the adapter side effect and again after its terminal
transition. If a creation or cancellation checkpoint fails before file
replacement, the corresponding task, idempotency binding and approval mutation
are rolled back before an API success can be returned. A failure after atomic
replacement is reported as `state_commit_indeterminate`; the matching in-memory
mutation is retained for reconciliation, and an idempotent creation retry
returns the original task instead of duplicating it.

Expiry discovered by a task or event read is also committed synchronously before
the response is returned. A pre-replacement checkpoint failure restores both the
task and its approval state; an indeterminate replacement keeps the expired
state so a restart cannot reopen an execution window.

Approval expiry discovered while an approver decides or an executor claims a
grant follows the same rule. The Broker writes a mandatory `v2_approval_expired`
event and a synchronous control-plane checkpoint before returning
`approval_expired`. A definite audit or checkpoint failure restores the prior
approval state for retry; an indeterminate atomic replacement retains
`EXPIRED` in memory and requires reconciliation. Listing approvals materializes
the same durable terminal state, and cancellation cannot overwrite it.

The operation component is included in every global checkpoint and shutdown
checkpoint. Operation creation, device replay-nonce consumption, OTP receipt,
browser-extension claims and completions, and isolated-browser lease claims,
OTP release and completion all require a synchronous checkpoint before the API
can report success. A pre-replacement write failure rolls back the affected
operation or approval transition. A post-replacement
`state_commit_indeterminate` result retains the in-memory transition so restart
reconciliation observes the same state instead of reopening a replay window.

A restored `EXECUTING` task remains indeterminate and cannot be retried because
the upstream side effect may already have occurred. The current file-backed
store has no external monotonic generation anchor, distributed lock or
transactional audit outbox. Production scheduling and horizontal scaling
therefore remain blocked by DQ-001 and DQ-002; this implementation is approved
only for fail-closed recovery in one Broker process.
