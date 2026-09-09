# Automation tasks

The `/api/v2/tasks` API is the orchestration boundary for Codex, CI and other
agents. A caller names a registered tool and supplies schema-checked parameters;
it cannot supply a URL, authentication header, credential, command or adapter
implementation.

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
tombstone, idempotency and rate-limit state from an authenticated encrypted
state file. Task creation is returned only after a `created` checkpoint;
cancellation is returned only after a `cancelled` checkpoint. Execution is
checkpointed before the adapter side effect and again after its terminal
transition. If a creation or cancellation checkpoint fails, the corresponding
task, idempotency binding and approval mutation are rolled back before an API
success can be returned.

A restored `EXECUTING` task remains indeterminate and cannot be retried because
the upstream side effect may already have occurred. The current file-backed
store has no external monotonic generation anchor, distributed lock or
transactional audit outbox. Production scheduling and horizontal scaling
therefore remain blocked by DQ-001 and DQ-002; this implementation is approved
only for fail-closed recovery in one Broker process.
