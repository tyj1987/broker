# Automation tasks

The `/api/v2/tasks` API is the orchestration boundary for Codex, CI and other
agents. A caller names a registered tool and supplies schema-checked parameters;
it cannot supply a URL, authentication header, credential, command or adapter
implementation.

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

Every creation requires a caller-selected idempotency key. Reusing the key with
the same request returns the original task; reusing it with different parameters
is rejected. Execution and failure are terminal. The broker does not retry an
operation whose result is uncertain.

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

Each transition emits credential-free audit metadata containing the actor,
identity method, role, exact tool and target, environment, risk, policy
decision, approval and execution identifiers, terminal outcome, latency and a
safe error code. The production audit envelope adds the current validated
request ID and seals the redacted event into the hash chain.

The Go, Python and TypeScript SDKs expose the same five operations. The initial
runnable adapter, `broker.tools.inspect@1.0.0`, returns only public tool-registry
metadata and provides a credential-free end-to-end acceptance path.

## Current production boundary

The present task and approval stores are in-process and intentionally bounded.
They provide a tested vertical slice, not durable or multi-node execution.
Production scheduling remains blocked until the persistence and delivery
semantics in the decision queue are resolved and implemented. A process restart
must therefore be treated as cancellation of all in-flight tasks.
