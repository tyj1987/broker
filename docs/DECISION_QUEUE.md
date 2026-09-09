# Decision queue

This queue records consequential choices that should not be guessed during
incremental implementation. Work that does not depend on a queued choice may
continue.

## DQ-001: durable task and approval state

- Status: open
- Needed before: production automation scheduling or more than one Broker node
- Decision: choose the authoritative durable store and transaction boundary for
  task state, approval claims, idempotency records and audit outbox events.
- Required evidence: encrypted backup/restore, failover, concurrent claim,
  revocation race, audit-write failure and disaster-recovery tests.
- Current safe default: bounded in-process storage; no production scheduling.

## DQ-002: worker delivery semantics

- Status: open
- Needed before: remote or horizontally scaled executors
- Decision: select a queue and an at-least-once claim/lease protocol, including
  adapter idempotency requirements and handling of indeterminate upstream
  results. Do not claim exactly-once execution across network boundaries.
- Required evidence: worker crash before/after upstream commit, lease expiry,
  duplicate delivery, cancellation race and replay tests.
- Current safe default: explicit caller-triggered execution in one Broker
  process; terminal failure is never retried automatically.

## DQ-003: independent audit anchor

- Status: open
- Needed before: production acceptance
- Decision: select the independently administered immutable store and KMS or
  HSM identity used to sign retained audit-chain heads. The signing identity
  must not be available to the Broker application process.
- Required evidence: signed-head verification, suffix and full-chain deletion
  detection, signer revocation, clock rollback, storage outage, retention-lock
  enforcement and disaster-recovery tests.
- Current safe default: restart-safe local chain verification; no claim of
  independent non-repudiation.

## DQ-004: provider signing and account-binding authority

- Status: open
- Needed before: any live provider adapter is production-enabled
- Decision: select the independently managed KMS/HSM signing service and the
  authoritative encrypted store for provider account, environment, installation
  and resource bindings. Define workload attestation, key rotation, revocation,
  regional failover and break-glass ownership without exposing signing keys to
  the Broker process.
- Required evidence: signer policy denial, wrong-key and wrong-workload tests,
  rotation overlap, revocation latency, store rollback detection, regional
  outage behavior and isolated-account contract tests.
- Current safe default: dependency-injected signer and account resolver used
  only by deterministic tests; every provider remains `contract_required`.

## DQ-005: SSH target, host-key and certificate authority

- Status: open
- Needed before: any SSH-backed capability is production-enabled
- Decision: select the authoritative target registry, independently verified
  host-key or host-certificate store, short-lived user-certificate signer and
  isolated runner workload. Define principal restrictions, forced commands,
  revocation, regional failover and emergency ownership.
- Required evidence: unknown and changed host-key denial, wrong target and
  principal denial, expired and revoked certificate denial, forced-command and
  forwarding escape attempts, signer outage, runner compromise containment,
  output redaction and isolated-target contract tests.
- Current safe default: a dependency-injected runner used only by deterministic
  tests. No host address, credential, certificate signer or free-form command is
  available through the strict adapter, and the provider remains
  `contract_required`.

## DQ-006: PostgreSQL runner and authorization authority

- Status: open
- Needed before: any PostgreSQL capability is production-enabled
- Decision: select the isolated query-runner workload, authoritative database
  target registry, short-lived login issuer and per-query privilege ownership.
  Define TLS trust, RLS policy ownership, connection pooling, revocation,
  cancellation, audit and regional failover boundaries.
- Required evidence: wrong-target and wrong-database denial, read/write and DDL
  escape attempts, function and foreign-data side effects, RLS bypass,
  privileged-role detection, session revocation, timeout and cancellation,
  pool state reset, output bounds, log redaction and isolated-database contract
  tests.
- Current safe default: a dependency-injected fixed-query runner used only by
  deterministic tests. The strict adapter accepts no SQL or credentials and
  the provider remains `contract_required`.
