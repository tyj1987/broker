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
