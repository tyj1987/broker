# Single-use execution tokens

Every automation task that passes its final policy check receives a short-lived
opaque execution capability immediately before adapter invocation. The Broker
stores only a SHA-256 digest of the bearer value and consumes it before handing
verified claims to the adapter.

The capability is bound to:

- actor;
- exact `tool@version`;
- target;
- environment;
- canonical request fingerprint;
- a random nonce;
- an execution ID and absolute expiration.

The maximum TTL is 60 seconds and the task path currently requests at most 30
seconds. Consumption changes the record from `ACTIVE` to `CONSUMED`; replay,
expiration, revocation, nonce substitution or any binding change fails closed.
Consumed and revoked records remain as short-lived tombstones so replay cannot
be mistaken for an unknown new capability.

Neither the bearer capability nor its nonce is returned by `/api/v2/tasks`,
placed in task events, sent to the adapter, or written to audit metadata. The
adapter receives only the verified execution ID and public binding claims.

The current implementation is an in-process security boundary for local
adapters. Exporting capabilities to remote workers depends on the durable state
and delivery decisions recorded in the decision queue and is not yet a
production-supported mode.
