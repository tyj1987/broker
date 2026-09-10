# Audit integrity boundary

Broker seals each new production audit event into a SHA-256 hash chain before
appending it to an `audit-chain-*.jsonl` file. Each event commits to the
previous event hash and to its own canonical, redacted content.

Every event created in an HTTP request automatically carries the validated
request ID. Caller-provided request IDs are accepted only from a bounded safe
character set; ambiguous or header-like values are replaced with a generated
identifier. Automation transitions add actor, identity method, role, tool,
target, environment, risk, policy decision, approval, execution, outcome,
latency and safe error code fields.

Redaction is applied before hashing. It combines known credential-value
patterns with field-name enforcement for authorization, cookies, passwords,
private keys, API/access keys, tokens, credentials, OTP/TOTP material and
recovery codes. Sensitive fields are replaced even when their value does not
look like a known token. Resource identifiers use explicit names such as
`secret_name` so they remain observable without weakening the `secret` rule.

At startup, Broker reads every chained audit file in lexical order, verifies
the complete retained chain, and resumes from the last committed hash. Invalid
JSON, a broken link, or a modified event prevents startup. The in-memory chain
head advances only after the append succeeds.

## Migration boundary

Existing `audit-*.jsonl` files predate the chain and remain readable as legacy
evidence. They are not silently rewritten or included in the new genesis.
The first `audit-chain-*` event is the explicit migration boundary. Operators
must retain a separately signed migration evidence package before production
rollout.

## Verification

Run the repository audit-chain regression test:

```bash
node broker-test/test-audit-hash-chain.js
```

The administrative verification endpoint uses the same strict parser and
chain verifier. A successful local verification proves consistency only for
the files that are present; it cannot prove that an attacker did not remove a
valid suffix or the entire chain.

## Open production gate

Local hashing is tamper-evident, not independently non-repudiable. Production
acceptance requires signed chain heads exported to an independently
administered immutable store. Until that anchor and its recovery verification
exist, residual risk RR-012 remains open.
