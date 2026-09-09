# Audit integrity boundary

Broker seals each new production audit event into a SHA-256 hash chain before
appending it to an `audit-chain-*.jsonl` file. Each event commits to the
previous event hash and to its own canonical, redacted content.

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
