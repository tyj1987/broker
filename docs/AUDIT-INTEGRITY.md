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

## External anchor protocol core

The source tree includes a provider-neutral signed-head envelope in
`broker/lib/audit-anchor.js`. An anchor payload binds a stream identifier,
strictly increasing sequence, UTC capture time, retained file and event counts,
current chain head, and the previous anchor digest. The signature input uses a
fixed domain separator and also binds the signature algorithm and key
identifier. Only the payload digest and public metadata need to cross the
external signer boundary; no audit content or signing private key is released
to Broker.

The verifier fails closed when the payload is modified, the signer is not in
the explicit trust set, the signer is revoked, the signature is invalid, the
previous anchor or sequence is discontinuous, time or event count moves
backwards, or the restored local chain state differs from the signed head. An
externally retained envelope can therefore detect an exact recovery that is
missing a valid suffix or the complete local chain.

`loadAuditChainProofSync` also resolves the hash and file count at a retained
anchor's historical event count after newer files and events have been
appended. Verification therefore does not require stopping the audit stream at
the anchor boundary. A missing prefix, deleted suffix that crosses the retained
count, or mismatched historical head still fails closed.

Run the protocol and chain tests together:

```bash
npm --prefix broker run test:audit-hash-chain
```

This module is a contract and verifier, not an active exporter. It does not
choose an immutable store, KMS/HSM identity, retention policy, or disaster
recovery authority. Production export remains disabled until DQ-003 is decided
and its storage-outage, retention-lock, signer-rotation and recovery tests pass.

`broker/lib/audit-anchor-exporter.js` adds the provider-neutral publication
coordinator without selecting those controls. It verifies an externally signed
envelope locally before publication, uses the previous anchor digest as the
immutable store compare-and-set condition, and treats a concurrent publication
of the same chain state as an idempotent success. A conflicting chain state,
invalid retained head, signer outage or store outage fails closed. Only signed
chain metadata crosses either boundary; audit event content is never included.

`broker/lib/audit-anchor-recovery.js` verifies recovery against a fixed retained
head. It reads bounded pages only through that sequence and checks every anchor
from sequence one: signature trust and revocation, predecessor continuity, and
the corresponding historical local-chain proof. Missing, duplicated, reordered
or tampered anchors, a changed head, unavailable proof, or configured limit
overflow fails closed. This verifies the portable contract; it is not evidence
that any production immutable store or retention lock has been deployed.

`broker/lib/local-audit-anchor-signer-client.js` defines the corresponding
credential-isolated workload boundary. It accepts only the versioned anchor
request, connects to the fixed
`/run/secret-broker-audit-anchor/signer.sock` path, rejects symbolic links and
unsafe ownership or modes, and requires the response to echo the exact purpose,
algorithm, key identifier and payload digest. The wire request contains only
public anchor metadata and the domain-separated signing input. It never carries
audit events or private-key material. This client is source-only until a
separately managed signer workload is selected and deployed.

## Open production gate

Local hashing is tamper-evident, not independently non-repudiable. Production
acceptance requires signed chain heads exported to an independently
administered immutable store. Until that anchor and its recovery verification
exist, residual risk RR-012 remains open.
