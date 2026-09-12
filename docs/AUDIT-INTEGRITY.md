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
current chain head, and the previous anchor digest. The version 2 signature
input uses a fixed domain separator and also binds the signature algorithm,
key identifier, stream, sequence, previous anchor digest, and payload digest.
Only the payload digest and public metadata need to cross the
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

This module is a contract and verifier, not an active exporter. DQ-003 now
selects a non-exportable Alibaba Cloud KMS signing key, an independently
administered OSS BucketWorm store with 365-day retention, and a typed mirror to
a separate Tencent Cloud COS account with per-object 365-day COMPLIANCE
retention. Production export remains disabled until those independent
workloads and stores exist and their storage-outage, retention-lock,
signer-rotation, cross-cloud lag and recovery tests pass.

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

`core/auditanchor` is the server-side protocol core for that signer workload.
It independently validates the exact purpose, configured algorithm, key,
stream, positive sequence, previous anchor digest, lowercase SHA-256 payload
digest and canonical domain-separated signing input before consulting the
sequence authority or signing backend. Linux peer credentials bind the request
to the configured non-root Broker UID. The KMS adapter receives both the
validated public input and its SHA-256 digest, but no event body or credential.
The included monotonic authorizer requires a linearizable compare-and-swap
store outside the Broker host. It accepts only a contiguous predecessor,
allows an exact retry, and rejects gaps, rewinds, conflicting payloads, corrupt
state and exhausted concurrency retries. The Alibaba KMS adapter maps only the
validated 32-byte digest to `ECDSA_SHA_256` with `MessageType=DIGEST`, requires
the immutable key ID and exact response metadata, validates canonical P-256
DER signature bounds, and hides provider errors behind stable failures. This
is an SDK-independent transport contract, not a deployed KMS integration. The
cloud-backed state store, SDK transport and runnable signer remain production
work; an in-memory or Broker-owned implementation cannot satisfy DQ-003.

Four hardened systemd unit contracts pin mutually distinct signer, exporter,
store and recovery identities. The 22-item production preflight now requires
both the exporter and signer to be active and rejects shared or generic audit
users and groups. The units intentionally cannot start until their reviewed
binaries and provider configuration validators are packaged; their presence
does not constitute live KMS, WORM, mirror or recovery evidence.

`core/auditanchor.ImmutableObjectWriter` now defines the typed dual-cloud
write boundary. It accepts only a structurally valid signed-anchor envelope,
recomputes its payload digest, canonicalizes the JSON, and derives the object
key from the configured prefix, stream, zero-padded sequence and payload
digest. The primary transport exposes only BucketWorm inspection,
create-without-overwrite and read-back. The mirror transport exposes only COS
Object Lock inspection, create with STANDARD storage and per-object
COMPLIANCE retention, read-back and retention read-back. Both copies must
contain the exact canonical bytes; an existing different object is a conflict.
Provider failures are reduced to stable errors and never cross the workload
boundary. This remains a source contract: concrete SDK transports, credentials,
cloud resources and a runnable store service do not yet exist.

The selected primary contract uses Alibaba Cloud KMS `EC_P256` with
`ECDSA_SHA_256` and `MessageType=DIGEST`. The runtime identity is limited to the
exact signing key. The OSS writer can only create objects in the audit prefix;
it cannot delete objects or change WORM policy. BucketWorm must be completed
and read back as `Locked` with a 365-day retention period before the exporter
can become healthy. The Tencent mirror applies COMPLIANCE retention to each
object rather than relying only on a mutable bucket default. The initial mirror
storage class remains STANDARD until a real account proves that direct archive
upload, object lock and the recovery-time target work together.

Official contracts checked on 2026-09-12:

- [Alibaba Cloud KMS Sign](https://www.alibabacloud.com/help/en/kms/key-management-service/developer-reference/sign-1)
- [Alibaba Cloud KMS key specifications](https://www.alibabacloud.com/help/en/kms/key-management-service/user-guide/key-types-and-specifications)
- [Alibaba Cloud OSS retention policies](https://www.alibabacloud.com/help/en/oss/user-guide/oss-retention-policies)
- [Alibaba Cloud OSS PutObject](https://www.alibabacloud.com/help/en/oss/developer-reference/putobject)
- [Tencent Cloud COS Object Lock](https://cloud.tencent.com/document/product/436/55294)
- [Tencent Cloud COS PUT Object Retention](https://cloud.tencent.com/document/product/436/95768)
- [Tencent Cloud Object Lock condition keys](https://cloud.tencent.com/document/product/436/71307)

## Open production gate

Local hashing is tamper-evident, not independently non-repudiable. Production
acceptance requires signed chain heads exported to the selected independently
administered immutable stores. Until the KMS signer, both retention locks,
cross-cloud reconciliation and recovery verification exist as live evidence,
residual risk RR-012 remains open.
