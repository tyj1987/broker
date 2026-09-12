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
users and groups. The store gate requires both an active process and a fresh
typed health response obtained as the fixed recovery UID; only `ready`,
`verified`, `in_sync` and `ok` with an exact bounded response pass. Process
liveness alone cannot claim that WORM or mirror state was checked. The units
intentionally cannot start until their reviewed binaries and provider
configuration validators are packaged; their presence does not constitute live
KMS, WORM, mirror or recovery evidence.

`core/auditanchor.ImmutableObjectWriter` now defines the typed dual-cloud
write boundary. It accepts only a canonicalizable signed-anchor envelope,
recomputes its payload digest, then independently verifies the exact v2
domain-separated ECDSA P-256 signature against a configured stream and a
trusted key sequence epoch before any provider call. Sequence epochs let a
rotated key verify its historical anchors without authorizing new anchors.
Each stream sequence
has one fixed object key; the digest remains inside the signed envelope rather
than the key. This lets OSS create-without-overwrite enforce a real immutable
compare-and-set boundary: two different payloads for the same sequence collide
instead of creating parallel objects. Before sequence N is written, the writer
requires both clouds to contain the same canonical, retained sequence N-1 with
the exact predecessor digest. The primary transport exposes only BucketWorm
inspection, create-without-overwrite and read-back. The mirror transport
exposes only COS Object Lock inspection, create with STANDARD storage and
per-object COMPLIANCE retention, read-back and retention read-back. Both
copies must contain the exact canonical bytes; an existing different object
is a conflict.
Provider failures are reduced to stable errors and never cross the workload
boundary. Concrete transports now pin Alibaba OSS Go SDK v2 `v1.6.0` and
Tencent COS Go SDK v5 `v0.7.75`. They bind every call to one configured bucket.
The OSS public constructor derives the SDK endpoint from an exact region and
rejects custom endpoints, plaintext TLS, redirect, CNAME, proxy and alternate
addressing modes. The COS public constructor requires the exact regional
`https://<bucket>.cos.<region>.myqcloud.com` BucketURL with no userinfo, port,
path, query or fragment. The transports accept no arbitrary headers, expose no
delete or retention-policy mutation, bound read-back data, and stop between
SDK calls when the context is cancelled.
The OSS transport maps only a `409 FileAlreadyExists` response to an
idempotent existing object. The COS transport applies COMPLIANCE mode and the
exact retain-until timestamp in the original PutObject request. These are still
source-only transports: credentials, cloud resources and a runnable store
service do not yet exist.

OSS read-back requests a bounded byte range. A valid range response is `206
Partial Content`, so the transport accepts it only when `Content-Range` proves
that the returned bytes start at zero and comprise the complete object, the
declared length matches, and the total is within the 16 KiB anchor limit. It
also accepts an exact bounded `200` full response with no `Content-Range`.
Partial, oversized, versioned, malformed or unclosed responses fail closed.

`core/auditstore` and
`broker/lib/local-audit-anchor-store-client.js` now define the bounded local
boundary between the exporter or recovery verifier and that future store
workload. The versioned protocol fixes the stream, purpose and request ID;
accepts only `publish`, `read_head`, `read_page` and `health`; limits requests,
responses and recovery pages; and validates every returned envelope again.
Linux peer credentials assign one of two non-root roles: the exporter may
publish but may not enumerate recovery pages, while recovery may read but may
not publish. Provider errors are reduced to stable codes and an unauthorized
peer receives no response. The Node client additionally pins the Unix socket,
requires safe ownership and mode, and exposes exactly the store methods used by
the existing exporter and recovery verifier. The recovery unit has group-level
socket access, but the store still authorizes its exact UID for read-only
operations.

This protocol is hermetic source evidence, not a claim that the cloud store is
deployed or independently recoverable. A strict version-1 service
configuration now binds the stream, prefix, OSS/COS bucket and region,
independent provider profile identifiers, enumeration limits and one or more
non-overlapping P-256 public-key epochs. The exact JSON grammar has no endpoint,
AccessKey, token, credential-file or credential-command field; unknown,
duplicate, null, oversized, symlinked and non-canonical key inputs fail closed.
On Linux, the production loader accepts only the fixed root-managed audit
configuration directory, rejects writable or incorrectly owned path elements,
opens without following links, and verifies that the opened file is the one
that was inspected. The runtime passes only those non-secret bindings to an
injected workload-identity factory. Its checked-in default deliberately returns
`identity_unavailable`, so source presence cannot be mistaken for a configured
cloud identity.

The Linux service creates only the fixed `store.sock` name below a private,
service-owned, non-writable runtime directory. A non-blocking process lock
prevents a second instance from replacing the active path; an existing socket
is reclaimed only when it belongs to the service UID and an active-connection
probe proves it stale. Listener shutdown removes only its own inode. The socket
uses mode `0660`, and exporter/recovery authorization uses the kernel peer UID.
A separate bounded health helper reads the same fixed
non-secret configuration and returns only the typed health object consumed by
the 22-item preflight. Linux socket lifecycle and real request/response behavior
are exercised as an end-to-end test; non-Linux service startup fails closed.
The commands are not yet packaged and no production identity factory is
selected.

The OSS and COS SDK boundaries now
expose one fixed-bucket, fixed-prefix, lexicographically ordered object-key page
with a maximum of 1,000 entries. They reject arbitrary delimiter, endpoint,
header and continuation inputs, malformed ordering, unexpected prefixes,
oversized anchor objects and non-progressing pagination.

`core/auditstore.DualCloudRepository` uses those pages rather than a local head
file or in-memory checkpoint. On every operation it revalidates both retention
contracts and derives the identical contiguous prefix from sequence one. A
single primary-only tail is reported as `repair_required` and can be completed
idempotently; a gap, mirror lead, multi-object lead, key divergence, content
divergence or invalid retention blocks the store. Head and recovery reads
compare both clouds, verify canonical signatures and validate COS COMPLIANCE
retention. Enumeration is bounded to 128 pages by default and 512 pages at the
hard maximum, so exhausting the configured bound fails closed instead of
trusting a partial view. This removes the Broker-host checkpoint as an
authority, but the repository and service remain source-only. At the
maximum 1,000-object page size this admits 128,000 sequences by default and
512,000 at the hard limit. Operators must size the configured bound for the
retention-period publication rate and alert before 80 percent; no automatic
stream rollover or post-retention deletion is implemented. The Go CI gate
measures statement coverage with `go tool cover`; the separate release
requirement for 85 percent branch coverage remains pending dedicated evidence.

Recovery through the store socket is useful for contract tests but cannot by
itself prove freshness against a compromised store process. The independent
recovery authority must read both clouds directly or verify an independently
held freshness checkpoint.

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
