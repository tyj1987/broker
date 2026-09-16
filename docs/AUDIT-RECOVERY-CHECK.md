# Checkpoint-bound audit recovery check

`broker/bin/audit-recovery-check.js` is a one-shot, read-only verification
entrypoint. It reuses the existing fixed audit-store socket and full-chain
verifier; it does not start the planned recovery service or configure providers:

```sh
node broker/bin/audit-recovery-check.js --config-file /absolute/recovery-config.json --checkpoint-file /absolute/independent-checkpoint.json
```

Both input files are read through `readProtectedInputFile`, with owner-only
POSIX permissions, bounded sizes, no symbolic-link following and stable-file
checks. Windows ACL protection remains an operator prerequisite. Configuration
is exact-schema JSON with `version: 1`, purpose
`secret-broker.audit-recovery-check`, `stream_id`, an absolute normalized
`audit_directory`, `trusted_keys`, `revoked_key_ids`, `store_timeout_ms`,
`deadline_ms`, `page_size` and `max_anchors`. Each of one to eight trusted keys
has exactly `key_id`, `public_key_spki_der_base64` and `public_key_sha256`;
only canonical P-256 SPKI public keys with matching SHA-256 pins are accepted.
Unknown fields, duplicate JSON keys, credentials, private keys and provider
endpoints are rejected. Timeouts are 100–60,000 ms, store timeout cannot exceed
the overall deadline, page size is 1–32 and the anchor cap is 1–1,000,000.

The separately supplied checkpoint contains exactly `version: 1`, purpose
`secret-broker.audit-recovery-checkpoint`, `stream_id`, positive `sequence`,
nonzero lowercase `payload_digest`, `issued_at_ms` and `expires_at_ms`.
Issuance and expiry are integer UTC epoch milliseconds; the permitted validity
interval is at most one hour and expiry is exclusive. These timestamps describe
the operator's independently obtained checkpoint, not the age of an audit event.
The stream, sequence, digest, validity and configured cap are checked before any
store read and again before success. Empty stores, replayed prefixes, changed
heads, revoked/invalid signatures, incomplete proofs, clock rollback, expiry,
cancellation and deadline overruns fail closed. Caller cancellation and deadline
are enforced for unsettled asynchronous backends; a monotonic elapsed-time check
also prevents synchronous proof work from producing a late success.

**The checkpoint file is a trust input, not a self-authenticating receipt.**
It must be acquired/authenticated independently of the store and Broker host,
then provisioned under the independently administered recovery identity. A root
file mode, a timestamp or a successful parse does not prove that independence.
Do not produce this file from the store being tested, refresh an expired file's
timestamps automatically, or treat a compromised recovery host as trusted.
This command neither issues checkpoints nor supplies a freshness authority.

Local recovery data is read once as a quiescent, bounded snapshot: at most
4,096 directory entries, 512 matching files, 8 MiB per file, 64 MiB total,
256 KiB per JSONL record and 100,000 events. Only `audit-chain-*.jsonl` files
are considered. Links, non-regular files and metadata changes during the read
are rejected. Hashes and historical file counts, rather than event bodies,
are retained for repeated proofs. These metadata checks are not an atomic
filesystem snapshot; keep the recovery copy quiescent and do not interpret
later changes to that copy as included in the verified snapshot.

Successful output is only `checkpoint_verified`, the verified anchor count,
sequence and a checkpoint-match flag. It contains no audit events, paths,
stream/key identifiers or digests. Failures emit a fixed error code and nonzero
exit status. The existing portable `verifyRecovery()` API is unchanged and
still proves consistency with a supplied store head, not independent freshness.
This one-shot command does not itself start a service or grant release approval.
Independent checkpoint provenance, cloud retention, key administration and a
real disaster-recovery exercise remain separate acceptance evidence.

## Isolated recovery process and release wiring

The native `core/cmd/audit-recovery` command supplies the existing systemd
entrypoint `secret-broker-audit-recovery --config
/etc/secret-broker/audit/recovery.json`. It is a supervisor, not a second
cryptographic implementation: each iteration starts the existing Node verifier
with a fresh config/checkpoint and the fixed store socket. Only the distinct
`broker-audit-recovery` UID/GID with the audit-store supplementary group is
accepted. The native executable must reside in the immutable, SHA-named
release; Node and the verifier entrypoint must be root-owned with protected
ancestors. No command shell, inherited NODE_OPTIONS, cloud credentials, or
caller-selected executable is accepted.

The root-managed config uses the schema above. Its sibling
`/etc/secret-broker/audit/recovery-checkpoint.json` is the independently obtained
checkpoint. Both service input files must be root-owned, single-link, mode
0440 and readable by an explicit recovery group. All configuration directory
ancestors are root-owned and non-writable by group/other. The interactive
`audit-recovery-check.js` owner-only input convention remains unchanged.

The process sends systemd `READY=1` only after the first complete checkpoint
verification. Subsequent successful checks refresh the watchdog; an invalid,
expired, revoked, unavailable or changed checkpoint/head terminates the
process. Each child has a 65-second hard deadline and at most 1,024 stdout
bytes; stderr is never reflected. A 30-second wait separates completed checks.
The systemd unit uses `Type=notify`, `NotifyAccess=main`, a 75-second startup
limit, a 120-second watchdog, bounded restarts, control-group cleanup, and only
AF_UNIX networking. Node runs with `--jitless --disable-proto=throw --no-addons`
so the existing executable-memory restriction is not removed.

`package-audit-recovery.js` creates a closed `recovery-runtime` dependency
set containing only the verifier code and the locked YAML parser. Its manifest
is checked against the actual source closure before release installation;
manifest edits alone cannot authorize extra or modified files. The native
binary and runtime are built into the signed multi-service release, excluded
from the Node production container, and installed with recovery-only read/execute
ACLs without making the Broker application's tree readable by that identity.
The full-CI and production-approval triggers are unchanged.

This wiring does not provision accounts, input files, an independent checkpoint
publisher, KMS/CAS authority, immutable storage or a restored audit copy. It does
not automatically start any production service. The operator must coordinate a
quiescent recovery copy and independently issued checkpoint with the selected
store head. A store advancing beyond that exact checkpoint is a rejection, not
permission to rewrite or automatically advance the checkpoint. Production
readiness still requires current independent recovery evidence and all existing
LIVE checks; a successful unit build is not a recovery drill.
