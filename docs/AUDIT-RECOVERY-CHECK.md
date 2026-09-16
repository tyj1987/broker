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
This new command is not wired into production systemd units or release approval.
Independent checkpoint provenance, cloud retention, key administration and a
real disaster-recovery exercise remain separate acceptance evidence.
