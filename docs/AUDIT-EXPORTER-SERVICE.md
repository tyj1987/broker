# Isolated audit exporter service

The Linux `secret-broker-audit-exporter` entrypoint is a native supervisor in
`core/cmd/audit-exporter`. It replaces the direct Node script at the release
binary path without changing the existing exporter/signature/store algorithms.
It does not provision a signer, obtain provider credentials or approve releases.

## One verified publication per iteration

The supervisor requires the dedicated non-root exporter UID/GID and exactly
the signer/store supplementary groups. Its own executable must be under a
root-owned SHA-named release. Each iteration checks protected ancestors of the
native binary, pinned Node binary and same-release service script before
launching a child. Node receives only PATH/LANG, no inherited NODE_OPTIONS,
proxy, credential or shell configuration; it runs with jitless, native addons
disabled and prototype mutation blocked. Systemd remains restricted to AF_UNIX,
private networking, no capabilities and no writable executable memory.

The child loads the fixed protected `/etc/secret-broker/audit/exporter.json`
using the existing strict parser. Each invocation takes one bounded local
chain snapshot, invokes the existing exporter runtime, then performs a separate
read-only store-head query. Only an exact match with the already signature-
verified envelope can produce `anchor_verified`. A publish receipt alone,
unavailable read-back, changed head, revoked key, failure or cancellation cannot
produce readiness. No second signing/publication is used as a confirmation.
An uncertain result fails the iteration; later restarts still use the existing
idempotent chain/sequence protocol, not an exactly-once network guarantee.

Snapshot limits match the recovery reader: 4,096 directory entries, 512 files,
8 MiB per file, 64 MiB total, 256 KiB per record and 100,000 events. Concurrent
changes while taking the snapshot fail closed. A live append after the snapshot
belongs to a later iteration; the frozen snapshot defines this iteration's
anchor. Operators must size/rotate audit data accordingly; these checks are
not an atomic filesystem snapshot or production capacity evidence.

The configured deadline bounds asynchronous work and rejects a late result;
the native parent also kills a child after 65 seconds. Child output is capped
at 1,024 bytes and must be a canonical record with exactly status, positive
sequence and interval_ms. Raw errors, events, hashes and identifiers are not
forwarded. The first fully checked record permits READY; subsequent successful
records permit WATCHDOG. The original configured 60-second to one-hour interval
is retained. `WatchdogSec=3700s` exceeds the maximum interval plus the hard child
deadline; the watchdog is a supervisor liveness bound, not a new freshness SLA.
Startup is limited to 75 seconds, failures are restart-bounded, and control-group
shutdown cleans up descendants. Configuration is reread every iteration.

## Release and verification

`package-audit-exporter.js` produces `exporter-runtime`, a closed set of exporter,
local-socket client and chain-verification code plus the locked YAML parser.
Package validation compares both the manifest and actual files with the source
closure. The installer verifies the package before activation, and grants only
the exporter identity read/execute ACLs. It does not grant that identity access
to the Broker application or the recovery runtime. The native command is built
into the multi-service release, never copied into the Node production container.
Existing deployment branch, approval and LIVE preflight gates remain unchanged.

`test-audit-exporter-service.js` uses temporary audit files and real synthetic
P-256 signatures to check publication/read-back, exact retries, next-sequence
publication, aborts, hanging dependencies, protected packaging and safe output.
Native tests cover strict identity/path/report checks, real child processes,
output bounds, deadlines, and Unix notification datagrams.

The additional candidate CI job runs `audit-process-integration.py` **only on a
pristine disposable GitHub-hosted Linux runner**. It refuses existing Broker
paths/accounts/units. It starts the exact exporter/recovery systemd units,
uses real UIDs/ACLs/native MainPIDs and fixed Unix sockets, and checks the live
kernel privilege/network restrictions. The signing/store services are explicitly
synthetic fixtures, with in-memory state and a fixture-created checkpoint; their
success is not KMS, immutable storage, independently sourced checkpoint, real
retention-lock or disaster-recovery evidence. The script must never be used to
install or test a production host. Its cleanup touches only the pristine paths,
units and accounts created by that isolated run. It does not invoke the
production deployment helper or claim to test production rollback.

The final system still requires independent KMS/CAS and provider identities,
locked external stores, independent recovery authority, final-head review and
LIVE production acceptance before deployment can be approved.
