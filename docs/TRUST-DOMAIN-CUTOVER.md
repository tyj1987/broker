# Production trust-domain cutover

DQ-009 replaces the production certificate trust domain that must be treated
as compromised. Preparation is allowed; accepting a replacement identity is
not. No command in this document authorizes a production change.

The complete cutover plan is operational evidence and must remain outside the
repository. It contains certificate fingerprints and management-path evidence,
but never a CA private key, client private key, recovery code, credential or
decrypted configuration. Validate the plan through
`broker/lib/trust-domain-cutover.js` before requesting approval.

## Required plan

The validator requires all of the following:

- a 15-to-180-minute UTC maintenance window and a production change ID;
- different SHA-256 fingerprints for the legacy and replacement CAs;
- an explicitly selected offline CA or cloud HSM authority;
- at least two verified management paths of different kinds;
- a dedicated nginx workload certificate whose fingerprint exactly matches
  the trusted-proxy binding;
- every replacement client certificate, its owner and completed enrollment;
- an exact candidate Git SHA and encrypted production-configuration digest;
- a rehearsed rollback point before the first replacement identity is
  accepted, with restoration of the legacy trust domain forbidden afterward;
- pre-cutover snapshot, SSH host identity, staged proxy binding, rollback
  rehearsal and secret-free audit evidence;
- a separate change authorization reference.

Unknown fields fail validation. This prevents private-key material or ad hoc
instructions from being smuggled into the plan. The rendered report contains
the maintenance window, exact release SHA, impact, client and management-path
counts, rollback boundary, readiness result and missing control names. It does
not print fingerprints or evidence references.

## Preparation phases

1. Generate the replacement CA through the selected offline/HSM ceremony.
   Record only its public certificate and fingerprint in the online evidence
   package. The signing key cannot be exported to the Broker host.
2. Verify the production SSH host identity through an independent channel and
   prove a second management path. Take metadata-only configuration, release
   and certificate inventories plus the approved encrypted snapshot.
3. Issue a new Broker server identity, a separate nginx upstream workload
   identity and at least two operator client identities. Deliver client
   private keys directly to their owners; the server never stores them.
4. Stage the replacement domain on an isolated loopback listener or staging
   host. Verify full server chains, trusted-proxy binding, direct-backend
   denial, old/unknown identity denial, revocation, a read-only typed operation
   and secret-free logs.
5. Rehearse release/config rollback before any replacement identity is
   accepted by the public endpoint. Retain elapsed time and pass/fail-only
   output in the external evidence package.
6. Populate the authorization as `pending`, evaluate readiness and send the
   rendered report to the user. The report must state the maintenance window,
   impact and rollback point. Do not continue until the user approves that
   exact report and the authorization reference is updated out of band.

## Cutover boundary

Before the first replacement identity is accepted, the operator may abort and
restore the previous release/configuration to preserve availability. After a
replacement identity has been accepted, restoring the legacy trust domain is
forbidden. A software rollback after that point must keep the replacement CA,
new server identity, new nginx workload identity and legacy-identity denylist.

Within the approved window, switch the public listener atomically, verify a
replacement client, revoke and reject all legacy clients, verify the nginx
workload mapping, execute one read-only typed operation and confirm the audit
event contains no credential material. Any failure after the irreversible
boundary enters incident recovery in the replacement trust domain; it does not
re-enable the legacy CA.

## Acceptance evidence

DQ-009 closes only when retained evidence proves the exact release and config
digest, independently verified host identity, replacement CA and proxy
fingerprints, client ownership, old-identity rejection, typed read-only
operation, secret-free audit output and timed rollback rehearsal. A green unit
test or source-only plan is preparation evidence, not a production cutover.
