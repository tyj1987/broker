# Secret Broker operations runbook

This runbook covers the supported Node transition service plus the Go policy
core. It never replaces a maintenance approval, recovery exercise, or release
record. Do not paste credentials, OTPs, private keys, decrypted configuration,
or recovery codes into tickets, terminals with recording enabled, or chat.

## Operating invariants

- Public traffic terminates at nginx on port 443. Broker port 8443 and the
  health listener are loopback-only.
- nginx presents a dedicated workload certificate to Broker and verifies the
  Broker certificate chain and DNS name.
- The Go policy service exposes only an AF_UNIX socket. Production typed
  operations fail closed when it is unavailable.
- The `broker` and `broker-core` services are non-root. The deployment account
  can invoke only the audited deployment helper through sudo.
- The CA private key and client private keys do not exist on the Broker host.
- Releases are immutable directories selected by an atomic symlink. CI deploys
  only a verified artifact from the exact successful commit.

## Routine status check

Use an independently verified SSH host key. Never bypass host-key checking.

```sh
systemctl is-active secret-broker-policy secret-broker nginx
systemctl --no-pager --full status secret-broker-policy secret-broker nginx
curl --fail --silent --show-error http://127.0.0.1:9080/health
readlink /opt/secret-broker/broker
cat /opt/secret-broker/deployed-release
```

The public check is read-only and must verify TLS normally:

```sh
curl --fail --silent --show-error --proto '=https' --tlsv1.3 \
  https://broker.52trz.com/health
```

Do not use `-k`, `--insecure`, dynamic `ssh-keyscan`, or
`StrictHostKeyChecking=no` as a recovery shortcut.

## Log review

Read only the bounded interval needed for the incident. Do not export raw logs
until the canary-secret scan and redaction review pass.

```sh
journalctl -u secret-broker-policy -u secret-broker --since '-15 minutes' \
  --no-pager --output=short-iso
```

Expected audit records contain request IDs, principal metadata, policy result,
operation identifier, and status. They must not contain Authorization values,
cookies, OTPs, private keys, provider signatures, or decrypted secret values.

## Release and rollback

Normal deployment is the protected `Deploy ECS` GitHub environment. Before
approval, record the candidate commit, artifact SHA-256, attestation result,
current release, and rollback release. The deployment helper validates the
payload, creates a versioned directory, switches the symlink, restarts the Go
and Node services, and rolls back on health failure.

For a manual rollback in an approved maintenance window:

1. Resolve the exact prior release directory and verify it is under
   `/opt/secret-broker/releases`.
2. Record the current symlink and service status.
3. Atomically replace the symlink with the recorded prior release.
4. Restart `secret-broker-policy`, then `secret-broker`.
5. Verify the loopback health endpoint, public TLS health, identity mapping,
   one approved read-only typed operation, and audit persistence.
6. Preserve the failed release for investigation; do not delete it during the
   incident.

The one-time conversion of a legacy host is documented in
`deploy/PRODUCTION-MIGRATION.md`.

## Certificate response

For a lost client or nginx workload key:

1. Suspend the affected device/client and revoke its certificate or key.
2. Invalidate active sessions and operation grants for that principal.
3. Issue replacement material from the offline CA through the approved
   ceremony. Never generate or download a client private key through the
   production web interface.
4. Distribute the replacement through the approved out-of-band channel.
5. Verify rejection of the old identity and acceptance of the new identity.
6. Record certificate serial/fingerprint metadata only.

If the server key or CA is suspected compromised, stop credential operations,
activate the incident plan, replace the trust chain, and require all clients to
re-enroll. Do not attempt an in-place partial rotation.

If a CA private key or any final-client private key is found on the Broker
host, treat the complete trust domain as compromised even when file mode is
`0600`. The recovery ceremony must:

1. Preserve only public certificate fingerprints, serials and validity dates
   as evidence; never copy private material into the incident record.
2. Create a new offline root/intermediate hierarchy outside the Broker host
   and outside CI. Keep the signing key non-exportable where supported.
3. Issue a new Broker server certificate and one dedicated nginx workload
   certificate. Configure the latter's exact SHA-256 fingerprint as the only
   trusted proxy identity.
4. Re-enroll every human, workload and device from independently verified
   principals. Do not reuse or copy the old client private keys.
5. Switch trust in staging, prove that forged proxy headers and every old
   certificate fail, then perform the reviewed production cutover with a
   rollback that does not reactivate the compromised CA.
6. Remove all CA and final-client private keys and their backups from the
   Broker host after the cutover. Verify absence using file metadata only.
7. Revoke the old hierarchy wherever revocation is enforced and retain the
   public rotation evidence outside the repository.

## Provider credential rotation

Prefer OIDC, workload identity, and short-lived provider tokens. For a static
credential that cannot yet be removed:

1. Create a replacement with narrower or equal provider permissions.
2. Store it through the approved KMS/SOPS path without printing it.
3. Run the provider's read-only contract test in staging.
4. Switch the adapter, verify audit and canary-secret checks, then revoke the
   old credential at the provider.
5. Record provider, credential identifier/fingerprint, actor, timestamps, and
   evidence links—never the value.

Any credential previously committed, logged, pasted into chat, or placed in an
artifact is treated as compromised even after the file is deleted.

## Android OTP device incident

- Suspending or revoking the device cancels waiting, received and consuming
  tasks; a late consumer result must not restore a revoked operation.
- A SIM/subscription change requires a new binding before automatic matching.
- Ambiguous sender, account, SIM, template, or challenge matches go to manual
  handling. Never choose the newest SMS as a fallback.
- The app does not persist SMS bodies or OTPs. Push notifications must not carry
  codes.
- After permission revocation, battery restriction, reboot, or app update, run
  the physical-device acceptance matrix again before restoring unattended use.

## Go policy-core outage

Typed operations must return a denial while the socket is unavailable. Check
the socket ownership and service without changing permissions broadly:

```sh
systemctl status secret-broker-policy --no-pager
stat /run/secret-broker/core.sock
journalctl -u secret-broker-policy --since '-15 minutes' --no-pager
```

Restart only after recording the failure. If the core repeatedly fails, keep
operations denied and roll back the full release; do not configure Node to
bypass the policy decision.

## Backup and disaster recovery

Backups must be encrypted before leaving the host, integrity-signed, versioned,
and stored separately from their decryption key. They include encrypted Broker
configuration, audit-chain state, device public metadata, revocation data, and
release metadata. They never include client private keys, the offline CA key,
plaintext OTPs, browser cookies, or temporary sessions.

The Tencent environment is passive. A recovery exercise must:

1. Provision from reviewed Terraform without passwords or embedded secrets.
2. Restore a selected encrypted backup and verify its signature before
   decryption.
3. Install the exact attested release digest.
4. restore certificate revocation and audit-chain continuity;
5. keep DNS unchanged while loopback and private smoke tests run;
6. obtain approval, switch DNS, and run public read-only smoke tests;
7. measure backup age (RPO) and elapsed recovery time (RTO);
8. revoke temporary recovery access and retain the redacted report.

The target is RPO at most 15 minutes and RTO at most 60 minutes. These remain
unverified until a real exercise records both measurements.

## Escalation and acceptance

Stop the release for any known P0/P1, unrotated exposed credential, unverifiable
host identity, direct public backend access, unsigned/unattested production
artifact, failed provider contract, missing audit event, or detected canary
secret. Current evidence and blockers are tracked in
`docs/PRODUCTION-ACCEPTANCE.md`.
