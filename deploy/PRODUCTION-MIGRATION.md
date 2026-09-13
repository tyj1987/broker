# One-time production migration

This procedure prepares an existing installation for non-root, atomic releases. It is intentionally not run by CI. Execute it in a reviewed maintenance window using an independently verified SSH host key and keep the existing service available for rollback.

## Preconditions

Run `node deploy/bin/secret-broker-production-preflight.mjs` on the target host
before scheduling a release. It is read-only, prints only named pass/fail gates,
and exits with status 65 until every CD runtime invariant is satisfied. A green
preflight is necessary but does not replace the migration evidence or production
approval below.

- P0 proxy TLS verification has been fixed and tested in staging.
- The co-located CA and client keys have been replaced through an offline
  full-hierarchy ceremony, every client has been re-enrolled, and potentially
  exposed provider credentials have been rotated. Old-identity rejection
  evidence exists outside the repository.
- A filesystem or ECS snapshot and a copy of the current systemd/nginx configuration exist outside the release directory.
- The operator has recorded the current application SHA-256, nginx configuration hash, service status, and public health response.
- The `broker-deploy` account has its own SSH key; root SSH login is disabled after verification.

Do not copy credential values into tickets, shell history, CI variables, or this repository.

## Target ownership and paths

| Path | Owner/mode | Purpose |
|---|---|---|
| `/opt/secret-broker/releases` | `root:broker`, `0750` | Immutable application releases; the runtime group needs traversal, while the deployment account writes only through the root helper |
| `/opt/secret-broker/runtime/node` | root-managed symlink | Pinned Node 24 runtime verified against the vendor checksum |
| `/opt/secret-broker/broker` | root-managed symlink | Active release |
| `/var/lib/secret-broker` | `broker:broker`, `0700` | Encrypted secret data and audit output |
| `/etc/secret-broker/pki/ca/ca.crt` | `root:broker`, `0440` | CA public certificate only |
| `/etc/secret-broker/pki/server/server.crt` | `root:broker`, `0440` | Broker server certificate |
| `/etc/secret-broker/pki/server/server.key` | `root:broker`, `0440` | Broker server private key |
| `/etc/secret-broker/pki/workloads/nginx/*` | `root:nginx`, `0440` | nginx workload certificate and key |
| `/etc/secret-broker/age` | `root:broker`, directory `0750`, key `0440` | SOPS age identity |
| `/usr/local/sbin/secret-broker-deploy` | `root:root`, `0755` | Validated atomic deployment helper |
| `/usr/local/sbin/secret-broker-production-preflight.mjs` | `root:root`, `0755` | Read-only production CD readiness check |
| `/run/secret-broker/core.sock` | `broker-core:broker`, `0660` | Local-only Go policy decision channel |
| `/run/secret-broker-github-signer/signer.sock` | `root:broker-github-signer`, `0660`; parent `0750` | systemd-owned, signature-only GitHub App capability; private key remains in KMS/HSM |
| `/run/secret-broker-aliyun-signer/signer.sock` | `root:broker-aliyun-signer`, `0660`; parent `0750` | systemd-owned, execution-bound Alibaba Cloud Signature V3 capability; long-term credentials remain outside Broker |
| `secret-broker-audit-signer.service` | `broker-audit-signer:broker-audit-signer` | Uses only the pinned Alibaba KMS key and external monotonic state |
| `secret-broker-audit-exporter.service` | `broker-audit-exporter:broker-audit-exporter` | Exports audit-chain heads without holding a cloud signing or storage identity |
| `secret-broker-audit-store.service` | `broker-audit-store:broker-audit-store` | Publishes signed heads to locked OSS and COS stores |
| `secret-broker-audit-recovery.service` | `broker-audit-recovery:broker-audit-recovery` | Uses read-only cross-cloud identities to verify recovery evidence |

Install [secret-broker.service](systemd/secret-broker.service), [secret-broker-policy.service](systemd/secret-broker-policy.service), the deployment helper, and the sudoers fragment only after reviewing their exact contents. Validate the sudoers fragment with `visudo -cf` before enabling it. The service uses systemd credentials, so verify that the host supports `LoadCredential=` and the `%d` credential-directory specifier before the maintenance window.

The checked-in GitHub and Alibaba Cloud signer units and their `tmpfiles.d`
directory rules are deployment contracts,
not runnable placeholders. Do not install or enable them until their exact
release binaries, non-secret binding configurations, independently managed
cloud authorities and isolated-account receipts have passed review. The
production preflight intentionally remains red until that evidence exists.

Before the first hardened start, create `/etc/secret-broker/control-plane-state.key` from 32 cryptographically random bytes, owned by `root:root` with mode `0600`. Never pass this key on a command line or store it in Git, a unit file, a deployment log, or Helm values. With the Broker stopped, initialize the state exactly once using the same protected credential and the persistent state path:

```sh
sudo systemd-run --unit=secret-broker-state-init --wait --pipe --collect \
  --property=User=broker --property=Group=broker \
  --property=LoadCredential=control-plane-state.key:/etc/secret-broker/control-plane-state.key \
  --setenv=CONTROL_PLANE_STATE_PATH=/var/lib/secret-broker/control-plane-state.enc \
  --setenv=CONTROL_PLANE_STATE_KEY_FILE=/run/credentials/secret-broker-state-init.service/control-plane-state.key \
  --working-directory=/opt/secret-broker/broker \
  /opt/secret-broker/runtime/node/bin/node bin/control-plane-state-init.js
```

The initializer refuses to overwrite an existing state file. Back up the encrypted state and its key through separate protected channels. If the file later disappears, is corrupted, or cannot be authenticated, production startup must fail closed; do not rerun initialization as an availability workaround. Cold-start rollback detection still requires the external monotonic anchor recorded in DQ-001, so the file-backed mode is not approved for production scheduling.

## Migration sequence

1. Create the locked `broker` and `broker-core` service accounts, put `broker-core` in the `broker` group, and create the separate `broker-deploy` login account.
2. Create the target directories with the ownership and modes above.
3. Copy—not move—the currently deployed application to a versioned rollback directory named by its verified commit. Refuse to invent a commit when provenance is unknown; use a quarantine label and do not enable CI deployment. Separately extract the verified candidate artifact into its own versioned release directory, validate its manifest and compiled policy binary, then make that candidate the managed release symlink. Release directories are owned by `root:broker`; directories are `0550`, ordinary files are `0440`, and only reviewed executables are `0550`.
4. Copy encrypted data and only the runtime PKI files listed above to the target paths without printing them. The CA private key and all client private keys must remain offline and must not exist on the Broker host. Verify ownership and permissions with metadata-only commands.
5. Install the checksum-pinned Node 24 runtime below `/opt/secret-broker/runtime`, then replace `/opt/secret-broker/broker` with a relative symlink to the verified candidate release.
6. Install and start both hardened Broker systemd units. This one-time bootstrap is manual because the normal deploy helper intentionally requires an already-active policy core and managed symlink. Verify that the policy socket is owned by `broker-core:broker`, confirm the encrypted control-plane state was restored at generation 1 or later, then verify `127.0.0.1:9080/health`, the nginx mTLS path, and a read-only typed operation. Before starting either provider socket, install `deploy/tmpfiles.d/secret-broker-provider-signers.conf` as `root:root` mode `0644`, run `systemd-tmpfiles --create` against that exact file, and verify both parent directories are `root:<provider-signer-group>` mode `0750`. Provision the independently reviewed GitHub and Alibaba Cloud signer workloads under those separate runtime directories. Each root-owned systemd socket unit creates and retains its listener, while the matching service runs under a distinct non-root user and group. The Broker user may connect through group access but neither Broker nor a signer process may replace either directory or socket. A missing tmpfiles rule, policy core, socket unit, signer service, contract receipt, or unavailable control-plane state must make production acceptance fail closed.
7. Create the four fixed audit users and groups, then install the reviewed audit signer, exporter, immutable-store, and recovery-authority units listed above. The store service and health-helper source now enforce a strict non-secret configuration and fixed Unix-socket boundary, but the production workload-identity factory is intentionally unavailable and the binaries are not packaged. These units therefore remain deployment contracts, not runnable production services. Do not substitute placeholder commands, static AccessKeys, shared credential files or a shared `nobody` identity. The preflight intentionally remains not ready until all four units are active under their exact, mutually distinct identities and the immutable store returns a fresh `ready`/`verified`/`in_sync` health response when queried as `broker-audit-recovery`; process liveness alone is insufficient. A local JSONL chain is not production audit evidence.
8. Install the dedicated nginx workload certificate and [nginx configuration](nginx/broker.52trz.com.conf); run `nginx -t` before reload.
9. Install the deploy helper, production preflight, and sudoers fragment. Confirm the deployment account cannot obtain an interactive root shell or run any other sudo command. Run the preflight locally as root and retain its pass/fail-only output with the release evidence.
10. Record `deployed-release`, artifact SHA-256, service unit hash, nginx hash, and rollback release.
11. Disable root SSH login only after a second verified management path is working.

## Rollback

Stop the new service, restore the prior systemd/nginx files, atomically restore the recorded prior release layout, run `systemctl daemon-reload`, and restart the units that belonged to that release. Disable the new policy unit when the prior release did not use it. Re-run the prior release's loopback and public read-only health checks. Restoring a legacy configuration that contains a known P0 is availability rollback only and must not be reported as security acceptance. Preserve failed release logs after redaction; do not copy raw environment or secret files into the incident record.

Migration does not by itself approve production. The release gates in [production acceptance](../docs/PRODUCTION-ACCEPTANCE.md) still apply.
