# One-time production migration

This procedure prepares an existing installation for non-root, atomic releases. It is intentionally not run by CI. Execute it in a reviewed maintenance window using an independently verified SSH host key and keep the existing service available for rollback.

## Preconditions

- P0 proxy TLS verification has been fixed and tested in staging.
- Potentially exposed credentials and the nginx workload certificate have been rotated.
- A filesystem or ECS snapshot and a copy of the current systemd/nginx configuration exist outside the release directory.
- The operator has recorded the current application SHA-256, nginx configuration hash, service status, and public health response.
- The `broker-deploy` account has its own SSH key; root SSH login is disabled after verification.

Do not copy credential values into tickets, shell history, CI variables, or this repository.

## Target ownership and paths

| Path | Owner/mode | Purpose |
|---|---|---|
| `/opt/secret-broker/releases` | `root:broker-deploy`, `0750` | Immutable application releases |
| `/opt/secret-broker/broker` | root-managed symlink | Active release |
| `/var/lib/secret-broker` | `broker:broker`, `0700` | Encrypted secret data and audit output |
| `/etc/secret-broker/pki/ca/ca.crt` | `root:broker`, `0440` | CA public certificate only |
| `/etc/secret-broker/pki/server/server.crt` | `root:broker`, `0440` | Broker server certificate |
| `/etc/secret-broker/pki/server/server.key` | `root:broker`, `0440` | Broker server private key |
| `/etc/secret-broker/pki/workloads/nginx/*` | `root:nginx`, `0440` | nginx workload certificate and key |
| `/etc/secret-broker/age` | `root:broker`, directory `0750`, key `0440` | SOPS age identity |
| `/usr/local/sbin/secret-broker-deploy` | `root:root`, `0755` | Validated atomic deployment helper |
| `/run/secret-broker/core.sock` | `broker-core:broker`, `0660` | Local-only Go policy decision channel |

Install [secret-broker.service](systemd/secret-broker.service), [secret-broker-policy.service](systemd/secret-broker-policy.service), the deployment helper, and the sudoers fragment only after reviewing their exact contents. Validate the sudoers fragment with `visudo -cf` before enabling it.

## Migration sequence

1. Create the locked `broker` and `broker-core` service accounts, put `broker-core` in the `broker` group, and create the separate `broker-deploy` login account.
2. Create the target directories with the ownership and modes above.
3. Copy—not move—the currently deployed application to a versioned release directory named by its verified commit. Refuse to invent a commit when provenance is unknown; use a quarantine label and do not enable CI deployment.
4. Copy encrypted data and only the runtime PKI files listed above to the target paths without printing them. The CA private key and all client private keys must remain offline and must not exist on the Broker host. Verify ownership and permissions with metadata-only commands.
5. Replace `/opt/secret-broker/broker` with a relative symlink to the versioned release.
6. Install and start both hardened systemd units. Verify that the policy socket is owned by `broker-core:broker`, then verify `127.0.0.1:9080/health`, the nginx mTLS path, and a read-only typed operation. A missing policy core must make production operations fail closed.
7. Install the dedicated nginx workload certificate and [nginx configuration](nginx/broker.52trz.com.conf); run `nginx -t` before reload.
8. Install the deploy helper and sudoers fragment. Confirm the deployment account cannot obtain an interactive root shell or run any other sudo command.
9. Record `deployed-release`, artifact SHA-256, service unit hash, nginx hash, and rollback release.
10. Disable root SSH login only after a second verified management path is working.

## Rollback

Stop the new service, restore the prior systemd/nginx files, atomically point the symlink to the recorded prior release, and restart. Re-run loopback and public read-only health checks. Preserve failed release logs after redaction; do not copy raw environment or secret files into the incident record.

Migration does not by itself approve production. The release gates in [production acceptance](../docs/PRODUCTION-ACCEPTANCE.md) still apply.
