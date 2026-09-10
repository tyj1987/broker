# Infrastructure baseline

These Terraform configurations create the minimum network and compute baseline
for the primary Aliyun deployment and Tencent Cloud disaster-recovery site. They
do not install Secret Broker, create credentials, copy PKI, or perform failover.

## Supply-chain baseline

- Terraform CLI is fixed to `1.16.1`.
- Aliyun provider is fixed to stable `1.279.0`.
- Tencent Cloud provider is fixed to `1.83.26`.
- CI runs `terraform fmt -check`, initializes without a backend, validates both
  roots, and scans the result as infrastructure as code.
- A reviewed provider upgrade must update the exact constraint and committed
  dependency lock file together.

Never use `terraform init -upgrade` in an apply job. Production applies consume
the reviewed lock file and a verified Terraform binary.

## Authentication and state

Use workload identity to assume a narrowly scoped role. Do not configure root
AccessKeys, account passwords, SSH private keys, TLS private keys, Broker API
keys, or recovery material as Terraform variables.

Backend settings are intentionally environment-specific and are not committed.
Production automation must inject an approved remote backend configuration; a
local-state apply is prohibited. The service must encrypt state at rest,
authenticate a workload identity, retain versions, and serialize writes. No
apply wrapper is shipped in this repository yet; until a reviewed deployment
job enforces these requirements, these roots are validation inputs only and
must not be used for a production apply.

For validation without state access, CI uses:

```sh
terraform init -backend=false -lockfile=readonly
terraform validate
```

## Network boundary

Only TCP 443 is public. SSH is restricted to `admin_cidr`; the Broker backend
port is never opened by the cloud security group. Outbound provider traffic is
limited to HTTPS plus explicitly supplied DNS and NTP CIDRs.

Resolve DNS and NTP addresses from the selected region's current official cloud
documentation and review them before apply. The example Aliyun values use
documentation-only address space so an unedited example fails connectivity
instead of silently granting broad access.

Security groups are only one layer. The host firewall must keep the Broker
listener on loopback, and provider adapters must apply their hostname, port,
method, path, redirect, and response-size allowlists.

## Encryption and recovery

System and data disks are encrypted. Application secrets use KMS-backed envelope
encryption and do not enter Terraform state. A Tencent Cloud deployment remains
standby until a documented restore has verified backup decryption, certificate
revocation state, audit continuity, endpoint identity, and a read-only smoke
test. These files alone are not evidence of the RPO or RTO targets.

## Apply gate

Before any apply, record the source commit, Terraform plan hash, provider lock
hashes, target account and region, approvers, rollback path, and current remote
state version. A human must review the saved plan; CI must never auto-apply code
from a public pull request.
