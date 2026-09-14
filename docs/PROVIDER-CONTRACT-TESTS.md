# Isolated provider contract tests

Provider operations remain `contract_required` until a real isolated account
has passed the active-path and revocation checks defined for that provider.
Passing unit tests or enabling a tool in the registry is not contract evidence.

The first executable contract runner covers these read-only operations:

- `github.repository.read@1.0.0`
- `aliyun.ecs.instances.list@1.0.0`

For one exact provider, account, environment and resource binding, the version 2
runner checks registry discovery, a fixed provider-principal probe, an exact
authority match, one bounded read, secret-free output, wrong-account denial and
wrong-resource denial. GitHub uses the authenticated App installation endpoint;
Alibaba Cloud uses STS `GetCallerIdentity`. The adapter hashes every returned
principal identifier before it can enter a task result. The runner accepts and
compares only lowercase SHA-256 digests plus the bounded principal type.
For Alibaba Cloud, signer protocol version 3 also returns an opaque,
non-credential lease binding. The ECS request must use the same binding as the
identity probe and the consumed task execution. The Node client, adapters and
Go protocol core reject execution, request or credential binding drift before
the ECS request is sent. All typed business parameters are validated before
either signer or provider traffic occurs.

It issues only typed `/api/v2/tasks` requests.
It cannot submit a URL, authentication header, provider credential or arbitrary
operation. An unexpected negative task is cancelled when possible and the run
still fails.

## Protected invocation

The JSON plan and every credential input are absolute file paths supplied by
the operator's existing protected local channel. Credential values are not
accepted as command-line arguments or environment variables. A representative
invocation is:

```console
npm run provider:contract -- \
  --broker https://broker.52trz.com \
  --plan-file /protected/dq004-plan.json \
  --api-key-file /protected/broker-api-key \
  --client-cert-file /protected/client.crt \
  --client-key-file /protected/client.key \
  --ca-file /protected/broker-ca.crt
```

The CLI opens each input with a no-follow descriptor on POSIX, rejects symbolic
links and redirected parent paths, and verifies that the file metadata remains
stable through the read. POSIX input directories and files cannot be writable
by group or other users; API keys and client private keys must be owner-only.
On Windows, the same reparse-point and stable-file checks apply, while the
operator must provision an owner-only NTFS ACL because POSIX mode bits are not
authoritative there. An unsafe or changing input fails before any Broker
request is created.

The plan is an external evidence input and must not be committed. It contains
only account and resource references plus expected authority digests, never
raw provider identifiers or credentials. A version 2 plan must contain the
provider-specific `expected_authority` object. GitHub requires SHA-256 digests
of the installation ID, account ID and lowercase account login plus
`target_type`; Alibaba Cloud requires SHA-256 digests of `AccountId`,
`PrincipalId` and `Arn` plus `IdentityType`.

The command emits a
small pass/fail receipt containing provider, operation, environment and check
names. It omits account references, resource references and provider results.
Failures emit only a stable contract error code.

The operator must retain the signed plan digest, exact release SHA, timestamp,
provider-side audit event references and the safe receipt outside the source
repository. The runner does not collect or print those external references.

Production preflight accepts that material only through the version 1 signed
evidence contract in `contracts/provider-contract-evidence-v1.schema.json`.
The canonical evidence contains exactly one GitHub receipt followed by one
Alibaba Cloud receipt and binds each plan digest and provider-audit reference
digest to the exact release SHA, current provider binding generation and exact
bytes of both protected signer authority configurations. Its validity is at
most 15 minutes. A detached Ed25519 signature is checked against a root-owned
keyring; the Broker receives no evidence-signing private key.

The verifier reads release-specific root-owned files from
`/var/lib/secret-broker/provider-contract-evidence/<release-sha>` and fixed
signer configuration and keyring files under `/etc/secret-broker`,
rejects symbolic links, writable parent directories, unsafe modes, unstable
files, non-canonical JSON, key ambiguity, expired evidence and release or
configuration drift. It queries the binding digest twice over the Broker-owned
mode `0600` Unix health socket and rejects any change during verification. It
emits only `provider_contract_evidence_ready=yes` or `no`. Missing evidence
remains a production-preflight failure.

The deployment helper validates candidate-SHA evidence before changing the
managed release symlink. After switching, it restarts every release-bound
signer, audit, policy and Broker service, waits on the protected Unix health
socket, then runs all 22 production preflight checks. Any failure atomically
returns the symlink to the previous release, restarts the previous workloads
and verifies runtime readiness. The deployment remains failed even when
availability is restored. Full rollback acceptance remains closed until fresh,
release-specific evidence is issued; an expired prior receipt is never treated
as successful security verification.

## Evidence boundary

This runner proves the bound provider principal, active read path and two
authorization boundaries only.
Provider-side credential or role revocation, rotation overlap, wrong-workload
denial, regional outage behavior and audit continuity are separate required
phases. A passing receipt alone must not change a provider manifest from
`contract_required` to `production`.

The signer protocol cores require the generation of the configuration actually
loaded at construction time and return it only for a peer-authorized random
challenge on the fixed Unix socket. Production preflight samples both signers
before and after evidence verification and accepts only when those generations
remain stable and equal the protected configuration hashes and the signed
receipt. The probe returns no credential material and performs no provider
request. A separate pre-start marker is not accepted because it would leave a
configuration-open race.

The Alibaba signer contains an IMDSv2-only ECS RAM Role credential backend and
the fixed Signature V3 implementation. It has no IMDSv1, environment variable,
shared-profile or long-term access-key fallback. Its unit restricts IP egress to
the ECS metadata address; a dedicated workload and production egress controls
must still be verified before enablement. The GitHub signer contains the strict
KMS digest-signing boundary, exact key-version routing, pinned-public-key
verification and a dedicated-gateway `AsymmetricSign` transport. That transport
uses only an explicit IMDSv2 ECS RAM Role, a fixed private gateway hostname,
root-owned CA pin and configured private CIDRs. Its pure-Go resolver can query
only Alibaba Cloud's documented VPC DNS addresses `100.100.2.136` and
`100.100.2.138`; it cannot inherit `/etc/resolv.conf` or an environment proxy.
It rejects redirects, DNS answers outside the configured KMS CIDRs, response
drift and credential fallback.

The shared IMDSv2 provider keeps the metadata token and temporary STS
credential only in the immutable role-bound process instance. Credential
refreshes are coalesced, have a hard timeout, and stop serving the cached value
at a fixed five-minute refresh boundary. The token lifetime is measured from
the token request start. Cache use requires both the absolute deadline and a
non-negative local elapsed-time check, so a wall-clock rollback cannot extend
authority. Cancellation never returns a cached credential, and a failed or
late refresh clears the credential and fails closed through a bounded retry
cooldown. These are source-level controls; they are not evidence of ECS
metadata behavior or credential revocation in an isolated account.

GitHub does not document a way to upload an arbitrary externally generated App
public key. The approved design therefore requires a human-controlled ceremony
to import a GitHub-generated RSA private key into Alibaba KMS/HSM as BYOK. That
ceremony, real KMS transport verification, protected configurations, isolated workload
identities and real account receipts are still required before DQ-004 can
close. Unit or mock-signature success is not provider contract evidence.

The Alibaba version 2 and GitHub version 3 service configurations remain non-secret and exact-schema. The Alibaba
configuration names one `ecs_ram_role_name` and one or more exact
account/environment/resource/region bindings. The GitHub configuration binds
each account/environment/client tuple to a KMS `key_id`, immutable key-version
ID, base64-encoded RSA SPKI public key and its SHA-256 digest. Its global fields
also bind one ECS RAM Role, one dedicated KMS hostname, the exact CA file digest
and one or more canonical private CIDRs. Unknown, null,
duplicate, weak-RSA, mismatched-digest and credential-like fields are rejected.
No access key, session token, GitHub private key or KMS client credential is a
valid configuration field.

The source GitHub signer unit denies all IP traffic by default and allows only
IMDSv2 plus the two fixed VPC DNS endpoints. A reviewed root-owned systemd drop-in must add the exact configured KMS
private CIDRs before activation. Application-layer DNS validation independently
requires every answer to remain inside those same CIDRs and dials the verified
IP directly while preserving TLS hostname validation. This is source-level
fail-closed preparation, not evidence that production network controls exist.
Configured ranges are bounded to `/24` or narrower for IPv4 and `/64` or
narrower for IPv6; use `/32` or `/128` pins whenever gateway addressing is
stable.

The VPC DNS addresses are fixed from Alibaba Cloud's current ECS documentation:
[DHCP options sets and DNS hostnames](https://www.alibabacloud.com/help/en/vpc/dhcp-option-set-and-dns-hostname).
They must be revalidated during the production network ceremony; custom or
non-ECS deployment requires a separately reviewed resolver design rather than a
fallback to system DNS.

Runtime behavior follows the current official contracts: GitHub App JWTs use
RS256 and remain at most ten minutes; Alibaba ECS role credentials are obtained
with IMDSv2 and the temporary security token is included in the canonical
Signature V3 headers. The implementation sources and dates are recorded in the
versioned provider manifests. Before production, the ECS instance itself must
be independently verified with metadata `HttpTokens=required`, and the KMS key
version/public-key pin must match the human-reviewed BYOK receipt.

The 2026-09-12 production capability probe did not run either provider
operation: the deployed registry exposed only `broker.tools.inspect`, and both
requested provider bindings were denied before execution. That result is a
safe fail-closed observation, not a completed DQ-004 contract test.
