# Frequently asked questions

## Is this release production-ready?

Not yet. Local source gates have passed for several components, but production
still has unresolved P0/P1 findings and the provider, physical-device,
credential-rotation and disaster-recovery evidence is incomplete. See
[Production acceptance](PRODUCTION-ACCEPTANCE.md).

## Does the Broker give secrets to an AI client?

Strict-profile clients call `/api/v2` typed operations and receive only the
allowed business result. Plaintext resolve, arbitrary proxy and free-form SSH
are v1 compatibility features and are denied to strict identities.

Redaction is defense in depth, not a permission mechanism. A value that has
already been returned to a caller cannot be made secret by later masking it in
a log.

## Why does `/health` work without a client certificate?

The public endpoint intentionally returns only `{"status":"ok"}` for load
balancers. Version, uptime, service names, configuration and secret state are
not exposed there. Operation and management endpoints require an authenticated
identity.

## How is nginx trusted?

nginx uses a dedicated workload certificate that is not a user or AI identity.
Broker trusts only its pinned fingerprint as a proxy. nginx replaces inbound
certificate and forwarding headers, verifies Broker's certificate chain and
name, and connects only to the loopback backend. Copying a public client
certificate or forging an `X-SSL-*` header is not sufficient authentication.

## Can I turn off TLS verification for testing?

No production or acceptance command may use `--insecure`, `-k`,
`rejectUnauthorized: false`, dynamic host-key acceptance or equivalent bypasses.
Create a test CA and correct SANs instead. Private CA material stays outside the
repository.

## How do provider operations become production-enabled?

Each operation has a versioned Manifest and a policy entry. It is exercised
with an isolated provider account for request shape, least privilege, error
handling, rotation, revocation and redaction. Only retained evidence for the
exact revision permits `contract_verified: true`; otherwise production policy
returns `contract_unverified`.

## How does Android OTP collection work?

The device registers a hardware-backed signing key and reports its capabilities.
It accepts only messages matching an existing task, exact sender/template,
device, SIM and challenge binding. Unmatched messages and full SMS bodies are
not uploaded. Ambiguity, delayed codes, SIM changes, revoked permission and
expired tasks require user handling.

Android SMS permissions are restricted by the platform and device policy. A
signed APK does not guarantee unattended access. Google SMS User Consent is a
user-confirmed fallback and is not reported as unattended success.

## Does iOS read SMS messages in the background?

No. The current iOS source is an initial SwiftUI pairing and Secure Enclave
proof implementation. Compilation, signing, approval UI and physical-device
validation are still open. Background arbitrary SMS reading is not a release
claim.

## Where are credentials stored?

Runtime secrets and private PKI material are excluded from Git. The transition
service supports SOPS-encrypted local storage, while the production target is a
KMS-backed envelope and short-lived cloud identity wherever possible. Never
place credentials in Terraform variables, state, issue text, chat, screenshots
or CI logs.

## What happens if audit storage fails?

Sensitive v2 state changes must append mandatory audit intent before mutation.
If that append fails, the request returns `audit_unavailable` and the mutation
does not run. Production acceptance additionally requires independent,
immutable audit retention; local JSONL alone does not satisfy that gate.

## How do I deploy or roll back?

Use the protected workflow and versioned-release helper described in
[Deployment](https://github.com/tyj1987/broker/blob/master/deploy/README.md) and [RUNBOOK](https://github.com/tyj1987/broker/blob/master/RUNBOOK.md). Do not copy the
working tree over production. The current host must first complete the one-time
migration and all P0/P1 remediation in
[Production migration](https://github.com/tyj1987/broker/blob/master/deploy/PRODUCTION-MIGRATION.md).

## How do I report a vulnerability?

Follow [SECURITY.md](https://github.com/tyj1987/broker/blob/master/SECURITY.md) and use GitHub's private vulnerability
reporting flow. Do not include real credentials, OTP values, private keys or
decrypted production configuration.
