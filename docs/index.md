# Secret Broker documentation

Secret Broker is a policy-bound credential broker for automation, developer
tools and cloud workloads. Strict callers submit typed operations and receive
only approved business results; they do not receive long-lived credentials.

[:material-rocket-launch: Source verification](QUICKSTART.md){ .md-button .md-button--primary }
[:material-github: GitHub](https://github.com/tyj1987/broker){ .md-button }

## Start here

- [Architecture](https://github.com/tyj1987/broker/blob/master/ARCHITECTURE.md) — current trust boundaries and repository layout.
- [Threat model](THREAT-MODEL.md) — assets, actors, attacks, implemented controls and open gaps.
- [SDK reference](SDK-REFERENCE.md) — `/api/v2` typed-operation and approval clients.
- [Tool registry](TOOL-REGISTRY.md) — versioned capability metadata and risk invariants.
- [Automation tasks](AUTOMATION-TASKS.md) — policy-routed task lifecycle, APIs and current durability boundary.
- [Execution tokens](EXECUTION-TOKENS.md) — short-lived, bound, single-use adapter capabilities.
- [Audit integrity](AUDIT-INTEGRITY.md) — restart-safe hash chaining, migration boundary and external-anchor gate.
- [GitHub adapter](GITHUB-ADAPTER.md) — fixed-origin repository metadata operation and credential lease boundary.
- [Cloudflare adapter](CLOUDFLARE-ADAPTER.md) — account-bound zone inventory with a scoped token capability.
- [SSH capability](SSH-PROXY.md) — typed target inspection and the isolated-runner production boundary.
- [Docker adapter](DOCKER-ADAPTER.md) — repository-bound tag inventory through a short-lived pull token.
- [PostgreSQL adapter](POSTGRESQL-ADAPTER.md) — fixed-query inspection with a verified read-only role boundary.
- [Google Drive adapter](GOOGLE-DRIVE-ADAPTER.md) — file-bound plain-text export through a mandatory content-release filter.
- [Decision queue](DECISION_QUEUE.md) — open high-impact choices and their required evidence.
- [Verification](https://github.com/tyj1987/broker/blob/master/VERIFY.md) — reproducible local and CI checks.
- [Production acceptance](PRODUCTION-ACCEPTANCE.md) — observed evidence, release blockers and remaining gates.
- [Operations runbook](https://github.com/tyj1987/broker/blob/master/RUNBOOK.md) — deployment, rollback, rotation, incidents and disaster recovery.

## Security boundary

`/api/v2` covers the versioned tool registry, typed operations, WebAuthn-backed approvals, registered
devices and operation-bound OTP tasks. A production request must pass both the
Node precheck and the Go policy core, and its exact provider operation must have
retained isolated-account contract evidence.

`/api/v1` is a migration surface. Strict-profile identities are denied access
to plaintext resolution, arbitrary proxying, state mutation and free-form SSH.
The existence or test coverage of a compatibility route does not make it safe
for a strict deployment.

## Client status

The repository includes Go, Python and VS Code SDKs; a Tauri Windows/Linux
client; a Kotlin Android client; an initial SwiftUI iOS client; and a Chrome/
Edge helper. Physical-device, signing and production validation states are
reported separately in the production acceptance record.

Do not place credentials, OTP values, private keys, decrypted configuration or
production evidence containing secrets in documentation, issues or CI logs.
