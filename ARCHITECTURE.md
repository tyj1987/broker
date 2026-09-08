# Secret Broker architecture

> Current V4.2 architecture. Design goals and verified evidence are separate;
> see `docs/PRODUCTION-ACCEPTANCE.md` for release status and `RUNBOOK.md` for
> operations.

中文：[ARCHITECTURE.zh-CN.md](ARCHITECTURE.zh-CN.md)

## Trust boundary

```text
clients / SDKs / workloads
        |  mTLS, short browser session, or scoped workload identity
        v
trusted nginx edge
        |  replaces inbound identity headers; dedicated proxy identity
        v
Node transition layer -- identity/schema/policy precheck -- local socket -- Go policy core
        |
        +-- typed /api/v2 operations, approvals, devices and OTP tasks
        +-- isolated /api/v1 compatibility surface; strict callers denied
        +-- append-only audit and common redaction
        +-- provider adapters with pinned outbound request shapes
```

Production fails closed when the Go decision core is unavailable. Node remains
a transition, UI and protocol-compatibility layer; it must not offer a route
that bypasses the Go policy decision.

## Typed operation model

A caller supplies only `provider`, `operation_id`, `account_ref`, `environment`
and schema-approved `typed_parameters`. Authorization binds subject, role,
security profile, identity method, provider, account, environment, resource,
API-key subconstraints, approval state and lifetime.

Approval requests bind a canonical hash of the complete operation. The
requester cannot approve their own request; approval requires a short session
with WebAuthn step-up and is consumed once. Creating an approval request is
itself pre-authorized through the same Node and Go policy path.

An OTP belongs to an existing operation. The task binds operation, account,
device, SIM, provider, challenge, recipient and expiry. There is no API for an
AI caller to read the newest code.

## Identity and session levels

- Strict: hardware FIDO2/WebAuthn, mTLS, or audience-bound short-lived workload
  identity.
- Controlled: a managed passkey may be allowed by policy.
- Compatibility: password, TOTP, bearer keys and v1 features are available only
  on an isolated listener under explicit policy.

SMS is not an authentication factor for Broker and cannot approve payments,
account recovery or security-setting changes. Browser sessions have a ten
minute absolute lifetime, are revocable, are not returned in response bodies,
and use `Secure`, `HttpOnly`, `SameSite=Strict` cookies.

## Credential and outbound boundary

OIDC, cloud roles and STS identities are preferred. Where a static credential
is unavoidable, only the constrained adapter uses it. Callers cannot replace
authorization, cookie, host, signature or forwarded-identity headers.

Outbound policy fixes scheme, hostname, port, method, path template, headers
and response size. Absolute URLs, redirect escape, IP literals, private and
loopback networks, and cloud metadata endpoints are denied.

Production configuration, private keys, logs, backups, device data and
Terraform state are excluded from Git. Local encrypted storage remains a
transition implementation; KMS envelope encryption, immutable remote audit and
process-isolated adapters do not yet have production evidence.

## Clients

- Windows/Linux: Tauri 2 desktop client.
- Android: Kotlin/Compose, Keystore, dual-SIM and SMS capability detection.
- iOS: initial SwiftUI and Secure Enclave P-256 protocol implementation;
  compilation, signing and device validation remain open.
- Browser: Chrome/Edge MV3 plus Native Messaging for user-assisted one-time
  filling only.
- CLI/SDK: Go CLI and maintained Go, Python and VS Code clients.

## Deployment surfaces

- `Dockerfile` and Compose: separate Node and Go-core containers, non-root and
  read-only runtime policies.
- `deploy/helm/broker/`: Go core as a local-socket sidecar.
- `infra/aliyun/broker/`: Aliyun primary-site infrastructure baseline.
- `infra/tencent/`: Tencent disaster-recovery infrastructure baseline.
- `deploy/systemd/` and `deploy/nginx/`: versioned release and trusted-proxy
  configuration.

Terraform currently has formatting and offline validation evidence only; that
does not imply a plan or apply. Production remains subject to the P0/P1,
credential-rotation, contract-test, physical-device and recovery gates in the
acceptance record.

## Repository layout

```text
broker/               Node transition service and dashboard
core/                 Go policy core and CLI
clients/              desktop, android, ios and browser
sdk/                  Go, Python and VS Code clients
contracts/            OpenAPI and generated contracts
providers/            versioned provider manifests
deploy/               container, Helm, nginx, systemd and rollback assets
infra/                Aliyun primary and Tencent DR Terraform
docs/                 architecture, security, usage and acceptance records
```

## Invariants

1. AI callers do not receive long-lived plaintext credentials.
2. Every entry point uses the same permission dimensions; identity transport
   does not alter the resulting authority.
3. Strict profiles deny plaintext resolution, arbitrary URLs and free-form
   command execution.
4. Sensitive v2 mutations record mandatory audit intent first and fail closed
   when audit storage is unavailable.
5. Implemented, automated-test passed, physical-device passed and production
   verified are reported as separate states.
