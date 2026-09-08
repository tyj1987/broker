# Secret Broker

A policy-bound credential broker for automation, developer tools and cloud
workloads. Strict-profile callers submit typed operations and receive only the
allowed business result; they do not receive long-lived credentials.

[![CI](https://github.com/tyj1987/broker/actions/workflows/ci.yml/badge.svg)](https://github.com/tyj1987/broker/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Languages:** [English](README.md) · [中文](README.zh-CN.md)

## Security model

- `/api/v2` is the strict boundary for typed operations, bound approvals,
  devices and short-lived OTP tasks.
- Node performs identity, schema and policy checks; production also requires an
  allow decision from the Go policy core over a local socket.
- A production operation is denied until its exact provider contract is marked
  verified after isolated-account testing.
- Browser sessions expire absolutely after ten minutes. Approvals require a
  WebAuthn-stepped-up session, separation of duties and one-time consumption.
- Outbound requests pin scheme, host, port, method, path, headers and response
  size. Private, loopback, metadata and redirect destinations are denied.
- Strict identities cannot use plaintext secret resolution, arbitrary proxying
  or free-form SSH from the v1 compatibility API.
- v2 state changes write mandatory audit intent before mutation and fail closed
  if audit storage is unavailable.

SMS is an input to an already-authorized operation, not a Broker login factor.
The Android client uploads only a matched code and task binding; it does not
upload message history or unmatched messages. SMS cannot approve payments,
account recovery or security-setting changes.

See [the threat model](docs/THREAT-MODEL.md) and
[architecture](ARCHITECTURE.md) for the precise trust boundaries.

## Current maturity

This repository contains the transition service, Go policy core, API contracts,
provider manifests, SDKs, Windows/Linux desktop client, Android client, initial
iOS client and browser helper. Existence of code is not production acceptance.

The six initial provider manifests remain contract-gated. Android and iOS need
physical-device validation, release artifacts need signing and provenance, and
the production environment has unresolved release blockers. The current,
evidence-based status is maintained in
[Production acceptance](docs/PRODUCTION-ACCEPTANCE.md).

## Repository layout

```text
broker/               Node transition service and dashboard
core/                 Go policy core
clients/
  desktop/            Tauri Windows/Linux client
  android/            Kotlin/Compose OTP device client
  ios/                SwiftUI/Secure Enclave initial client
  browser/            Chrome/Edge MV3 helper and native-host metadata
sdk/                  Go, Python and VS Code clients
contracts/            Generated OpenAPI contract
providers/            Versioned provider manifests
deploy/               Container, Helm, nginx, systemd and rollback assets
infra/                Aliyun primary and Tencent DR Terraform baselines
docs/                 Architecture, security, operations and acceptance docs
```

Production configuration, credentials, PKI private material, audit logs,
backups, device data, Terraform state and generated packages do not belong in
Git.

## Source verification

Node 24 is the supported broker development runtime. Install from the lock file
and run the security coverage gate:

```sh
cd broker
npm ci --ignore-scripts --no-audit --no-fund
npm audit --audit-level=high
npm run lint
npm run test:coverage
npm run openapi:generate
git diff --exit-code -- ../contracts/openapi.yaml
```

Additional Go, Python, Rust, Android, Swift, Terraform, Helm and container gates
run in [CI](.github/workflows/ci.yml). The complete local/CI distinction is in
[VERIFY.md](VERIFY.md).

## Configuration and deployment

[`secrets/broker.yaml.example`](secrets/broker.yaml.example) is deliberately
fail-closed and contains no credentials. It is suitable only as a structure
reference. Do not set `contract_verified: true` without retained contract-test
evidence, and do not perform a Terraform apply from the validation-only roots.

- Local source validation: [Quickstart](docs/QUICKSTART.md)
- Deployment and rollback: [deploy/README.md](deploy/README.md)
- Operations: [RUNBOOK.md](RUNBOOK.md)
- Production migration blockers: [deploy/PRODUCTION-MIGRATION.md](deploy/PRODUCTION-MIGRATION.md)

## Contributing and security reports

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Report
security issues privately using [SECURITY.md](SECURITY.md); do not include real
credentials, OTP values, private keys or production configuration in an issue.

Licensed under the [MIT License](LICENSE).
