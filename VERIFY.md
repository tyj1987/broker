# Verification guide

This file describes reproducible checks. It is not a release certificate and
does not claim that a workflow, device test, provider contract test or
production deployment has run.

## Local checks

Use Node 24 LTS and install from lock files:

```sh
cd broker
npm ci --ignore-scripts --no-audit --no-fund
npm audit --audit-level=high
npm run lint
npm run test:coverage
npm run openapi:generate
git diff --exit-code -- ../contracts/openapi.yaml
```

Run the Go policy-core gate independently:

```sh
cd core
test -z "$(gofmt -l .)"
go vet ./...
go test -race -coverprofile=coverage.out ./policy
go test -race ./server
go build ./...
go tool cover -func=coverage.out
```

The Go policy package must remain at or above 90% statement coverage. The Node
typed-operation state machine, authorization policy, and outbound policy gate
enforces at least 90% lines, 85% branches and 90% functions.

The Python, Go and VS Code SDKs, Android project, browser helper, Windows Tauri
client, Terraform trees and production image are checked by
`.github/workflows/ci.yml`. CI output and artifacts are the evidence; this
document never substitutes for them.

## Artifact verification

Successful `master` CI publishes the candidate image by immutable digest,
scans it, creates an SPDX JSON SBOM and signs provenance and SBOM attestations.
Verify a downloaded artifact with GitHub CLI:

```sh
gh attestation verify ARTIFACT --repo tyj1987/broker
```

Deployment must use the exact successful CI commit. The production workflow
re-verifies the release checksum and attestation before the protected
environment can deploy it.

## Acceptance boundary

Passing automation is necessary but insufficient. The release remains blocked
until the evidence and residual-risk gates in
[`docs/PRODUCTION-ACCEPTANCE.md`](docs/PRODUCTION-ACCEPTANCE.md) are satisfied,
including real provider accounts, approved staging attacks, Xiaomi device
tests, credential rotation, production read-only smoke tests and disaster
recovery rehearsal.

Report vulnerabilities through the repository's private GitHub security
advisory form. Do not include credentials, OTPs, private keys or decrypted
configuration in an issue or test log.
