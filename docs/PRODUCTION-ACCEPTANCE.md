# Production acceptance record

This document records observed evidence separately from planned controls. Passing source tests does not approve a production release.

## Baseline

- Source baseline: `master@450c3ed2e1ffafb6507b908fc5b94a980c9820b0`
- Upgrade branch: `codex/platform-upgrade`
- Production read-only observation date: 2026-09-09 (Asia/Singapore)
- Production DNS observed: `broker.52trz.com` resolved to `47.94.225.76`
- Public `/health`: HTTP 200 with the minimal body `{"status":"ok"}`

No credential values, private keys, environment files, or secret configuration were read during this observation.

## Production blockers observed

| Severity | Evidence | Required remediation |
|---|---|---|
| P0 | Effective nginx configuration uses `proxy_ssl_verify off` for Broker upstream locations. | Enable CA and hostname verification, deploy the dedicated nginx workload certificate, and regression-test forged headers and direct backend access. |
| P1 | `secret-broker.service` runs as `root`. | Run under a dedicated locked system account with only the required writable paths. |
| P1 | `/opt/secret-broker/broker` is not a managed release symlink and no `deployed-release` baseline was present. | Perform a reviewed one-time migration to versioned releases before enabling atomic CI deployment. |
| P1 | nginx 1.20.1 is the active production version. | Move to a vendor-supported security-maintained release and record the package provenance. |
| P2 | Broker listens only on `127.0.0.1:8443`, which prevents direct public access, but it has no separate observed `9080` health listener in the live configuration. | Deploy and verify the loopback-only health listener used by the hardened workflow. |

Production remains **not approved**. No deployment was attempted because P0/P1 gates, repository CI, credential rotation evidence, signed artifacts, provider contract tests, Android physical-device tests, and disaster-recovery rehearsal are incomplete.

## Local evidence obtained on the upgrade branch

- Node broker full regression suite: passed. The typed-operation, approval,
  authorization and outbound-policy coverage gate reports 97.51% lines,
  93.1% branches and 96.87% functions. Approval creation is pre-authorized by
  the same Node and Go policy path, and v2 state changes require a durable audit
  intent before mutation.
- Go policy core: test/vet/build passed; statement coverage 95.1%. Windows race instrumentation is unavailable and remains a Linux CI gate.
- Go SDK: test/vet/build passed.
- Python SDK: 30 tests passed with `cryptography==50.0.1`; the fixed test
  requirements passed `pip-audit --strict` with no known vulnerabilities.
- VS Code extension: build and 6 tests passed; VSIX packaging rejects fixture private keys and the final package contains only runtime files.
- Android: an earlier revision passed `testDebugUnitTest`, `assembleDebug` and
  `lintDebug` with Android API 37 and Build Tools 36. The latest source changed
  enrollment to require hardware-backed P-256; this Windows host currently has
  no Android SDK, so that revision awaits clean CI rebuild. Physical-device
  behavior remains unverified.
- Windows desktop: an earlier revision passed the TypeScript build, Cargo check,
  Clippy with warnings denied, five Rust tests, release executable, native host
  executable and unsigned NSIS build. The latest ACL addition awaits clean CI
  rebuild because Rust tooling is no longer available in this session.
- Browser helper: JavaScript syntax, least-privilege manifest tests, native-host compilation, and native-host unit tests passed locally. Browser-to-production end-to-end fill remains unaccepted.
- Supply chain: Gitleaks 8.29.1 (official release checksum verified) reports no
  unallowlisted findings in either the complete Git history or the staged
  upgrade. Node broker, VS Code and desktop dependency audits report no known
  vulnerabilities. MkDocs builds in strict mode and its fixed requirements
  pass `pip-audit --strict`.
- Terraform: both Aliyun and Tencent roots pass formatting and validation with
  Terraform 1.16.1 and committed cross-platform provider lock files. No plan or
  apply has been run against a cloud account.
- iOS: a Swift package now contains the initial SwiftUI pairing client, Secure
  Enclave P-256 proof protocol and protocol tests. Swift/Xcode is unavailable
  on this Windows host, so compilation, signing and physical-device evidence
  remain open.

## Gates still required

- GitHub Actions must execute successfully after the account billing/spending restriction is resolved.
- Container build, SBOM, signature, provenance, SAST/SCA, license and IaC reports must be retained as CI artifacts.
- All production credentials potentially exposed before this audit must be rotated with evidence outside the repository.
- Six provider adapters require isolated-account contract tests before any production-ready status.
- Xiaomi 12S Ultra dual-SIM, permission revocation, delayed/duplicate OTP, background restriction, and manual fallback tests must pass.
- Windows installer signing/update verification, Ubuntu packaging, iOS
  compile/sign/device validation, isolated browser worker, and native browser
  bridge production validation remain open.
- Aliyun-to-Tencent recovery must demonstrate RPO at most 15 minutes and RTO at most 60 minutes.
