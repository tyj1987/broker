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
- Android: CI run
  [`34293025716`](https://github.com/tyj1987/broker/actions/runs/34293025716)
  passed `testDebugUnitTest`, `assembleDebug` and `lintDebug` against Android API
  37 and Build Tools 36.0.0 and retained the debug APK as a digest-addressed
  artifact. Physical-device behavior remains unverified.
- Windows desktop: the same run passed the TypeScript build, formatting,
  Clippy with warnings denied, Rust tests, native-host release build, RustSec
  vulnerability gate and unsigned NSIS build. RustSec reported no
  vulnerabilities and seven transitive maintenance or soundness warnings,
  which remain registered risks rather than silently ignored findings.
- Browser helper: JavaScript syntax, least-privilege manifest tests, native-host compilation, and native-host unit tests passed locally. Browser-to-production end-to-end fill remains unaccepted.
- Isolated browser worker: typed input and output filtering, exact HTTPS-origin
  routing, disposable browser contexts, server-issued 60-second leases and
  signed device requests are unit-tested. Worker grants bind provider,
  operation, account and environment. A production launcher, hardware-backed
  workload signer, provider adapters, container egress enforcement and real
  account tests are not implemented, so this is not production-ready.
- Supply chain: Gitleaks 8.29.1 (official release checksum verified) reports no
  unallowlisted findings in either the complete Git history or the staged
  upgrade. Node broker, VS Code and desktop dependency audits report no known
  vulnerabilities. MkDocs builds in strict mode and its fixed requirements
  pass `pip-audit --strict`.
- Terraform: both Aliyun and Tencent roots pass formatting and validation with
  Terraform 1.16.1 and committed cross-platform provider lock files. No plan or
  apply has been run against a cloud account.
- Ubuntu desktop: CI built both unsigned Debian and AppImage packages after
  passing Rust formatting, Clippy, tests and dependency auditing.
- iOS: CI compiled and tested the Swift package containing the initial SwiftUI
  pairing client and Secure Enclave P-256 proof protocol. Signing and
  physical-device evidence remain open.

## GitHub Actions evidence

CI run [`34293025716`](https://github.com/tyj1987/broker/actions/runs/34293025716)
at commit `c101a3b45497e81a11d6e18409c097e46726452c` proved that all source,
contract, client, CodeQL, dependency, secret-history, IaC and deployment-script
jobs pass. Its container build completed, but the job failed while publishing
to GHCR because the token had insufficient package scope. The workflow now
restricts registry login, publication and registry-backed attestations to a
push on `master`; feature branches still build, inspect, scan and generate an
SBOM for the local candidate image.

CI run [`34296476883`](https://github.com/tyj1987/broker/actions/runs/34296476883)
at commit `ab1da42dc0fda9849976f60c995b050775b68d8b` completed successfully. It
validated all source and client jobs, rebuilt the pinned SOPS toolchain, checked
the non-root/read-only production runtime, passed the HIGH/CRITICAL container
vulnerability gate, and generated an SBOM. Registry publication and attestation
were correctly skipped on the feature branch and therefore remain release gates.

## Gates still required

- A separate `master` publication run must prove
  GHCR package permission and registry-backed attestations before release.
- Container build, SBOM, signature, provenance, SAST/SCA, license and IaC reports must be retained as CI artifacts.
- All production credentials potentially exposed before this audit must be rotated with evidence outside the repository.
- Six provider adapters require isolated-account contract tests before any production-ready status.
- Xiaomi 12S Ultra dual-SIM, permission revocation, delayed/duplicate OTP, background restriction, and manual fallback tests must pass.
- Windows installer signing/update verification, Ubuntu packaging, iOS
  compile/sign/device validation, isolated browser-worker production runtime,
  and native browser bridge production validation remain open.
- Aliyun-to-Tencent recovery must demonstrate RPO at most 15 minutes and RTO at most 60 minutes.
