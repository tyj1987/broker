# Production acceptance record

This document records observed evidence separately from planned controls. Passing source tests does not approve a production release.

## Source and time policy enforcement

Typed operations now enforce optional IPv4/IPv6 CIDR and absolute RFC 3339
time-window conditions in the Node transition layer and independently in the
Go policy core. The core wire contract carries the original trusted-proxy
source address and exact policy bounds; missing or malformed inputs fail
closed. Go policy tests cover native IPv4, IPv4-mapped IPv6, IPv6, outside
networks, invalid rules, boundary time and inverted windows. This is source and
automated-test evidence only; it does not close the live nginx trust-boundary
findings below.

## Baseline

- Source baseline: `master@450c3ed2e1ffafb6507b908fc5b94a980c9820b0`
- Upgrade branch: `codex/platform-upgrade`
- Production read-only observation date: 2026-09-09 (Asia/Singapore)
- Production DNS observed: `broker.52trz.com` resolved to `47.94.225.76`
- Public `/health`: HTTP 200 with the minimal body `{"status":"ok"}`

No credential values, private keys, environment files, or secret configuration were read during this observation.

## Production read-only revalidation

The host was rechecked on 2026-09-09 through the IP identity already present in
the operator's `known_hosts`. The DNS name itself had no saved ED25519 host-key
entry and was therefore rejected under strict checking; no key was learned
from the live connection.

- Git blob hashes for the deployed `server.js`, `package.json`, and
  `package-lock.json` exactly match `master@450c3ed2e1ffafb6507b908fc5b94a980c9820b0`.
  They do not match the upgrade branch. The deployed `server.js` SHA-256 is
  `bd09f039c40d10049b2fbb8106ab7d74fe93ccc6ee24b7652920f712a628a4d1`.
- `secret-broker.service` is active as `root`; `secret-broker-policy.service`
  is inactive. `/opt/secret-broker/broker` is a directory owned by
  `mysql:mysql`, not a release symlink, and no deployed-release record exists.
- nginx listens publicly on `443`; Broker listens only on
  `127.0.0.1:8443`. Nothing listens on the expected loopback health port
  `9080`.
- nginx presents a dedicated upstream workload certificate with
  `CN=client.nginx-bridge`, but the effective configuration still contains
  `proxy_ssl_verify off`. A dedicated certificate name therefore does not
  close the server-authentication failure.
- The active CA private key, an older CA private-key backup, and multiple
  final-client private keys are co-located under the production application
  tree. The deployed configuration has no `trusted_proxy_fingerprints` entry.
  The complete trust domain must therefore be treated as potentially
  compromised and replaced; rotating only the nginx certificate is
  insufficient.
- Active nginx is version 1.20.1. The loopback `8443` health endpoint returns
  only `{"status":"ok"}`.

This was metadata-only verification. Certificate private keys, Broker secrets,
environment files and credential values were not opened or printed.

## Production blockers observed

| Severity | Evidence | Required remediation |
|---|---|---|
| P0 | Effective nginx configuration uses `proxy_ssl_verify off` for Broker upstream locations. | Enable CA and hostname verification, deploy the dedicated nginx workload certificate, and regression-test forged headers and direct backend access. |
| P0 | CA private keys and multiple final-client private keys are stored together on the Broker host, including an old CA backup; the deployed config has no trusted-proxy fingerprint allowlist. | Replace the full CA hierarchy through an offline ceremony, re-enroll every client, revoke the old trust domain, remove all CA/client private keys from the host, and verify old identities are rejected. |
| P0 | Production still runs the pre-upgrade `master@450c3ed` Node boundary while the Go policy service is inactive. Current branch security fixes and decision enforcement are not deployed. | Complete staging and credential-rotation gates, then deploy one digest-addressed release with the Go policy service required and verify fail-closed behavior. |
| P1 | `secret-broker.service` runs as `root`. | Run under a dedicated locked system account with only the required writable paths. |
| P1 | `/opt/secret-broker/broker` is an unmanaged directory owned by `mysql:mysql`; it is not a release symlink and no `deployed-release` baseline is present. | Perform a reviewed one-time migration to root-managed versioned releases before enabling atomic CI deployment. |
| P1 | nginx 1.20.1 is the active production version. | Move to a vendor-supported security-maintained release and record the package provenance. |
| P2 | Broker listens only on `127.0.0.1:8443`, which prevents direct public access, but it has no separate observed `9080` health listener in the live configuration. | Deploy and verify the loopback-only health listener used by the hardened workflow. |

Production remains **not approved**. No deployment was attempted because P0/P1 gates, repository CI, credential rotation evidence, signed artifacts, provider contract tests, Android physical-device tests, and disaster-recovery rehearsal are incomplete.

## Local evidence obtained on the upgrade branch

- The management console now exposes a bound approval workbench. Decisions
  require an exact same-origin request from a WebAuthn-authenticated browser
  session; missing or cross-site Origin, API-key identity, unknown decision
  fields and non-WebAuthn sessions fail closed before mutation. Desktop and
  Android clients only open the fixed `/approvals` entrypoint in the system
  browser and never receive its session or approval authority. Source, Node
  regression and Windows Tauri build/Clippy/test evidence has been obtained;
  Android CI and end-to-end physical-key ceremony remain open.
- Node broker full regression suite: passed. The security-core coverage gate
  reports 96.91% lines, 89.88% branches and 97.35% functions. Approval creation
  is pre-authorized by the same Node and Go policy path, and v2 state changes
  require a durable audit intent before mutation.
- Production audit writes now enter restart-safe `audit-chain-*` files. Startup
  strictly verifies the retained chain and refuses malformed or modified
  records; tests cover restart continuation, malformed input and tampering.
  Legacy unsealed logs remain outside the migration genesis, and the missing
  independent signed chain-head anchor remains a P1 acceptance blocker.
- The GitHub repository-read adapter has a fixed origin, method, API version,
  response limit and projection. The App token provider produces an RS256 JWT
  only through an injected signer capability, requests exactly one repository
  with Metadata read, and verifies the returned repository, permission and
  expiry. The HTTPS transport validates all DNS answers, pins the connection,
  keeps TLS hostname verification enabled, denies redirects and bounds body,
  response and time. The composed executor is integration-tested without a
  private key. No production KMS/HSM signer, account binding or isolated-account
  live contract has run, so the manifest remains `contract_required` and this
  is not production-available evidence.
- The Cloudflare zones-list adapter binds the execution, credential and API
  query to one exact account ID, accepts only bounded filters and pagination,
  and returns a minimal zone projection. The composed executor uses the pinned
  HTTPS transport. Unit and integration coverage is 100% line/function and
  96.77% branch. No production token resolver or isolated-account contract has
  run, so Cloudflare also remains `contract_required`.
- The strict SSH host-inspection adapter accepts one opaque target reference,
  validates execution-token target and environment binding, and delegates to an
  injected runner without accepting a command or credential. It projects only
  bounded health fields and rejects wrong-target, malformed or unexpected
  runner output without exposing runner errors. Its integration test crosses
  the automation task policy, schema, single-use grant, execution, result and
  audit lifecycle and rejects replay and command injection before the runner.
  The production target registry,
  verified host-key authority, short-lived certificate signer, isolated runner
  and target contract test remain open, so SSH is `contract_required`.
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
- Android physical-device partial evidence on 2026-09-09: the debug APK was
  built locally and installed without replacing app data on a Xiaomi 12S Ultra
  (`2203121C`) running Android 15 / API 35 and HyperOS
  `OS3.0.6.0.VLACNXM`. Both SIM slots reported loaded in DSDS mode. The app
  reported hardware-backed P-256 signing, available Google SMS User Consent,
  no Android background restriction, and active battery optimization. Its
  fixed approval entrypoint opened Chrome at the exact
  `https://broker.52trz.com/approvals` URL. `RECEIVE_SMS` remained denied while
  the system permission dialog awaited the operator, and no real SMS delivery
  or OTP consumption was attempted. This is capability evidence, not full
  device acceptance.
- Android dual-SIM binding no longer has a disconnected code path: after local
  pairing the receiver records only delivery subscription/slot metadata, the
  operator explicitly binds that observed SIM to an opaque task binding, and a
  subscription change in a slot clears the old binding. The SMS body and OTP
  are never persisted. This change still requires CI and Xiaomi hardware
  evidence before acceptance. CI run
  [`34299709185`](https://github.com/tyj1987/broker/actions/runs/34299709185)
  passed the complete workflow at `e63213d9e8dece7c5c9b761a10cb35a9aca2a541`,
  including Android unit tests, lint and debug APK assembly.
- A paired Android device can submit a signed, replay-protected empty request
  to suspend itself. The server persists the downgrade, cancels pending OTP
  work, clears in-memory browser claims, and rejects a late result from an OTP
  consumer that was already in flight. Reactivation requires the existing
  administrator WebAuthn plus two-person flow. The app retains the suspended
  state across restarts and only clears it after a signed Broker check
  succeeds. Physical-device behavior remains unverified.
- Child API keys now receive an absolute expiration no later than their parent
  rather than deriving a relative second count from two clock reads. The
  millisecond boundary regression passed 20 consecutive local runs.
- Windows desktop: the same run passed the TypeScript build, formatting,
  Clippy with warnings denied, Rust tests, native-host release build, RustSec
  vulnerability gate and unsigned NSIS build. RustSec reported no
  vulnerabilities and seven transitive maintenance or soundness warnings,
  which remain registered risks rather than silently ignored findings.
- Browser helper: JavaScript syntax, least-privilege manifest tests, native-host compilation, and native-host unit tests passed locally. Browser-to-production end-to-end fill remains unaccepted.
- Isolated browser worker: typed input and output filtering, exact HTTPS-origin
  routing, disposable browser contexts, server-issued 60-second leases and
  signed device requests are unit-tested. OTP claims are single-use, are
  cancelled with the operation lifetime, and cannot be retried after an
  uncertain exchange. Suspending a worker invalidates its active leases and
  prevents late completion. Worker grants bind provider, operation, account
  and environment. A production launcher, hardware-backed workload signer,
  provider adapters, container egress enforcement and real account tests are
  not implemented, so this is not production-ready.
- Device enrollment and state changes now require a strict administrator with
  WebAuthn step-up plus a request-bound approval from two other administrators.
  This is source and unit-test evidence only; the three-operator ceremony has
  not been exercised with physical security keys.
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

CI run [`34300658196`](https://github.com/tyj1987/broker/actions/runs/34300658196)
at commit `36bc25b27f82b5e55345501c96dc8b03c7aa3078` completed successfully.
It independently validated the Node and Go source/time policy enforcement,
all client builds, CodeQL, dependency and secret-history scans, IaC checks,
the production candidate image, SBOM generation and deployment-script tests.

CI run [`34301716336`](https://github.com/tyj1987/broker/actions/runs/34301716336)
at commit `d6271af21f95211f4c1f443628fa572034e0a35e` completed successfully.
All 22 jobs passed, including the Android self-suspension path, exact child-key
expiration boundary, Windows and Ubuntu desktop packages, iOS, CodeQL,
secret-history scanning and production candidate image validation.

## Gates still required

- A separate `master` publication run must prove
  GHCR package permission and registry-backed attestations before release.
- Container build, SBOM, signature, provenance, SAST/SCA, license and IaC reports must be retained as CI artifacts.
- All production credentials potentially exposed before this audit must be rotated with evidence outside the repository.
- Seven provider adapters require isolated-account or isolated-target contract tests before any production-ready status.
- Xiaomi 12S Ultra dual-SIM, permission revocation, delayed/duplicate OTP, background restriction, and manual fallback tests must pass.
- Windows installer signing/update verification, Ubuntu packaging, iOS
  compile/sign/device validation, isolated browser-worker production runtime,
  and native browser bridge production validation remain open.
- Aliyun-to-Tencent recovery must demonstrate RPO at most 15 minutes and RTO at most 60 minutes.
