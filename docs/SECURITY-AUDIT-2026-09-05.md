# Secret Broker Security Audit — 2026-09-05

## Verdict

**NOT APPROVED FOR PRODUCTION.** Local controls were hardened and regression tests pass, but release gates remain open: production identity evidence, credential rotation, physical-key WebAuthn E2E, Go security-core migration, full route coverage, signed-build execution, provider contract tests and disaster-recovery evidence are unavailable or incomplete.


## Scope note (2026-09-06)

This document is a **desensitized historical snapshot** of the local audit at baseline `f3a7cc7` (plus then-uncommitted working-tree changes). It is **not** a claim that current `master` (including merged #16 / #17 and later) matches this baseline. Gaps vs current trunk—especially production identity P0 and SSH/audit-redact landings—should be tracked separately; do not treat this file as an up-to-date approval of today's deployed behavior.

## Evidence baseline

- Audited local commit: `f3a7cc7af4eef1425382f0fa63dd2c7e267c8565` plus working-tree changes.
- `origin/master` is behind local master by three commits; deployment must record the final commit, image digest and SHA-256 manifest.
- Sensitive untracked file `secrets/secrets-detail.json` was not opened. Treat all values referenced by prior documentation as compromised and rotate them.
- Production read-only probe on 2026-09-05 found the origin (`47.94.225.76:443`) healthy and one Cloudflare edge address (`172.67.152.223`) returning `/health` normally. Requests through `104.21.32.162` completed TLS but timed out before an HTTP response. This is partial edge-path degradation, not proof of production acceptance. No client certificate was available and no production mutation was attempted.

## Remediations implemented locally

- Added strict/controlled/compatibility security profiles and API-key scope enforcement.
- Added typed provider operations and outbound policy checks: HTTPS origin pinning, absolute-URL rejection, private/metadata IP blocking, redirect/header controls and response limits.
- Added method-aware service ACL checks.
- Required authorized mTLS sockets and constrained trusted proxy metadata to an enrolled proxy identity.
- Strict and controlled profiles now set `rejectUnauthorized:true`, so peers without a certificate chaining to the configured CA fail during the backend TLS handshake. Only the isolated compatibility profile permits application-layer fallback authentication.
- Hardened sessions (Secure/HttpOnly/SameSite=Strict, 15-minute inactivity, 12-hour absolute expiry).
- Removed browser session tokens from successful login response bodies; sessions are delivered only through the HttpOnly cookie.
- Added real WebAuthn registration/authentication verification with `@simplewebauthn/server`, one-time challenges, RP ID/origin binding, mandatory user verification, hardware-only single-device enforcement, attestation requirement, counter rollback detection and encrypted config persistence rollback.
- Added WebAuthn login/enrollment routes. Strict mode disables legacy session login and requires two enrolled hardware keys before WebAuthn login; enrollment requires fresh mTLS identity.
- Added five-minute, session-bound, one-use WebAuthn reauthentication grants and payload-bound two-person approval. The requester cannot self-approve; the second administrator must present a separate WebAuthn reauthentication grant. Replays, expiry, wrong sessions and payload changes fail closed.
- Connected approval enforcement to client creation, update, deletion, certificate rotation and revocation. Strict mode now forbids API responses that contain newly issued client private keys or downloadable private-key bundles.
- Extended the same payload-bound approval gate to secret creation/update/deletion and service creation/update/deletion. Strict-mode secret listings now preserve field names but replace every value with `[REDACTED]`.
- Dual control also verifies that requester and approver used different physical WebAuthn credential IDs, preventing two nominal accounts sharing one key from satisfying the control.
- Pinned every external GitHub Action to a verified 40-character commit SHA and added a CI policy verifier that rejects mutable tags. The previously referenced `aliyun-cli-action@v1.2.0` tag did not exist and was replaced by the verified official `v1` commit.
- Enforced lockfile-only Docker dependency installation and Node 24 CI, and added the security coverage and supply-chain policy jobs.
- Repaired an invalid SDK workflow YAML block. Added a reproducible VS Code lockfile and exact build dependencies; fixed reversed TLS-verification behavior and invalid HTTPS request options. VSIX packaging now excludes source/tests, preventing a test private key from entering the published artifact.
- Replaced the misleading cloud auto-deploy workflow with a fail-closed release-candidate workflow. It uses only the GitHub job token to push a commit-addressed GHCR image, requests SBOM and maximum provenance, signs the immutable digest with GitHub OIDC/Cosign, verifies the exact workflow identity, and archives commit/digest evidence. It deliberately performs no cloud deployment until short-lived cloud identities and digest-bound runtime rollout exist.
- Removed public security-group access to broker port 8443 in both clouds; only the nginx TLS edge on 443 remains public. Replaced cloud VM password provisioning with existing SSH key-pair names, made Helm production images digest-only, corrected Terraform CI directories, and added executable infrastructure policy checks.

## 2026-09-06 production smoke evidence

- Read-only smoke against `broker.52trz.com` and the recorded ECS origin `47.94.225.76` passed: 443 returned HTTP 200 with HSTS and no credential-shaped response; the origin TCP/8443 probe timed out (not publicly reachable).
- This evidence covers only the network boundary and public health response. It does not replace production image/digest attestation, credential rotation proof, FIDO2 hardware E2E, provider contract tests, or disaster-recovery rehearsal.
- Reduced the Aliyun broker runtime RAM role to read-only Describe operations; instance lifecycle, remote-command, EIP mutation and wildcard OSS data access were removed.
- Changed GitHub auth template to Bearer and updated provider manifests toward current operation formats.
- Made auto-rotation fail closed when encrypted persistence fails; removed plaintext fallback.
- Restricted compose backend binding to loopback and corrected the production Dockerfile entrypoint/SOPS stage.
- Unified the canonical `BROKER_*` runtime environment contract with the legacy installer names; Helm/Compose-mounted config, PKI, audit and health-socket paths are now actually consumed by the Node entrypoint, with invalid ports rejected before startup.
- Removed the concrete password value from `AGENTS.md`; a history scan still identifies commit `74e1cf8` as containing the old pattern, so credential rotation and repository-history remediation remain mandatory release gates.
- Added a complete-history gitleaks gate to the signed release workflow; publishing now stops before build/sign if repository history contains a detected secret.
- Added lockfile installation, full regression, security coverage, and supply-chain gates before the signed image build; the release workflow can no longer sign an untested candidate.
- Removed a false-positive CI smoke test that lacked a server certificate, key, encrypted configuration and age identity yet ignored startup/curl failure before printing success. CI now runs the complete regression suite, and policy checks reject unsigned release-URL executable downloads and ignored-failure smoke success markers.
- Replaced unauthenticated TLS health probes with a mode-0600 Unix-domain health socket under `/tmp`. Compose and Helm liveness/readiness probes use that local socket, while the network listener remains certificate-chain enforced; the socket exposes only health/live/ready routes.
- Pinned Node 24 Alpine, SOPS and distroless production build stages to registry-reported OCI index digests. Compose now requires the verified Broker digest at startup and pins the optional Prometheus/Grafana images; policy checks reject any unpinned Dockerfile base or Compose runtime image.
- Centralized trusted-proxy recognition and source-IP resolution. Forwarded IP metadata is used only when the TLS peer is authorized, arrives over loopback and matches an enrolled proxy fingerprint; direct callers cannot spoof API-key IP allowlists with `X-Forwarded-For`. Dedicated tests cover wrong fingerprints, unauthorized/remote proxies and header spoofing.
- Changed API-key resource grants to default deny: empty `allowed_secrets` or `allowed_services` no longer means unrestricted, and wildcard access must be explicit. Child grants are intersected with the parent; child TTL is capped, and child IP/quota constraints cannot relax the parent. Missing, malformed or expired timestamps fail closed, revoking/removing/expiring a parent immediately invalidates its children, and malformed/zero/missing rate limits deny use. API-key authorization is now included in the enforced security coverage gate.
- Removed the duplicate production session implementation and routed the monolith through the tested session store. Every session lookup re-resolves the current client; deletion, disablement, role downgrade and certificate fingerprint changes take effect immediately, and client update/delete/rotate/revoke clears every associated session. Client certificate material is deleted only after durable config revocation succeeds. Strict mode also blocks the certificate-rotation endpoint from returning private keys, and the dormant modular auth route now applies the same strict/controlled/compatibility login policy as the active route.
- Hardened compatibility MFA transactions: an mTLS-started challenge must finish with the same enrolled certificate, five failures lock the client across newly minted challenge tokens, and success clears the aggregate lock. Recovery codes are no longer removed only in memory; the selected hash is removed transactionally, persisted before session issuance, and restored if persistence fails. Verification now returns only the recovery-code index and does not mutate durable state itself.
- Added durable TOTP replay prevention for the compatibility profile. Successful verification returns the matched RFC 6238 counter; a counter at or below the last persisted value is rejected, and the new counter must be persisted transactionally before a session is issued. Persistence failure rolls the counter back and fails closed.
- Added an explicit typed-operation policy decision point. In strict mode every identity, including administrators, needs an `allowed_operations` grant scoped by service, operation ID, environment and resource; a control-plane role no longer implies data-plane access. Controlled/compatibility profiles retain a documented migration fallback to the legacy path ACL. API keys additionally require a `service:operation` grant, and child keys can only inherit the intersection of their parent's operation grants.
- Fixed service lifecycle handling that previously discarded `operations` supplied through the administration API. Operation catalogs are now normalized before persistence: methods, relative paths, query parameter names and scalar values, body limits, environment and resource bindings fail closed. Absolute/network-path URLs, embedded query/fragment data, nested query values and unknown executable fields are rejected. Typed operations also honor the service method allowlist.
- Fixed a provider implementation mismatch: `aliyun_v3` was executable but rejected by service administration, while `tencent_v3` had a unit-tested signer and advertised templates but no production `callUpstream` branch. Both types are now accepted by validated configuration, and Tencent TC3 requests use fixed operation-bound Action/Version/service/region metadata, structured or legacy credential references, signed Host/body/query data and optional temporary-token headers. The request shape was checked against Tencent Cloud's current common-parameter and CVM DescribeInstances documentation; a real isolated-account contract test remains required.
- Made credential health enforcement profile-aware and credential-source-aware. Static `token_secret`, `ak_secret` and legacy access-key references all pass through the same gate. Strict mode now denies missing references, missing health-check plumbing, absent results and stale evidence; dynamic IMDS/workload identities are validated during per-request credential acquisition instead of being mistaken for missing static secrets. Added the previously orphaned guard suite to the enforced security coverage run and repaired its machine-specific import path.
- Replaced the service-template administration stub with a safe executable skeleton feed and one-click form population. The UI now carries validated type, upstream, region, API version, service code, non-secret headers, typed operations and dashboard actions while never returning secret references or values. Templates without a wired typed adapter are disabled and every adapter defaults to `production_ready:false` until live contract evidence exists. The strict example configuration now validates cleanly and no longer enables administrator password login or implicit unrestricted proxying.

## Open release blockers

| ID | Severity | Finding | Required evidence/fix |
|---|---|---|---|
| SEC-001 | P1 | WebAuthn, short-lived reauthentication and dual approval are implemented and unit-tested, but a two-physical-key browser ceremony has not been run. | Run the browser E2E with two distinct hardware keys and archive the audit evidence. |
| SEC-002 | P1 | Production identity boundary and nginx proxy certificate are not verified live. | Deploy dedicated proxy cert, enroll fingerprint, restrict backend network path, run read-only mTLS/forgery tests. |
| SEC-003 | P1 | Node monolith remains the production security core; planned Go core is absent. | Complete Go core migration or obtain documented risk acceptance with compensating controls. |
| SEC-004 | P1 | Credential rotation has not been evidenced. | Rotate every potentially exposed secret/private key/recovery code and attach provider-side revocation evidence. |
| SEC-005 | P1 | Security-core c8 coverage and an operation authorization decision matrix now pass locally. The typed-operation data-plane executor has been extracted from the monolithic HTTP handler and is directly covered, but the remaining HTTP adapter/routes are not yet instrumented and the report has not been published by CI. | Continue extracting and testing security-sensitive route adapters, execute CI, and publish the c8 artifact; meet 90% core line/85% branch gates in the release job. |
| SEC-006 | P1 | GitHub Actions, Dockerfile bases and Compose runtime images are digest-pinned and lockfile gates are implemented, but the new SBOM/signing/provenance workflow has not executed and no deployed digest is verified. | Run the release workflow, verify SBOM/signature/provenance, then verify the deployed digest matches its evidence. |
| SEC-007 | P1 | Docker Registry V2 bearer exchange is now pinned, SSRF-checked and locally contract-tested; first-wave live provider contracts and Aliyun OIDC/STS/ActionTrail tests have not run with isolated accounts. | Execute GitHub, Docker, OpenAI, Aliyun, Tencent and Cloudflare contract matrix. |
| SEC-008 | P1 | Tencent disaster-recovery restore and RPO/RTO are unproven. | Execute restore drill; demonstrate RPO ≤15m and RTO ≤60m. |

## Local test evidence

`npm run test:verify` passes, including ACL, outbound-policy, security-profile, signing, workload, SSH, WebSocket and v4 module suites. These are regression tests only; they do not establish production acceptance or coverage thresholds.

`npm run coverage:security` now enforces a real c8 gate over API-key authorization, typed-operation authorization and execution, credential health gating, MFA transactions, sessions, outbound, trusted-proxy, local-health, security-profile, secret-view, WebAuthn, approval, read-only service-test policy, Aliyun V3, Tencent V3 and Docker Registry V2 signing modules. Current locally reproduced result (2026-09-06): 96.40% statements/lines, 85.61% branches and 96.77% functions. The command fails when line/statements/functions fall below 90% or branches below 85%. The remaining monolithic HTTP adapter coverage is not included yet and remains required before closing SEC-005.

Unavailable in this environment: Go, Helm, Terraform, gitleaks and a configured production mTLS client certificate. Dependency/SCA, container, IaC, SBOM, provenance and live provider tests therefore remain pending.

## Release decision

Do not deploy or label the project compliant until every P1 above is closed or explicitly accepted in writing with compensating controls. Keep strict profile enabled, keep compatibility endpoints isolated, and perform credential rotation before any further production testing.
