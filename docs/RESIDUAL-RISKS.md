# Residual risk register

This register separates verified source controls from evidence that still
requires a production account, signed release, physical device, or recovery
exercise. An open item is not evidence of acceptance.

| ID | Severity | Risk and current control | Closure evidence |
|---|---|---|---|
| RR-001 | P0 | Production nginx uses a dedicated `client.nginx-bridge` workload certificate but still has upstream server-certificate verification disabled. The hardened repository configuration fails closed, but the live host is unchanged. | Reviewed proxy workload certificate rollout, `proxy_ssl_verify on`, forged-header regression, direct-backend denial and rollback evidence. |
| RR-002 | P1 | Production runs the pre-upgrade source as root, its Go policy service is inactive, and its unmanaged application directory is owned by `mysql:mysql` rather than being an atomic release symlink. | Dedicated locked accounts, required Go policy service, versioned release migration, read-only filesystem checks and rollback exercise. |
| RR-003 | P1 | Existing production credentials have no completed rotation evidence following possible historical exposure. | Provider-side revocation timestamps and replacement identifiers stored outside the repository. |
| RR-004 | P1 | Source policy now requires a strict-admin WebAuthn session and two independent approvers for device enrollment and state changes. The approval workbench rejects cross-origin mutations and desktop/mobile clients cannot decide with device credentials, but strict AAL3 still requires two physical FIDO2 keys and no complete operator ceremony has been recorded. | Two-key enrollment, two-person registration/revocation, loss/revocation, challenge replay, RP ID/origin, cross-site request and step-up tests on staging. |
| RR-005 | P1 | The typed isolated-browser boundary and signed, single-use worker lease protocol are implemented and unit-tested. OTP exchange cancellation and device suspension invalidate late completion, but no production launcher, non-exportable workload signer, provider login adapter, container egress policy or real provider-account contract test exists. Typed operations and manifests remain contract-gated. | Workload identity and isolation escape tests plus successful least-privilege contracts for GitHub, Docker, OpenAI, Aliyun, Tencent Cloud and Cloudflare. |
| RR-006 | P1 | Android fails closed on missing SIM metadata, requires explicit binding of an observed subscription, invalidates a prior binding when a slot changes, and can self-suspend without gaining reactivation authority. Suspension now revokes waiting, received and consuming OTP state so an in-flight result cannot commit. Restricted SMS permission, real dual-SIM delivery and OEM background behavior remain unknown. | Xiaomi 12S Ultra dual-SIM matrix including denial, self-suspension/reactivation, revocation, delayed/duplicate OTP, SIM change, offline expiry and manual fallback. |
| RR-007 | P2 | Desktop packages and the Android APK are unsigned development artifacts. | Windows code signing and update verification, Linux package provenance, Android release signing and iOS signing/device validation. |
| RR-008 | P2 | RustSec reports seven transitive warnings: six unmaintained `unic`/macro crates and one `glib 0.18.5` soundness advisory. No known vulnerability was reported. | Dependency upgrade/removal, or written risk acceptance proving the affected code path is unreachable with compensating controls. |
| RR-009 | P1 | GHCR publication and registry-backed attestations have not succeeded with the repository package permissions. | Successful `master`-only image publication, digest verification, SBOM, vulnerability scan and registry attestation. |
| RR-010 | P1 | Aliyun-to-Tencent recovery targets are design values only. | Timed recovery with encrypted backup restore, revocation state, continuous audit evidence, RPO at most 15 minutes and RTO at most 60 minutes. |

P0 and P1 entries block production approval. P2 entries require remediation or
explicit written acceptance with a named owner, expiry date and compensating
control.
