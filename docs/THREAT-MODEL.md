# Secret Broker Threat Model (2026-09-09, v4.2.0)

## Trust boundaries

1. **Human administrator** uses a browser and phishing-resistant authenticator for control-plane changes.
2. **AI/CLI/CI workloads** are untrusted callers. They receive scoped short-lived workload identity and must never receive long-lived secret material.
3. **Nginx/edge proxy** is a separate workload identity. It terminates public traffic and forwards only authenticated, bounded requests to the broker loopback listener.
4. **Broker security core** is the policy enforcement point for identity, authorization, outbound destination, provider operation and audit events.
5. **Provider adapters** must become isolated outbound clients with fixed manifests; this is a release gate, not a property of the current Node compatibility layer.
6. **Audit storage** must be independently protected and immutable. Current structured, redacted local logs do not yet satisfy that production boundary.

## Primary attack paths and controls

| Path | Threat | Required control | Local status |
|---|---|---|---|
| Public edge → broker | forged proxy identity or direct backend access | mTLS, loopback-only backend, trusted proxy certificate fingerprint and overwrite of identity headers | code/config hardened; production evidence pending |
| Workload → proxy | SSRF, header credential override, arbitrary method/path, operation/tenant/environment confusion | typed operation IDs, explicit service/operation/environment/resource grants, pinned HTTPS origin, destination/IP checks, denylisted caller headers, method ACL | implemented and unit-tested; production identity matrix pending |
| Workload → secrets | plaintext credential exfiltration | strict profile denies resolve and long-lived master keys; dynamic workload identity or constrained short-lived operation keys preferred | typed-operation boundary implemented; emergency human flow and production KMS integration remain open |
| Browser → control plane | session theft/fixation and weak MFA | Secure/HttpOnly/Strict cookies, short absolute TTL, AAL3 hardware key and re-authentication | session and WebAuthn routes implemented and tested; two-key production enrollment and ceremony acceptance pending |
| Rotation → storage | failed encryption or false-success rotation | fail-closed persistence and critical alert | implemented and tested |
| Build → production | mutable dependencies or unsigned artifact | lockfile, SAST/SCA, SBOM, signing/provenance, digest pinning | release pipeline evidence pending |
| Broker → isolated browser worker | task theft, replay, cross-account/environment execution, or credential/result leakage | strict-admin WebAuthn enrollment with two independent approvers, signed nonce-bound requests, short one-time leases, exact workload capability, typed parameters and nested result filtering | protocol and unit tests implemented; physical-key ceremony, hardware-backed workload identity, runtime isolation and real adapters pending |
| Broker → tool adapter | capability replay, actor/target/environment substitution, duplicate concurrent execution | opaque digest-only execution tokens bound to actor, exact tool version, target, environment, request fingerprint and nonce; 60-second maximum TTL, one-time consumption, revocation tombstone and per-task execution lock | local adapter protocol and attack tests implemented; durable multi-node token state remains pending |

## Residual assumptions

- Production nginx, broker, image digest and cloud configuration must be collected read-only and compared with this repository.
- All potentially exposed passwords, API keys, private keys and recovery codes must be rotated before release.
- A passing local regression script is not evidence of coverage, production identity mapping or disaster recovery.
