# Secret Broker Threat Model (2026-09-05)

## Trust boundaries

1. **Human administrator** uses a browser and phishing-resistant authenticator for control-plane changes.
2. **AI/CLI/CI workloads** are untrusted callers. They receive scoped short-lived workload identity and must never receive long-lived secret material.
3. **Nginx/edge proxy** is a separate workload identity. It terminates public traffic and forwards only authenticated, bounded requests to the broker loopback listener.
4. **Broker security core** is the policy enforcement point for identity, authorization, outbound destination, provider operation and audit events.
5. **Provider adapters** are isolated outbound clients with fixed manifests; provider credentials remain in KMS/Secrets Manager-backed memory.
6. **Audit storage** is append-only/independently protected. Logs are structured and redacted.

## Primary attack paths and controls

| Path | Threat | Required control | Local status |
|---|---|---|---|
| Public edge → broker | forged proxy identity or direct backend access | mTLS, loopback-only backend, trusted proxy certificate fingerprint and overwrite of identity headers | code/config hardened; production evidence pending |
| Workload → proxy | SSRF, header credential override, arbitrary method/path, operation/tenant/environment confusion | typed operation IDs, explicit service/operation/environment/resource grants, pinned HTTPS origin, destination/IP checks, denylisted caller headers, method ACL | implemented and unit-tested; production identity matrix pending |
| Workload → secrets | plaintext credential exfiltration | strict profile denies resolve and API-key identity; dynamic workload identity preferred | implemented; emergency human flow still requires integration |
| Browser → control plane | session theft/fixation and weak MFA | Secure/HttpOnly/Strict cookies, short absolute TTL, AAL3 hardware key and re-authentication | session hardening implemented; WebAuthn routes/AAL3 not wired |
| Rotation → storage | failed encryption or false-success rotation | fail-closed persistence and critical alert | implemented and tested |
| Build → production | mutable dependencies or unsigned artifact | lockfile, SAST/SCA, SBOM, signing/provenance, digest pinning | release pipeline evidence pending |

## Residual assumptions

- Production nginx, broker, image digest and cloud configuration must be collected read-only and compared with this repository.
- All potentially exposed passwords, API keys, private keys and recovery codes must be rotated before release.
- A passing local regression script is not evidence of coverage, production identity mapping or disaster recovery.
