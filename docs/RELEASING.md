# Release Process (v4.8.0+)

> **Version**: applies to Secret Broker v4.8.0+
> **Last updated**: 2026-09-11

## How releases happen

A release is triggered by pushing a tag of the form `vX.Y.Z`:

```bash
git tag -s v4.8.0 -m "v4.8.0 — see CHANGELOG.md"
git push origin v4.8.0
```

The `.github/workflows/release.yml` workflow then:

1. Builds a multi-platform (linux/amd64) Docker image from the root
   `Dockerfile` (target: `production`).
2. Pushes the image to `ghcr.io/tyj1987/broker:vX.Y.Z` (and `latest` if
   on the default branch).
3. Generates two SBOM formats via `anchore/sbom-action`:
   - **SPDX JSON** — `broker.spdx.json` (Linux Foundation standard)
   - **CycloneDX JSON** — `broker.cyclonedx.json` (OWASP standard)
4. Signs the image digest with `cosign` using **keyless OIDC** tied to
   the GitHub Actions runner (no long-lived signing keys to manage).
5. Attaches the SPDX SBOM as a cosign attestation on the image.
6. Self-verifies the signature to ensure the workflow didn't produce
   an unverifiable artifact.
7. Creates a GitHub Release with both SBOMs as downloadable artifacts.

## Verifying a deployed image (operators)

To verify the image you pulled was signed by this workflow:

```bash
# Install cosign
go install github.com/sigstore/cosign/v2/cmd/cosign@latest

# Set environment variables
export IMAGE="ghcr.io/tyj1987/broker:v4.8.0"
export EXPECTED_DIGEST="sha256:..."  # from the release page

# Verify signature (matches GitHub Actions OIDC)
cosign verify \
  --certificate-identity-regexp 'https://github.com/tyj1987/broker' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --image "${IMAGE}@${EXPECTED_DIGEST}"

# Verify SBOM attestation
cosign verify-attestation \
  --type spdxjson \
  --certificate-identity-regexp 'https://github.com/tyj1987/broker' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${IMAGE}@${EXPECTED_DIGEST}"
```

A successful verification proves:

- The image digest was signed by the official `release.yml` workflow.
- The SBOM attached to it is the same one published in the GitHub Release.
- No human (or attacker) tampered with the artifact between the GitHub
  runner and your local `docker pull`.

## Manual / ad-hoc releases

If you need to release without pushing a tag (e.g., for an emergency
hotfix that bypasses the normal flow), use the **Run workflow** button
in GitHub Actions and supply a `tag` value. The workflow will:

1. Reuse the same build / sign / attest pipeline.
2. Push to GHCR under whatever tag you supplied.

## SBOM consumers

SBOMs are useful for:

- **Vulnerability scanning** — feed the CycloneDX file into Trivy,
  Grype, or `docker scout` to find CVEs in the production image.
- **License compliance** — the SPDX file lists every package license.
- **Supply chain attestation** — attach the SBOM to your own compliance
  evidence (SOC 2 CC7, ISO 27001 A.15).

## Pre-release checklist (release manager)

Before pushing the tag, ensure:

- [ ] All `vX.Y.Z` items in CHANGELOG.md are complete.
- [ ] `npm run test:verify-all` passes locally (Node + Python SDK).
- [ ] `mkdocs build --strict` passes (no broken doc links).
- [ ] `docker compose -f docker-compose.yml config` is valid.
- [ ] Helm template renders: `helm template deploy/helm/broker > /dev/null`.
- [ ] No pending `SECURITY.md` advisories (or they're disclosed).
- [ ] The CA private key on the build runner has not been used outside
      the official signing workflow.

## Why keyless OIDC?

Keyless OIDC ties each signature to a GitHub Actions identity (the
specific workflow run, the specific commit, the specific repository).
This is more secure than long-lived signing keys because:

- No secret key to leak, rotate, or revoke.
- Every signature is publicly auditable against the GitHub Actions logs.
- Sigstore's transparency log (Rekor) records each signature for
  independent verification.

The trade-off is that verification requires GitHub Actions to remain
a trusted identity issuer. If GitHub were compromised at the OIDC level,
signatures would still be valid but the identity claim would be false.
This is the standard tradeoff for keyless signing and is considered
acceptable for open-source projects.
