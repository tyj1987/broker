# Contributing to Secret Broker

Thanks for your interest in making Secret Broker better! This document
covers how to file issues, submit code, and review changes.


> **Languages**: [English](CONTRIBUTING.md) · [中文](CONTRIBUTING.zh-CN.md)
## Code of conduct

This project follows the [Contributor Covenant](https://www.contributor-covenant.org/).
By participating, you agree to abide by its terms.

## Filing issues

### Bug reports

Use the **Bug Report** issue template. Include:

- broker version (`X-Broker-Version` header or `npm run --silent -p broker/version.js` style query)
- Node.js / Python / Go version (if using SDK)
- Minimal reproduction steps
- Expected vs actual behavior
- Relevant audit log excerpt (auto-redacted by the broker, but double-check)

### Security issues

**Do not file public GitHub issues for security vulnerabilities.**

Use [GitHub private vulnerability reporting](https://github.com/tyj1987/broker/security/advisories/new)
and follow [`SECURITY.md`](SECURITY.md). Do not include real credentials.

### Feature requests

Open a GitHub Discussion first (not an issue). If the maintainers agree
the feature is in scope, convert to an issue with the **Feature Request**
template.

## Submitting code

1. Fork the repo and create a feature branch from `master`.
2. Make your changes.
3. Run the module checks documented in [`VERIFY.md`](VERIFY.md). Do not quote
   a test count unless it comes from the current CI run.
4. Update `CHANGELOG.md` under the next unreleased version.
5. Submit a PR using the [PR template](.github/PULL_REQUEST_TEMPLATE.md).
   Make sure all checklist items are checked.

## Code style

- **JavaScript / TypeScript**: 2-space indent, `kebab-case` filenames,
  `camelCase` functions, ESM (`"type": "module"`).
- **Python**: PEP 8, 4-space indent, `snake_case`. Type hints required for
  public API.
- **Go**: `gofmt` + `go vet` clean. Standard `golangci-lint` rules.
- **YAML / JSON**: 2-space indent. No trailing whitespace.

## Architecture principles

These are not negotiable:

1. **Zero credential leakage**: every code path that touches a secret must
   pass through `broker/lib/redact.js` (or the SDK's equivalent) before
   logging, error-reporting, or returning to the caller. See the
   [redact engine tests](broker-test/test-redact.js) for the 12 patterns
   currently supported.
2. **Authenticated operations**: no anonymous operation endpoints. The single exception is
   `GET /health`, which returns only `{ "status": "ok" }`. Do not put
   `version`, `sops_loaded`, service names or `uptime_seconds` on the
   public health body.
3. **No new hard dependencies for SDKs**: Python and Go SDKs must remain
   stdlib-only. Node SDK may add `ws` (already there). New deps require
   maintainer approval.
4. **Backward compatibility**: v3.8 clients must keep working. Breaking
   changes bump `broker/version.js` and add a `Breaking` section to
   `CHANGELOG.md`.

## Testing

- Unit tests live next to the source (`broker/lib/`, `sdk/python/secret_broker/`,
  `sdk/go/broker/`).
- Integration tests live in `broker-test/` and use stdlib mocks.
- Performance-sensitive paths have benchmark tests (see `bench/` if
  present; PRs that regress by > 10% need justification).
- Node changes must pass `npm run test:coverage`; the full language, client,
  infrastructure, supply-chain and artifact matrix must pass in CI before merge.

## Release process

1. A maintainer selects an exact commit after all required checks pass.
2. CI runs the repository's declared Node 24, Go, Python, Android, iOS, browser,
   Windows desktop, Terraform and security jobs.
3. CI builds the candidate image by immutable digest and retains SBOM and
   provenance evidence.
4. The protected production environment requires human approval and deploys
   only the successful `master` commit. Tags and release notes are created only
   after the corresponding release procedure is approved.

## Reviewing PRs

Maintainers will review within 7 days. Focus areas:

- **Security impact**: does the change touch any auth path, secret value
  path, or new external input?
- **Backward compatibility**: does the v3.8 client still work?
- **Test coverage**: are there unit tests for the new logic? Are edge
  cases (empty, oversized, malformed) covered?
- **Documentation**: is `CHANGELOG.md` updated? Are any new env vars or
  config knobs documented in `secrets/broker.yaml.example`?
- **Style**: do the diffs match the conventions above?

## Community

- GitHub Discussions: design questions, RFCs
- Discord `#broker`: real-time chat
- Office hours: by appointment (DM a maintainer on Discord)
- Email: broker@local for non-security private matters

## License

By contributing, you agree that your contributions will be licensed
under the [MIT License](LICENSE).
