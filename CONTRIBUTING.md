# Contributing to Secret Broker

Thanks for your interest in making Secret Broker better! This document
covers how to file issues, submit code, and review changes.

**V4.1.1 SDK parity note** (added 2026-09-06): all 4 official SDKs
(Python, Go, Node CLI, VSCode) now share a unified error contract
(`BrokerError` + `parseBrokerError` + built-in retry). If you change
one SDK, change all 4 in the same release. See
[SDK-REFERENCE.md §V4.1.1](docs/SDK-REFERENCE.md#v411-sdk-parity) and
[SDK-UPGRADE-GUIDE.md](docs/SDK-UPGRADE-GUIDE.md) for details.

## Code of conduct

This project follows the [Contributor Covenant](https://www.contributor-covenant.org/).
By participating, you agree to abide by its terms.

## Filing issues

### Bug reports

Use the **Bug Report** issue template. Include:

- broker version (`X-Broker-Version` header or `broker/version.js`)
- Node.js / Python / Go version (if using SDK)
- 4-SDK version (Python `secret_broker.__version__` / Go `broker.Version` /
  Node CLI `version` / VSCode `package.json#version`)
- Minimal reproduction steps
- Expected vs actual behavior
- Relevant audit log excerpt (auto-redacted by the broker, but double-check)
- For SDK errors: include `e.status`, `e.code`, `e.requestId` (V4.1.1+
  `BrokerError` fields; see [ERROR-CODES.md](docs/ERROR-CODES.md))

### Security issues

**Do not file public GitHub issues for security vulnerabilities.**

See [`SECURITY.md`](SECURITY.md) and the **Bug Bounty** section.
V4.1.1 security notes: see [SECURITY.md §V4.1.1 Security Notes](SECURITY.md#v411-security-notes-2026-09-06).
Email: **security@broker.example.com** (PGP key in `.well-known/pgp-key.asc`).

### Feature requests

Open a GitHub Discussion first (not an issue). If the maintainers agree
the feature is in scope, convert to an issue with the **Feature Request**
template.

## Submitting code

1. Fork the repo and create a feature branch from `master`.
2. Make your changes.
3. **Verify all 4 SDKs** if your change touches SDK code (V4.1.1 parity):
   - Broker: `npm run test:verify-all` (629 tests)
   - Python SDK: `cd sdk/python && pytest tests/ -q` (54 tests)
   - Go SDK: `cd sdk/go && go test ./...` (33 + 1 SKIP)
   - Node CLI: `cd cli && node --test test-error.js` (21 tests)
   - VSCode SDK: `cd sdk/vscode && npm install && npm run build && node ./out/test/error.test.js` (38 tests)
4. **Verify V4.1.1 release readiness** if your change is part of V4.1.1:
   - `node scripts/preflight-v4.1.1.mjs --strict`
   - `node scripts/verify-sdk-v4.1.1-parity.mjs --strict`
   - Or: `node scripts/verify-v4.1.1-release.mjs --strict` (combined runner)
5. Update `CHANGELOG.md` under the next unreleased version.
6. Update [SDK-REFERENCE.md](docs/SDK-REFERENCE.md) if SDK API changed.
7. Update [ERROR-CODES.md](docs/ERROR-CODES.md) if new broker error codes.
8. Submit a PR using the [PR template](.github/PULL_REQUEST_TEMPLATE.md).
   Make sure all checklist items are checked, especially the
   **SDK V4.1.1 parity checklist** (14 items).

## Code style

See [.editorconfig](.editorconfig) for cross-editor defaults.
Per-language:

- **JavaScript / TypeScript**: 2-space indent, `kebab-case` filenames,
  `camelCase` functions, ESM (`"type": "module"`).
- **Python**: PEP 8, 4-space indent, `snake_case`. Type hints required
  for public API. Black-compatible (max 100 chars/line).
- **Go**: `gofmt` + `go vet` clean. Standard `golangci-lint` rules. Tab
  indent.
- **YAML / JSON**: 2-space indent. No trailing whitespace.
- **Markdown**: 2-space indent for lists. Preserve 2-trailing-space
  for line breaks.

## Architecture principles

These are not negotiable:

1. **Zero credential leakage**: every code path that touches a secret must
   pass through `broker/lib/redact.js` (or the SDK's equivalent) before
   logging, error-reporting, or returning to the caller. See the
   [redact engine tests](broker-test/test-redact.js) for the 12 patterns
   currently supported. V4.1.1 SDKs auto-redact body on `BrokerError`
   construction.
2. **mTLS-only**: no anonymous endpoints. The single exception is
   `GET /health`, which returns only `{ok, version}`.
3. **No new hard dependencies for SDKs**: Python and Go SDKs must remain
   stdlib-only. Node SDK may add `ws` (already there). New deps require
   maintainer approval.
4. **Backward compatibility**: v3.8 clients AND V4.1.0 SDK users must
   keep working. Breaking changes bump `broker/version.js` and add a
   `Breaking` section to `CHANGELOG.md`. V4.1.1 SDKs maintain backward
   compat with V4.1.0 SDK code (V4.1.0's 6 typed classes still
   exported for one release, emit `DeprecationWarning`).
5. **4-SDK parity (V4.1.1+)**: all 4 official SDKs (Python, Go, Node CLI,
   VSCode) must expose the same `BrokerError` contract. If you change
   one SDK, change all 4. CI verifies parity via
   `node scripts/verify-sdk-v4.1.1-parity.mjs --strict`.

## Testing

- Unit tests live next to the source (`broker/lib/`, `sdk/python/secret_broker/`,
  `sdk/go/broker/`).
- Integration tests live in `broker-test/` and use stdlib mocks.
- Performance-sensitive paths have benchmark tests (see `bench/` if
  present; PRs that regress by > 10% need justification).
- All PRs must pass:
  - Broker: `npm run test:verify-all` (629 tests)
  - 4 SDKs: see "Submitting code" step 3.
- Total V4.1.1: **795 tests** (was 658 in V4.1.0).

## Release process (V4.1.1, 9 steps)

See [docs/RUNBOOK-v4.1.1.md](docs/RUNBOOK-v4.1.1.md) for full details:

1. Maintainer cuts a release branch `release/vX.Y.Z`.
2. CI runs full matrix (Linux / macOS / Windows × Node 20 / 22).
3. Tag is `git tag -a vX.Y.Z -m "..." && git push origin vX.Y.Z`.
4. `bash scripts/release/vX.Y.Z.sh` (build 8 assets + SHA-256 + MANIFEST).
5. `bash scripts/release/vX.Y.Z.sh --upload --publish` (GitHub Release).
6. Smoke: `curl -k --cert pki/clients/admin.crt --key pki/clients/admin.key https://broker:8443/health`.
7. (Optional) `ssh broker.52trz.com "cd /opt/secret-broker && git checkout vX.Y.Z && npm install --omit=dev && systemctl restart secret-broker"`.
8. Announce via [ANNOUNCEMENT-TEMPLATES-vX.Y.Z.md](docs/ANNOUNCEMENT-TEMPLATES-v4.1.1.md)
   (10 platform templates).
9. Update AWAITING-USER.md to mark sections as merged.

## Reviewing PRs

Maintainers will review within 7 days. Focus areas:

- **Security impact**: does the change touch any auth path, secret value
  path, or new external input?
- **4-SDK parity (V4.1.1+)**: if PR touches one SDK, do all 4 SDKs update
  in the same release? Are tests updated in all 4?
- **Backward compatibility**: does the V4.1.0 SDK user still work?
  Does the v3.8 client still work?
- **Test coverage**: are there unit tests for the new logic? Are edge
  cases (empty, oversized, malformed) covered?
- **Documentation**: is `CHANGELOG.md` updated? Is
  [SDK-REFERENCE.md](docs/SDK-REFERENCE.md) updated? Is
  [ERROR-CODES.md](docs/ERROR-CODES.md) updated (if new error codes)?
- **Style**: do the diffs match the conventions above? Does the
  .editorconfig apply?

## Community

- GitHub Discussions: design questions, RFCs
- Discord `#broker`: real-time chat
- Office hours: by appointment (DM a maintainer on Discord)
- Email: broker@local for non-security private matters

## License

By contributing, you agree that your contributions will be licensed
under the [MIT License](LICENSE).

---

**Document version**: 2026-09-06 (V4.1.1 release prep)
**Applies to**: V4.1.1 and later
**Last updated**: session 17 (V4.1.1 + 4-SDK parity, 24 commit)
