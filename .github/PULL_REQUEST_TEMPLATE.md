<!--
Thanks for contributing to Secret Broker!

Please complete the following checklist. For SDK changes, also see
SDK-REFERENCE.md V4.1.1 parity section. For V4.1.1 release, see
docs/RUNBOOK-v4.1.1.md.
-->

## Summary

> One-paragraph description of what this PR does and why. Reference the
> V4.1.1 SDK error contract if relevant (e.code, e.requestId, etc.).

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that changes existing behavior)
- [ ] Documentation / docs only
- [ ] Refactor (no functional change)
- [ ] Performance improvement
- [ ] Security fix
- [ ] SDK V4.1.1 parity (single BrokerError + parseBrokerError + retry)

## Affected area

### Broker

- [ ] `broker/` server
- [ ] `broker/lib/` helpers
- [ ] `broker/lib/audit.js`
- [ ] `broker/lib/session.js`
- [ ] `broker/lib/redact.js`
- [ ] `broker/lib/ssh.js` / WebSocket
- [ ] `broker/lib/rate-limit.js`
- [ ] `broker/lib/mfa-policy.js`
- [ ] `broker/lib/workload-identity.js`
- [ ] `broker/bin/`
- [ ] `broker-test/`

### SDKs (all 4 must stay in parity)

- [ ] `sdk/python/`
- [ ] `sdk/go/`
- [ ] `cli/` (Node CLI / mavis / Mavis)
- [ ] `sdk/vscode/` (Cursor / Windsurf / VSCodium)
- [ ] `sdk/python/examples/`
- [ ] `sdk/go/examples/`
- [ ] `cli/examples/`
- [ ] `sdk/vscode/examples/`

### Deployment

- [ ] `deploy/helm/`
- [ ] `deploy/terraform/`
- [ ] `deploy/packer/` (AWS AMI)
- [ ] `deploy/homebrew/`
- [ ] `deploy/apt/`
- [ ] `snap/`
- [ ] `winget/`

### Desktop / Mobile (V2 stretch)

- [ ] `desktop/` (Tauri 2.0)
- [ ] `sdk/ios/`
- [ ] `sdk/android/`

### Documentation

- [ ] `docs/SDK-REFERENCE.md`
- [ ] `docs/SDK-UPGRADE-GUIDE.md`
- [ ] `docs/ERROR-CODES.md`
- [ ] `docs/RUNBOOK-v4.1.1.md`
- [ ] `docs/ANNOUNCEMENT-TEMPLATES-v4.1.1.md`
- [ ] `ROADMAP-post-1.0.md`
- [ ] `CHANGELOG.md`
- [ ] `STATUS.md`
- [ ] `AWAITING-USER.md`
- [ ] `RELEASE-NOTES-*.md`
- [ ] `AGENTS.md` (broker project onboarding)
- [ ] `RUNBOOK.md` (general operations)
- [ ] `DEPLOY-52TRZ.md`

### CI / Tooling

- [ ] `.github/workflows/`
- [ ] `scripts/release/`
- [ ] `scripts/preflight-*.mjs`
- [ ] `scripts/dev/`

### Other

- [ ] Other (describe below)

## Test plan

- [ ] I added tests that prove my fix is effective or my feature works
- [ ] New and existing unit tests pass locally with my changes
  - Broker: `npm run test:verify-all`
  - Python SDK: `cd sdk/python && pytest tests/ -q`
  - Go SDK: `cd sdk/go && go test ./...`
  - Node CLI: `cd cli && node --test test-error.js`
  - VSCode SDK: `cd sdk/vscode && npm run build && node ./out/test/error.test.js`
- [ ] I have manually verified the change against a running broker
  (if applicable — see `VERIFY.md` for PKI + curl recipe)
- [ ] For SDK changes, all 4 SDKs updated in parity
- [ ] For SDK changes, examples/ updated to reflect new API

## SDK V4.1.1 parity checklist (if SDK change)

> All 4 SDKs (Python, Go, Node CLI, VSCode) must stay in parity.
> If you change one, change all 4 in the same release.

- [ ] `BrokerError` (or Go `BrokerError` struct) has consistent fields:
      `status`, `code`, `requestId`, `retryAfter`, `body`, `is_retryable`
- [ ] `BrokerConnectionError` (or equivalent) is separate class
- [ ] `parseBrokerError` (or `parse_broker_error` / `ParseBrokerError`)
      factory handles all body shapes (object error.code+message, string
      error, top-level message, etc.)
- [ ] Built-in retry: 5xx / 429 / connection → exponential backoff
- [ ] `Retry-After` header honored (overrides backoff)
- [ ] `toString()` / `toJSON()` / `to_map()` / `__repr__()` / `to_dict()`
      correct format
- [ ] `toJSON()` / `to_map()` omits `body` (security)
- [ ] Body auto-redacted on `BrokerError` construction
- [ ] User-Agent / version bumped to 4.1.1
- [ ] SDK `version` field in pyproject.toml / client.go / package.json
      / client.ts matches
- [ ] `docs/SDK-REFERENCE.md` §V4.1.1 parity table updated
- [ ] `docs/SDK-UPGRADE-GUIDE.md` migration section updated (if breaking)
- [ ] `docs/ERROR-CODES.md` updated (if new error codes)
- [ ] `cli/examples/v4.1.1-error-handling.mjs` and SDK equivalents
      demonstrate new pattern

## Zero-credential-leakage checklist (CRITICAL)

> The broker's core promise is that AI agents never see plaintext credentials.
> Every PR must verify this.

- [ ] My change does NOT add new code paths that return secret values to AI
- [ ] If my change adds a new log line, the value is passed through `redact()`
      (`broker/lib/redact.js` — 12 patterns) or marked explicitly safe
- [ ] If my change adds a new error message, the message is passed through
      `redact()` before returning to the client
- [ ] No new pattern of "leaking by exception" (e.g. printing env on crash)
- [ ] If I introduced a new credential format (e.g. a new cloud provider's
      API key), I added its pattern to `redact.js` AND a test case
- [ ] V4.1.1 SDK: `BrokerError.body` is auto-redacted on construction
      (verify with test)

## Security review

- [ ] No new mTLS bypass
- [ ] No new auth path that skips `clients[].is_admin` / scope check
- [ ] No new use of `eval`, `Function()`, or `child_process` without
      explicit shell-metacharacter sanitization
- [ ] No new hardcoded secret / key / token in source
- [ ] No new dependency that pulls in unmaintained or malicious code
      (`npm audit` clean / `pip-audit` clean / `govulncheck` clean)
- [ ] Cert-as-session audit trail writes `mfa_method: cert-bypass` entry
      (V4.1.1 fix)

## Backward compatibility

- [ ] This PR does not break V4.1.0 SDK users (REST API, secrets YAML schema,
      Python/Go/Node/VSCode SDKs)
- [ ] If it does, I bumped `broker/version.js` per semver
- [ ] Migration notes added to `CHANGELOG.md` under "Breaking" section
- [ ] `docs/SDK-UPGRADE-GUIDE.md` updated (if breaking SDK change)
- [ ] Old error classes (`BrokerAuthError` / `ErrAuth` etc.) still
      exported for one release (V4.1.1 → V4.2.0 deprecation window)

## Documentation

- [ ] I updated `CHANGELOG.md` under the next unreleased version
- [ ] I updated the relevant `docs/DESIGN-V4-*.md` if the design changed
- [ ] I updated `docs/SDK-REFERENCE.md` if SDK API changed
- [ ] I updated `docs/ERROR-CODES.md` if new error codes
- [ ] I updated `docs/RUNBOOK-v4.1.1.md` if release process changed
- [ ] I updated `VERIFY.md` if the verification steps changed
- [ ] I updated `docs/QUICKSTART.md` if the user flow changed
- [ ] I updated `AGENTS.md` (broker project onboarding) if project structure
      changed (new dirs, new files, etc.)
- [ ] I updated `ROADMAP-post-1.0.md` status table if item status changed

## Checklist for V4.x milestones (if relevant)

- [ ] V4.1.0 (GA — done 2026-09-01)
- [ ] V4.1.1 (patch — code complete 2026-09-06, awaiting release)
- [ ] V4.1.2 (Q1 2027 — community-reported bug fixes + auto-rotate cache)
- [ ] V4.2.0 (Q2 2027 — per-tenant rate limit + ABAC + secret versioning + approval)
- [ ] Marketplace self-service (Q2 2027)
- [ ] Mobile clients iOS + Android (Q1 2027)

## Reviewer focus

> What specific part of the code do you want reviewers to look at carefully?
> Examples: "the redact logic in alerts", "the SSH target parser regex",
> "the workload identity cache invalidation race", "the V4.1.1 SDK retry
> backoff curve".

## Screenshots / logs

> Paste terminal output, screenshots, or curl traces here. Use fenced
> code blocks. **Redact all secrets before pasting** — see the zero-leak
> checklist above.

## V4.1.1 release readiness (if relevant)

If this PR is part of the V4.1.1 release (currently 32 PRs in origin
per AWAITING-USER V13):

- [ ] `node scripts/preflight-v4.1.1.mjs --strict` returns 0 after merge
- [ ] `CHANGELOG.md` V4.1.1 section updated
- [ ] `RELEASE-NOTES-v4.1.1.md` updated
- [ ] `docs/SDK-REFERENCE.md` V4.1.1 section updated
- [ ] `docs/SDK-UPGRADE-GUIDE.md` migration section updated
- [ ] `docs/ERROR-CODES.md` registry updated
- [ ] `docs/RUNBOOK-v4.1.1.md` 8 步 manual accurate
- [ ] `STATUS.md` reflects V4.1.1 ready state
- [ ] `ROADMAP-post-1.0.md` P2 #9 marked done

## Related issues

> Use closing keywords: `Closes #123`, `Fixes #456`, `Refs #789`.

---

**Reference docs** (read before submitting):
- [AGENTS.md](../AGENTS.md) — broker project onboarding (for AI agents)
- [ROADMAP-post-1.0.md](../ROADMAP-post-1.0.md) — 13 items P0-P3 status
- [AWAITING-USER.md](../AWAITING-USER.md) — current user decisions (V13)
- [docs/RUNBOOK-v4.1.1.md](../docs/RUNBOOK-v4.1.1.md) — V4.1.1 release 8 步
- [docs/SDK-UPGRADE-GUIDE.md](../docs/SDK-UPGRADE-GUIDE.md) — V4.1.0 → V4.1.1
- [docs/ERROR-CODES.md](../docs/ERROR-CODES.md) — error code reference
