<!--
Thanks for contributing to Secret Broker!
-->

## Summary

> One-paragraph description of what this PR does and why.

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that changes existing behavior)
- [ ] Documentation / docs only
- [ ] Refactor (no functional change)
- [ ] Performance improvement
- [ ] Security fix

## Affected area

- [ ] `broker/` server
- [ ] `broker/lib/` helpers
- [ ] `broker/routes/` endpoints
- [ ] `broker/signing/` algorithms
- [ ] `sdk/python/`
- [ ] `sdk/go/`
- [ ] `sdk/vscode/`
- [ ] `deploy/helm/`
- [ ] `deploy/grafana/`
- [ ] `docs/`
- [ ] CI / GitHub Actions
- [ ] Other (describe below)

## Test plan

- [ ] I added tests that prove my fix is effective or my feature works
- [ ] New and existing unit tests pass locally
  - `cd broker && npm run test:verify-all`
- [ ] I have manually verified the change against a running broker
  - See `RUNBOOK.md` for the standard verification recipe

## Zero-credential-leakage checklist (CRITICAL)

> The broker's core promise is that AI agents never see plaintext credentials.
> Every PR must verify this.

- [ ] My change does NOT add new code paths that return secret values to AI
- [ ] If my change adds a new log line, the value is passed through `redact()`
      (`broker/lib/redact.js`) or marked explicitly safe
- [ ] If my change adds a new error message, the message is passed through
      `redact()` before returning to the client
- [ ] If I introduced a new credential format (e.g. a new cloud provider's
      API key), I added its pattern to `redact.js` AND a test case

## Security review

- [ ] No new mTLS bypass
- [ ] No new auth path that skips `clients[].role` / scope check
- [ ] No new use of `eval`, `Function()`, or `child_process` without
      explicit shell-metacharacter sanitization
- [ ] No new hardcoded secret / key / token in source
- [ ] No new dependency that pulls in unmaintained or malicious code
      (`npm audit` clean / `pip-audit` clean / `govulncheck` clean)

## Backward compatibility

- [ ] This PR does not break the v4.x API contract
- [ ] If it does, I bumped `broker/version.js` per semver
- [ ] Migration notes added to `CHANGELOG.md` under "Breaking" section

## Documentation

- [ ] I updated `CHANGELOG.md` under the next unreleased version
- [ ] I updated the relevant docs/ spec if the design changed
      (THREAT-MODEL.md, SSH-PROXY.md, etc.)
- [ ] I updated `RUNBOOK.md` if the verification steps changed
- [ ] I updated `docs/QUICKSTART.md` if the user flow changed

## Reviewer focus

> What specific part of the code do you want reviewers to look at carefully?
> Examples: "the redact logic in alerts", "the SSH target parser regex",
> "the workload identity cache invalidation race".

## Screenshots / logs

> Paste terminal output, screenshots, or curl traces here. Use fenced
> code blocks. **Redact all secrets before pasting** — see the zero-leak
> checklist above.

## Related issues

> Use closing keywords: `Closes #123`, `Fixes #456`, `Refs #789`.
