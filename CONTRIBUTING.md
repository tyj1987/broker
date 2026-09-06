# Contributing to Secret Broker

Thanks for your interest in making Secret Broker better! 🎉

This document covers how to file issues, submit code, write tests, add
service templates, contribute to SDKs, and review changes for Secret
Broker **V4.1+**.

If you only want to add a service template (e.g. "Stripe", "Notion",
"Linear"), see [docs/CONTRIBUTING-TEMPLATES.md](docs/CONTRIBUTING-TEMPLATES.md)
(future — for V4.3.0 marketplace).

## Code of conduct

This project follows the [Contributor Covenant](https://www.contributor-covenant.org/).
By participating, you agree to abide by its terms.

## Table of contents

- [Filing issues](#filing-issues)
- [Submitting code](#submitting-code)
- [Code style](#code-style)
- [Architecture principles](#architecture-principles)
- [Testing](#testing)
- [Service templates](#service-templates)
- [SDK contributions](#sdk-contributions)
- [WebAuthn 2-person approval flow](#webauthn-2-person-approval-flow)
- [Audit log format](#audit-log-format)
- [Release process](#release-process)
- [Reviewing PRs](#reviewing-prs)
- [Community](#community)
- [License](#license)

## Filing issues

### Bug reports

Use the **Bug Report** issue template (`.github/ISSUE_TEMPLATE/bug_report.yml`).
Include:

- **Version**: `X-Broker-Version` header value (e.g. `4.1.1`) + commit SHA
- **Platform**: macOS / Linux / Windows / Docker / k8s / Homebrew / Snap / apt / winget
- **Node / Python / Go version** (if using SDK)
- **Reproduction steps**: minimal, copy-pasteable
- **Expected vs actual behavior**
- **Audit log excerpt** (broker auto-redacts 12+ patterns in `broker/lib/redact.js`; double-check before posting)
- **Security profile**: strict / controlled / compatibility

### Severity classification

| Severity | Examples | SLA |
|----------|----------|-----|
| **Critical** | Data loss, RCE, secret leak, auth bypass | < 7 days |
| **High** | Privilege escalation, mTLS bypass, session hijack | < 30 days |
| **Medium** | XSS, info disclosure (no PII) | < 90 days |
| **Low** | DoS, rate limit bypass, cosmetic | best effort |

### Security issues

**Do not file public GitHub issues for security vulnerabilities.**

See [SECURITY.md](SECURITY.md) and the **Bug Bounty** section.
Email: **security@broker.example.com** (PGP key in `.well-known/pgp-key.asc`).

### Feature requests

Use the **Feature Request** template. Include:

- Use case (what workflow is broken)
- Proposed solution (or "not sure — need discussion")
- Workarounds you tried
- Willingness to implement (great if you can!)

## Submitting code

### Setup

```bash
# 1. Fork + clone
gh fork tyj1987/broker
cd broker
git remote add upstream https://github.com/tyj1987/broker.git

# 2. Create a feature branch
git checkout -b feat/my-feature
# naming convention: feat/short-desc, fix/short-desc, docs/short-desc, refactor/short-desc

# 3. Install dependencies
cd broker && npm install
cd ../sdk/python && pip install -r requirements.txt
cd ../sdk/go && go mod download
cd ../sdk/vscode && npm install

# 4. Verify local tests pass
cd ../../broker && npm run test:verify-all
# Expect: 647/0 (V4.1.0) or higher
```

### Make your changes

- **Add code** to the appropriate directory (see [Architecture principles](#architecture-principles))
- **Add tests** — every new feature needs tests (see [Testing](#testing))
- **Update docs** — user-facing features need docs in `docs/`
- **Update CHANGELOG.md** — `## Unreleased` section
- **Update ROADMAP-post-1.0.md** if it closes a roadmap item

### Commit

```bash
# Conventional Commits format (enforced by CI)
git add -A
git commit -m "feat(server): add 2-person approval for client deletion

- broker/server.js: new requireClientDeletionApproval() function
- broker/lib/approval-engine.js: new module
- broker-test/test-approval.js: 40 tests
- CHANGELOG.md: ## Unreleased entry
- docs/DESIGN-V4-SECURITY-MODEL.md: 2-person approval section

Refs: ROADMAP-post-1.0.md §'WebAuthn 2-person approval'"

# Allowed types: feat, fix, docs, refactor, test, chore, perf
# Scopes: server, sdk-node, sdk-python, sdk-go, sdk-vscode, dashboard, deploy, ci, docs

# Sign commits (recommended)
git config --local commit.gpgsign true
```

### Open PR

```bash
git push -u origin feat/my-feature
gh pr create --title "feat(server): 2-person approval for client deletion" \
  --body "## What
...

## Why
...

## How tested
- npm run test:verify-all → 690/0 (was 647/0)
- new tests: broker-test/test-approval.js (40/0)

## Refs
- ROADMAP-post-1.0.md
- docs/DESIGN-V4-SECURITY-MODEL.md"
```

CI runs (V4.1+):
- `ci-v4.yml`: 3 OS × 2 Node × 5 Python × 3 Go = 90 jobs
- `test-sdks.yml`: 4 SDKs × 3 OS = 12 jobs
- `security-coverage.yml`: penetration test gate
- `supply-chain.yml`: pinned GitHub Actions + npm audit
- `release-candidate.yml`: signed image (signed only, not deployed)

## Code style

### JavaScript (broker server, dashboard, CLI, Node SDK)

- **Module system**: ESM (`"type": "module"` in package.json)
- **Style**: Prettier 3.x default
- **Lint**: ESLint 9.x with `@eslint/js` recommended
- **Test framework**: built-in `node:test` (Node 20+)
- **Imports**: relative paths (`./foo.js` not `foo`)

```bash
# Format
npx prettier --write broker/ dashboard/ cli/ sdk/node/

# Lint
npx eslint broker/ dashboard/ cli/ sdk/node/

# Test
cd broker && npm test
```

### Python SDK

- **Style**: Black 24.x + isort
- **Lint**: ruff 0.4+
- **Type hints**: required (mypy 1.10 strict)
- **Test framework**: pytest 8.x

```bash
# Format
cd sdk/python
black .
isort .

# Lint + type check
ruff check .
mypy secret_broker/

# Test
pytest tests/ -v
```

### Go SDK

- **Style**: `gofmt` + `goimports`
- **Lint**: `golangci-lint` (default linters)
- **Test framework**: built-in `testing` + `testify`

```bash
cd sdk/go
go fmt ./...
go vet ./...
golangci-lint run
go test ./...
```

### Rust (Tauri desktop, future)

- **Style**: `cargo fmt` + `cargo clippy`
- **Test framework**: built-in `#[test]`

### Shell scripts (broker/scripts/)

- **Style**: ShellCheck clean
- **Bash 5+** for `[[ ]]` and arrays
- **Quote all variables**: `"$var"` not `$var`

## Architecture principles

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full overview.
The **4 key invariants** that MUST hold across all changes:

1. **Zero credential leakage**: 12+ redact patterns in `broker/lib/redact.js`
   applied to audit/alert/broadcast/logs. Never log a raw secret.
2. **mTLS only**: all client → broker traffic uses mTLS. Loopback-only
   backend bind. nginx TLS edge in production.
3. **No new hard dependencies** in core broker: existing deps are `ws` +
   `yaml` (Node) + `setuptools` + `wheel` (Python build) only. Any new
   dep requires maintainer approval (security review).
4. **Backward compatibility**: V4.0.x → V4.1.x → V4.2.x must upgrade in-place
   with zero changes to `secrets/broker.yaml`, `secrets/clients.json`,
   `pki/`, `audit/`, secrets format, route paths.

### Directory map

```
broker/
├── broker/                    # broker server (Node.js)
│   ├── server.js              # main entry
│   ├── lib/                   # business logic modules
│   ├── routes/                # HTTP route handlers
│   ├── bin/                   # CLI scripts
│   ├── dashboard/             # web UI (vanilla JS)
│   ├── docs/                  # generated docs (gitignored)
│   └── tests/                 # unit tests (inside broker/)
├── broker-test/               # integration tests (outside broker/)
├── cli/                       # standalone CLI (broker CLI)
│   └── secret-broker.js
├── sdk/                       # language SDKs
│   ├── node/                  # NPM package
│   ├── python/                # pip package
│   ├── go/                    # Go module
│   └── vscode/                # VS Code extension
├── deploy/                    # deployment artifacts
│   ├── docker/                # Dockerfile + Compose
│   ├── helm/                  # Helm chart
│   ├── terraform/             # AWS / Azure / GCP modules
│   ├── grafana/               # monitoring dashboards
│   ├── homebrew/              # Homebrew formula
│   ├── packer/                # AWS Marketplace AMI
│   ├── snap/                  # Snap Store
│   ├── winget/                # Windows Package Manager
│   └── apt/                   # Debian/Ubuntu package
├── docs/                      # design docs + user guides
├── .github/                   # GitHub Actions + issue templates
├── scripts/                   # utility scripts
│   ├── broker/                # install / upgrade / migrate
│   └── dev/                   # dev tools
├── pki/                       # dev PKI (gitignored ca.key)
├── secrets/                   # dev config (gitignored)
└── audit/                     # dev audit logs (gitignored)
```

### Module boundaries

- `broker/lib/` modules are **pure functions** where possible
- `broker/routes/` handlers are **thin wrappers** around `lib/` modules
- `broker/bin/` CLI scripts use the same `lib/` modules
- `cli/secret-broker.js` is a **standalone** CLI (no `lib/` dependency)
- `sdk/*` mirror the **external API surface** (what users call)

## Testing

### Test framework

- **Broker**: built-in `node:test` (Node 20+)
- **Python SDK**: pytest 8.x
- **Go SDK**: built-in `testing` + testify
- **Dashboard**: manual smoke tests + Playwright (future)
- **Integration**: `broker-test/` (separate dir, requires broker running)

### Test commands

```bash
cd broker
npm run test:lib          # core lib tests
npm run test:ip           # IP allowlist
npm run test:routes       # route handlers
npm run test:obs          # observability
npm run test:trace        # audit log tracing
npm run test:ops          # ops endpoints
npm run test:backup       # backup + probes
npm run test:v4           # V4 modules (redact + mfa + sms + apikeys)
npm run test:v4-modules   # V4 integration
npm run test:workload     # workload identity
npm run test:ssh          # SSH proxy
npm run test:ws           # WebSocket
npm run test:verify       # broker only
npm run test:python-sdk   # Python SDK
npm run test:verify-all   # broker + Python SDK (THE main test)
```

### Test requirements

- **All new features**: 100% test coverage for new code (line + branch)
- **Bug fixes**: regression test that fails before the fix and passes after
- **Performance**: benchmark test if claim is "X% faster"
- **Security**: penetration test if claim is "X is now safe"

### Test naming

- `broker-test/test-<feature>.js` — top-level feature
- `broker-test/test-<feature>-<aspect>.js` — sub-aspect (e.g. `test-ssh-proxy.js`)

## Service templates

Service templates let broker call external APIs (GitHub, OpenAI, AWS, etc.).
V4.1.0 ships with 48 templates in `broker/service-templates.js`.

### Adding a template (V4.1.x — direct PR)

1. Edit `broker/service-templates.js`:
   ```javascript
   {
     name: 'my-service',
     displayName: 'My Service',
     category: '...',
     auth: { type: 'bearer', field: 'api_key' },
     operations: {
       list_items: {
         method: 'GET',
         path: '/v1/items',
         description: 'List items'
       }
     },
     rotation: { interval_days: 90, warning_days: 14, auto_rotate: true }
   }
   ```

2. Add tests to `broker-test/test-service-templates.js`
3. Add docs to `docs/SERVICES.md` (auto-generated)
4. Add icon to `broker/dashboard/icons/services/`
5. PR + CI passes

### Adding a template (V4.3.0 — marketplace)

V4.3.0 introduces 3rd-party marketplace (see [docs/DESIGN-MARKETPLACE-SELF-SERVICE.md](docs/DESIGN-MARKETPLACE-SELF-SERVICE.md)).
Then you can `secret-broker marketplace publish` from your own repo.

## SDK contributions

The 4 SDKs (Node / Python / Go / VSCode) all share the same API surface.
When adding a feature to one SDK, you usually need to add it to all 4.

### SDK consistency checklist

- [ ] Function signature matches across all 4 SDKs
- [ ] Error types / exceptions match (or have documented divergences)
- [ ] Tests in all 4 SDKs (V4.1.0: 28 tests in Python, ~50 in each other)
- [ ] Examples in all 4 SDKs (see `sdk/*/examples/`)
- [ ] Docs in all 4 SDKs (see `docs/SDK-REFERENCE.md`)
- [ ] CHANGELOG entry

### Adding a new SDK

1. Create `sdk/<lang>/` directory
2. Implement same API surface as existing SDKs
3. Add to `sdk/VERSION` matrix in `CHANGELOG.md`
4. Add to `.github/workflows/test-sdks.yml`
5. Add to `docs/SDK-REFERENCE.md` with code samples
6. Add to `package.json` workspaces (if Node) or `go.mod` (if Go) or `pyproject.toml` (if Python)

## WebAuthn 2-person approval flow

V4.1.0 enforces 2-person approval for **all mutations** (client/secret/
service create/update/delete). Adding a new mutation requires:

1. Add approval gate in `broker/lib/approval-engine.js`
2. Add 5-min one-use reauth grant in `broker/routes/auth.js`
3. Add tests in `broker-test/test-approval.js` (target 40+ tests)
4. Update [docs/DESIGN-V4-SECURITY-MODEL.md](docs/DESIGN-V4-SECURITY-MODEL.md) §2-person-approval
5. Test with 2 physical WebAuthn keys (e.g. 2 YubiKeys)

**Test pattern**:
```javascript
// broker-test/test-approval.js
test('2-person approval with 2 different physical key IDs', async () => {
  const requester = await createClientWithKey('KEY_REQUESTER');
  const approver = await createClientWithKey('KEY_APPROVER_DIFFERENT');  // different credential ID

  // 1. Requester submits mutation
  const approvalId = await requester.post('/api/v1/clients', { ... });

  // 2. Approver approves with WebAuthn reauth
  const grant = await approver.webauthnReauth();
  await approver.post(`/api/v1/approvals/${approvalId}/approve`, { grant });

  // 3. Server executes mutation
  const result = await approver.get('/api/v1/clients');
  expect(result).toContain('new_client');
});
```

## Audit log format

V4.1.0 audit logs are structured JSON. **Never** log raw secrets — they go
through `broker/lib/redact.js` (12+ patterns).

```json
{
  "timestamp": "2026-09-06T15:30:00.123Z",
  "request_id": "req_abc123",
  "client": "client.dashboard-admin-acme",
  "tenant": "tenant-a",                          // V4.2.0
  "source_ip": "203.0.113.42",
  "method": "POST",
  "path": "/api/v1/secrets/github-pat/decrypt",
  "action": "secret.decrypt",
  "resource": "secrets:github-pat",
  "mfa_method": "webauthn_aal3",                  // or "mTLS", "password", "totp"
  "risk_score": 35,
  "decision": "allow",                            // or "deny"
  "matched_policy": "developer-mfa-strict-prod",  // V4.2.0 ABAC
  "duration_ms": 12,
  "status_code": 200
}
```

### Reading audit logs

```bash
# All events in last 24h
jq '.' /var/log/secret-broker/audit-2026-09-06.log

# All decrypt attempts for a specific secret
jq 'select(.action == "secret.decrypt" and .resource == "secrets:github-pat")' audit.log

# All denied events
jq 'select(.decision == "deny")' audit.log

# All events with risk_score > 50
jq 'select(.risk_score > 50)' audit.log
```

## Release process

### V4.x.y patch (backport)

1. Branch from `master`: `git checkout -b release/v4.x.y origin/master`
2. Bump version: edit 7 files (broker/version.js, broker/package.json,
   sdk/python/pyproject.toml, sdk/python/secret_broker/__init__.py,
   sdk/go/broker/client.go, sdk/vscode/package.json, sdk/vscode/src/client.ts)
3. Cherry-pick fixes from master
4. Test: `npm run test:verify-all`
5. Audit: `npm audit --omit=dev`
6. Commit + push + open PR
7. After merge: tag `v4.x.y` + create GitHub Release (see V4.1.0 release notes)

### V4.x.0 minor (new features)

Same as patch + add new feature commits + update CHANGELOG section.

### V5.0.0 major (breaking changes)

Same as minor + bump major version + MIGRATION.md + deprecation warnings
for 1 minor version before.

## Reviewing PRs

We use **2 approvals** for all PRs:
- 1 maintainer (tyj1987) — required
- 1 community member (any contributor who has merged 3+ PRs)

### What we look for

- **Correctness**: does it work? Are tests comprehensive?
- **Security**: any credential leakage? Any new attack surface?
- **Architecture**: does it follow the 4 invariants?
- **Backward compat**: any breaking changes?
- **Docs**: is the change documented?
- **Tests**: are they real (not just smoke)?

### Review SLA

| PR type | First review | Final approval |
|---------|--------------|-----------------|
| Critical (security fix) | < 24h | < 7 days |
| High (broken feature) | < 48h | < 30 days |
| Medium (new feature) | < 7 days | < 90 days |
| Low (docs, refactor) | < 30 days | best effort |

## Community

- **GitHub Discussions**: https://github.com/tyj1987/broker/discussions
- **Security email**: security@broker.example.com
- **Maintainer**: tyj1987
- **Discord / Slack**: TBD (will be set up if there's interest)

## License

By contributing, you agree that your contributions will be licensed under
the [MIT License](LICENSE).

---

**Last updated**: 2026-09-06 (V4.1.0+ era)
