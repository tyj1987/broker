# AGENTS.md — broker project onboarding

> **For AI agents (Mavis / Mavis / Codex / Cursor / Windsurf) working on the
> broker repo.** Read this first to understand project structure, key
> commands, decision entry points, and gotchas — so you don't waste tokens
> rediscovering them.
>
> **Last verified**: 2026-09-06 (V4.1.1 release prep, 27 PR in origin).

## Project at a glance

- **What**: Secret Broker — mTLS credential proxy for AI agents (Mavis, Mavis,
  Claude, Codex, Cursor, etc.). Caches + redacts secrets so AI agents can
  call broker instead of holding raw credentials.
- **Status**: V4.1.0 GA (tag `v4.1.0`, 2026-09-01). V4.1.1 patch ready
  (release/v4.1.1 branch + 4 SDK V4.1.1 + 6 community/devops/docs PRs).
- **Language**: Node.js 20+/22+ (broker core + 4 SDKs: Python, Go, Node
  CLI, VSCode). C++17 only for visual clients (Tauri scaffold).
- **Tests**: 795 (V4.1.1 ahead of tag) — broker 629 + 4 SDKs 166.
- **Hard dependencies**:
  - Broker: `ws` (WebSocket only) + `yaml` (OpenAPI parser).
  - Python SDK: **none** (stdlib only).
  - Go SDK: **none** (stdlib only).
  - Node CLI: **none** (built-in `https` + `tls`).
  - VSCode: **none** (built-in `https` + `tls`).
- **Deployment**: Docker / Helm / Terraform / bare-metal / DEPLOY-52TRZ.md.

## Repository layout

```
E:\broker\
├── AGENTS.md                    ← you are here
├── AWAITING-USER.md             ← user decision entry (current: V13)
├── CHANGELOG.md                 ← version history (V4.1.1 entry)
├── LICENSE                      ← MIT
├── ROADMAP-post-1.0.md          ← 13 items P0-P3 (V4.1.1 done 55天 early)
├── STATUS.md                    ← project state (V4.1.1 ready)
├── RELEASES.md                  ← V4.0 → V4.1 release timeline
├── RELEASE-NOTES-v4.1.0.md
├── RELEASE-NOTES-v4.1.1.md      ← V4.1.1 GitHub Release body
├── README.md                    ← top-level project intro
├── DEPLOY-52TRZ.md              ← production deploy (52trz.com)
├── RUNBOOK.md                   ← general broker operations
├── V4.1-COMPLETE.md             ← V4.1.0 GA completion summary
├── VERIFY.md                    ← 1-line verification
├── ARCHITECTURE.md              ← one-page overview
├── SECURITY.md                  ← security policy + bug bounty
├── broker/                      ← core broker (Node.js)
│   ├── server.js
│   ├── version.js               ← BROKER_VERSION constant
│   ├── package.json
│   ├── lib/                     ← modular routes (auth, audit, ssh, ws, ...)
│   ├── bin/
│   ├── test/                    ← legacy test runner
│   └── ...
├── broker-test/                 ← new test runner (modular)
│   ├── test-phase-f-backup-probes.js
│   └── ...
├── cli/                         ← Node CLI (mavis, mavis, etc.)
│   ├── secret-broker.js         ← V4.1.1: BrokerError + parseBrokerError + retry
│   ├── test-error.js            ← V4.1.1: 21 tests
│   └── examples/
│       └── v4.1.1-error-handling.mjs   ← V4.1.1 example
├── sdk/
│   ├── python/                  ← Python SDK (zero deps)
│   │   ├── secret_broker/
│   │   │   ├── client.py
│   │   │   ├── exceptions.py    ← V4.1.1: BrokerError + 6 classes
│   │   │   └── ...
│   │   ├── tests/               ← V4.1.1: 54 tests
│   │   ├── examples/
│   │   │   └── v4.1.1_error_handling.py
│   │   └── pyproject.toml
│   ├── go/                      ← Go SDK (zero deps)
│   │   ├── broker/
│   │   │   ├── client.go
│   │   │   ├── errors.go        ← V4.1.1: BrokerError struct + retry
│   │   │   └── ...
│   │   ├── test/                ← V4.1.1: 33 tests + 1 SKIP
│   │   ├── examples/
│   │   │   ├── basic/
│   │   │   └── v4.1.1_error_handling/main.go
│   │   └── go.mod
│   └── vscode/                  ← VSCode / Cursor / Windsurf extension (TS)
│       ├── src/
│       │   ├── client.ts        ← V4.1.1: BrokerError + parseBrokerError + mtlsRequest retry
│       │   ├── extension.ts
│       │   └── test/
│       │       ├── client.test.ts
│       │       ├── error.test.ts ← V4.1.1: 38 tests
│       │       └── mock_broker.ts
│       ├── examples/
│       │   └── v4.1.1_error_handling.ts
│       ├── out/                 ← build output (gitignored)
│       └── package.json
├── deploy/
│   ├── docker/
│   ├── helm/broker/
│   ├── terraform/               ← AWS / Azure / GCP
│   ├── homebrew/broker.rb       ← Homebrew formula
│   ├── apt/debian/              ← apt debian packages
│   ├── packer/                  ← AWS AMI build
│   └── ...
├── snap/snapcraft.yaml          ← Snap manifest
├── winget/tyj1987.broker.*.yaml ← winget manifest
├── desktop/                     ← Tauri 2.0 desktop client scaffold
├── scripts/
│   ├── release/v4.1.1.sh        ← V4.1.1 bash build + upload
│   ├── preflight-v4.1.1.mjs     ← V4.1.1 Node pre-tag sanity check
│   └── ...
├── secrets/                     ← encrypted SOPS configs (gitignored values)
│   ├── broker.yaml.example
│   ├── secrets-detail.json      ← gitignored, used in dev
│   └── ...
├── pki/                         ← mTLS certs (ca.crt, clients/*.crt+key)
├── audit/                       ← audit log (gitignored)
├── docs/                        ← public docs
│   ├── DESIGN-*.md              ← design specs (V4 API, V4 identity, V4 master plan, ...)
│   ├── SDK-REFERENCE.md         ← full SDK API reference (V4.1.1)
│   ├── SDK-UPGRADE-GUIDE.md     ← V4.1.0 → V4.1.1 migration
│   ├── RUNBOOK-v4.1.1.md        ← V4.1.1 release 8 步 manual
│   ├── SECURITY-AUDIT-2026-09-05.md
│   ├── HOMEBREW.md
│   ├── SNAP-APT-WINGET.md
│   ├── CLOUD-MARKETPLACE.md
│   ├── SECURITY-CONTROLS-ISO27001.md
│   ├── SECURITY-CONTROLS-SOC2.md
│   ├── DESIGN-MOBILE-CLIENTS.md
│   ├── DESIGN-V4.2.0.md
│   ├── DESIGN-TAURI-DESKTOP.md
│   ├── DESIGN-MARKETPLACE-SELF-SERVICE.md
│   ├── V4.1.2-PATCH-PREP.md
│   └── openapi.yaml
├── .github/workflows/
│   ├── ci-v4.yml                ← broker core CI
│   ├── test-sdks.yml            ← 4 SDK CI
│   └── ...
└── node_modules/                ← gitignored
```

## Decision entry points (READ FIRST)

When a session starts, check these in order:

1. **[AWAITING-USER.md](AWAITING-USER.md)** — what the user is currently deciding
   on. V13 (2026-09-06) lists 27 PR + recommended merge order. V14 will
   be created 2026-10-01 for V4.1.2 prep.
2. **[ROADMAP-post-1.0.md](ROADMAP-post-1.0.md)** — 13 items P0-P3 (V4.1.1
   done 55 days early). Status table at top reflects current state.
3. **[STATUS.md](STATUS.md)** — V4.1.1 patch ready, awaiting user merge.
4. **[CHANGELOG.md](CHANGELOG.md)** — V4.1.1 entry + SDK parity subsection.
5. **[RUNBOOK-v4.1.1.md](docs/RUNBOOK-v4.1.1.md)** — 8 步 release manual
   (when user is ready to ship V4.1.1).

## Common tasks

### Run all tests

```bash
# Broker (modular, fast)
cd broker
npm run test:modular         # core + modular routes
npm run test:v4-modules      # P1+P2+P3 V4 modules
npm run test:workload        # OIDC + STS
npm run test:ssh             # SSH proxy + tunnel + exec
npm run test:ws              # WebSocket + broadcast

# Or all in one:
npm run test:verify-all      # 629 broker tests + 28 Python SDK tests

# Python SDK
cd ../sdk/python
pip install -e ".[test]"
pytest tests/ -q             # 54 tests (V4.1.1)

# Go SDK
cd ../sdk/go
go test ./...                # 33 tests + 1 SKIP (V4.1.1)

# Node CLI
cd ../cli
node --test test-error.js    # 21 tests (V4.1.1)

# VSCode SDK
cd ../sdk/vscode
npm install
npm run build
node ./out/test/error.test.js # 38 tests (V4.1.1)
```

### V4.1.1 pre-tag sanity check

```bash
# Cross-platform Node script — checks everything is in place before tagging.
node scripts/preflight-v4.1.1.mjs --strict
# Exit 0 = ready to tag. Non-zero = see output for missing items.
```

### V4.1.1 release (Linux/macOS only)

```bash
# Build 8 assets + SHA-256 + MANIFEST
bash scripts/release/v4.1.1.sh

# Upload to GitHub Release (with publish)
bash scripts/release/v4.1.1.sh --upload --publish
```

### Local broker smoke

```bash
# Start broker in plaintext bypass mode (one command, dev only)
pwsh scripts/dev/start-broker.ps1

# Or manual:
cd broker
npm install
node server.js               # foreground, Ctrl-C to stop
# Or background:
node server.js &

# Health check
curl -k --cert ../pki/clients/admin.crt --key ../pki/clients/admin.key \
     https://127.0.0.1:8443/health
# Expect: {"status":"ok","version":"4.1.0",...}
```

### Add a new SDK error code (when broker adds a new error)

When broker returns a new `code` field in error response body:

1. Update `broker/lib/error-codes.js` (if it exists) or wherever codes are
   enumerated. Most code lives in `broker/server.js` error responses.
2. Add tests for the new code in `broker/test/` (or relevant test file).
3. Update `docs/SDK-REFERENCE.md` Typed errors section.
4. SDKs already auto-pass-through `code` field — no SDK changes needed.
5. Update `docs/SDK-UPGRADE-GUIDE.md` if it's a behavioral change.

### Add a new SDK surface (e.g. new API endpoint)

When broker adds a new endpoint, expose it in all 4 SDKs:

1. Add broker endpoint + test in `broker/server.js` + `broker-test/`.
2. Add Python method in `sdk/python/secret_broker/client.py`.
3. Add Go method in `sdk/go/broker/client.go`.
4. Add Node CLI method in `cli/secret-broker.js`.
5. Add VSCode method in `sdk/vscode/src/client.ts`.
6. Update `docs/SDK-REFERENCE.md` Common API surface table.
7. Update 4 SDK tests.

## Gotchas (don't repeat these mistakes)

### 1. cp936 default execution-charset (Windows)

MSVC / Node on Windows defaults to cp936 (GBK) for source files, which
**replaces Korean / Chinese codepoints with `?` placeholder** when the
file is encoded UTF-8. Always add `/execution-charset:utf-8` to MSVC
compiles, and use `Set-Content -Encoding UTF8` for PowerShell writes.

### 2. mTLS cert-as-session (V4.1.0 → V4.1.1)

The `/api/v1/login` mTLS path **treats the client cert as the credential**
(bypassing the password check) instead of returning 403 "No password
configured for this client". V4.1.0 had this broken; V4.1.1 fixed it
(cherry-pick from `f3a7cc7`).

If you see `403 No password configured for this client` from a cert-only
client (mavis / Claude / Codex AI agent), the broker is running V4.1.0
or earlier. Upgrade to V4.1.1.

### 3. DEP0187 DeprecationWarning (V4.1.1 fix)

When `AGE_KEY_FILE` env is unset, `fs.existsSync(undefined)` triggers
Node 22+ DEP0187. V4.1.1 fix: `if (AGE_KEY_FILE && existsSync(AGE_KEY_FILE))`.

### 4. openssl not on PATH (mock broker tests)

`mock_broker.ts` and `error.test.ts` use `openssl` to generate self-signed
certs. On Windows, `openssl` is not on PATH by default. Fallback path:
`C:\Program Files\Git\mingw64\bin\openssl.exe` (Git for Windows ships
its own). Both test files now have fallback candidates.

### 5. PowerShell pathspec bug

When `git commit -m "...${var}..."` contains `{...}` literally, PowerShell
interprets it as a script block and errors with
`error: pathspec '<content>' not found`. Workaround: use
`Set-Content -Path .git/COMMIT_EDITMSG -Value "..." -Encoding UTF8` then
`git commit -F .git/COMMIT_EDITMSG`.

### 6. Node `--test` ESM-only

Node 20+ `node --test` requires ESM. CLI uses ESM (`.mjs`). VSCode SDK
uses TypeScript (compiled to CommonJS in `out/`).

### 7. Python `idn-email` dep (V4.1.0 fix)

Python 3.9- lacks `email_validator` for IDN email. V4.1.0 had a fallback
in `pyproject.toml` to skip the dep. Don't re-add it as a hard dep.

### 8. Local dirty tree (8 untracked files)

Currently untracked but `gitignored` or only in dev:
- `broker/docs/` (broker subdirectory, not main docs/)
- `lease_schedule_hydropower*.py` (personal — not for repo)
- `水电站融资租赁方案_1亿_15年.{md,xlsx}` (personal — not for repo)
- `secrets/secrets-detail.json` (encrypted, gitignored)
- `sdk/python/.pytest-tmp/` (test tmp, gitignored)
- `sdk/vscode/out/` (build output, gitignored)

User has not decided whether to commit `broker/docs/` or other items.
**DO NOT auto-commit these** without user explicit instruction.

## Style conventions

- **Commit message**: Conventional Commits style. `feat(scope): subject` /
  `fix(scope): subject` / `docs(scope): subject` / `chore(scope): subject`
  / `ci(scope): subject`. Subject ≤ 72 chars. Body explains WHY not WHAT.
- **Branch name**: `feat/<description>` / `fix/<description>` /
  `docs/<description>` / `chore/<description>` / `ci/<description>` /
  `release/<version>`. Use kebab-case.
- **PR**: One PR per logical change. Don't mix refactor + feature.
- **Tests**: All new code must have tests. SDK changes must update
  `docs/SDK-REFERENCE.md` + 4 SDK example code if behavior changes.
- **No commit unless user says "GO" / "commit" / "push"** — user is the
  source of truth for git operations.
- **PowerShell only** (Windows): no `&&`, no `ls -la`, no `head`/`tail`/
  `grep`/`wc`. Use `;`, `Get-ChildItem`, `Select-Object`, `Select-String`.

## When in doubt

1. **Check [AWAITING-USER.md](AWAITING-USER.md)** — current user decisions.
2. **Check [ROADMAP-post-1.0.md](ROADMAP-post-1.0.md)** — what's planned.
3. **Check [RUNBOOK-v4.1.1.md](docs/RUNBOOK-v4.1.1.md)** — release manual.
4. **Check [docs/SDK-REFERENCE.md](docs/SDK-REFERENCE.md)** — SDK API.
5. **Check [docs/SDK-UPGRADE-GUIDE.md](docs/SDK-UPGRADE-GUIDE.md)** — migration.
6. **Grep** for similar work in past commits (`git log --all --oneline | grep`).
7. **Ask user** — when the ambiguity would change the deliverable.

## Reference

- [README.md](README.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [QUICKSTART.md](docs/QUICKSTART.md)
- [RUNBOOK.md](RUNBOOK.md)
- [DEPLOY-52TRZ.md](DEPLOY-52TRZ.md)
- [AWAITING-USER.md](AWAITING-USER.md) — current: V13
- [ROADMAP-post-1.0.md](ROADMAP-post-1.0.md) — 13 items P0-P3
- [CHANGELOG.md](CHANGELOG.md) — V4.1.1 entry
- [STATUS.md](STATUS.md) — V4.1.1 ready
- [RELEASE-NOTES-v4.1.1.md](RELEASE-NOTES-v4.1.1.md) — GitHub Release body
- [docs/SDK-REFERENCE.md](docs/SDK-REFERENCE.md) — full SDK API
- [docs/SDK-UPGRADE-GUIDE.md](docs/SDK-UPGRADE-GUIDE.md) — V4.1.0 → V4.1.1
- [docs/RUNBOOK-v4.1.1.md](docs/RUNBOOK-v4.1.1.md) — 8 步 release
- [scripts/preflight-v4.1.1.mjs](scripts/preflight-v4.1.1.mjs) — pre-tag
- [scripts/release/v4.1.1.sh](scripts/release/v4.1.1.sh) — build + upload

---

**Document version**: 2026-09-06 (V4.1.1 release prep)
**Applies to**: future Mavis / Mavis / Codex / Cursor sessions working on broker repo
**Updated by**: session 17 (V4.1.1 + 4-SDK parity 11-commit push)
