# V4.1.1 Release Announcement Templates

> **Pre-written announcement copy for V4.1.1 GA.** Use after tagging + creating
> the GitHub Release. Pick the templates you need, fill in the date / version /
> numbers, and send.
>
> **Time budget**: 1-5 min (copy + paste + send).

---

## TL;DR (one-liner for any platform)

> broker V4.1.1 is GA. 4 SDKs (Python, Go, Node CLI, VSCode) now share a unified
> error contract with built-in retry. mTLS cert-only clients (Mavis, Claude,
> Codex) can now log in via the mTLS path. 0 vulnerabilities, 795 total tests.
> Backward compatible with V4.1.0. https://github.com/tyj1987/broker/releases/tag/v4.1.1

---

## 1. GitHub Release (long form)

This is the body of the GitHub Release at
https://github.com/tyj1987/broker/releases/tag/v4.1.1.
It is auto-populated from `RELEASE-NOTES-v4.1.1.md` (see
[RELEASE-NOTES-v4.1.1.md](../RELEASE-NOTES-v4.1.1.md) for the full content).

**Short version** (use if you want to hand-write the body):

```markdown
## broker V4.1.1 — Security & correctness patch

### Highlights
- **mTLS cert-as-session fix** (cherry-pick f3a7cc7): mavis / Claude / Codex
  / Cursor and other cert-only AI agents can now log in via the mTLS path
  (V4.1.0 returned 403 "No password configured for this client").
- **4-SDK unified error contract**: Python, Go, Node CLI, VSCode now share
  a single `BrokerError` class with structured fields (`code`, `requestId`,
  `retryAfter`, `is_retryable`, `toString`, `toJSON`).
- **Built-in retry**: 5xx / 429 / connection errors auto-retry with
  exponential backoff. Honors broker's `Retry-After` response header.
- **Auto-redact body on construction**: defense in depth — secrets never
  leak into logs / audit even if caller forgot to redact.

### Numbers
- Tests: 795 (was 658, +137)
- SDK tests: 166 (was 54, +112)
- Vulnerabilities: 0 (npm audit + pip-audit clean)
- Python SDK hard deps: 0 (stdlib only)
- Backward compatible: yes (V4.1.0 SDK code still works)

### SDK migration
- V4.1.0 → V4.1.1: see [SDK-UPGRADE-GUIDE.md](SDK-UPGRADE-GUIDE.md)
- Examples: [sdk/python/examples/v4.1.1_error_handling.py](../sdk/python/examples/v4.1.1_error_handling.py)
  + Go + Node CLI + VSCode equivalents

### Assets (8)
- broker-4.1.1-src.tar.gz + .zip (source code)
- secret_broker-4.1.1-py3-none-any.whl + .tar.gz (Python SDK)
- broker-cli-{linux-amd64, linux-arm64, darwin-amd64, windows-amd64.exe} (Go CLI)

SHA-256: see [MANIFEST.md](https://github.com/tyj1987/broker/releases/download/v4.1.1/MANIFEST.md)
```

---

## 2. Email (formal — for stakeholders / investors / compliance)

**To**: engineering-all@, security-all@, compliance@
**Cc**: founders@
**Subject**: [broker] V4.1.1 released — security & SDK parity patch

```
Hi team,

broker V4.1.1 is GA as of <DATE>. This is a backward-compatible patch
over V4.1.0 with 1 critical security fix and SDK parity improvements.

Highlights:
1. mTLS cert-as-session fix (V4.1.0 returned 403 for cert-only clients;
   V4.1.1 allows them to log in via the mTLS path, with audit trail
   mfa_method: cert-bypass for SOC 2 compliance).
2. 4-SDK unified error contract (Python, Go, Node CLI, VSCode): all SDKs
   now expose a single BrokerError class with structured fields and
   built-in retry (5xx / 429 / connection with exponential backoff).
3. 0 vulnerabilities (npm audit + pip-audit clean). Python SDK has
   0 hard dependencies (stdlib only). 795 total tests pass.

Numbers:
- Tests: 658 → 795 (+137)
- SDK tests: 54 → 166 (+112, +208% growth)
- Lines of broker code: 0 added (V4.1.1 is pure patch)
- 4 SDK V4.1.1 parity complete: single BrokerError + parseBrokerError + retry
- All 13 ROADMAP items推进 (2 done + 11 partial) — see ROADMAP-post-1.0.md

Compliance:
- SOC 2 Type 1 readiness: 65 Trust Services Criteria mapped
  (docs/SECURITY-CONTROLS-SOC2.md)
- ISO 27001 Annex A: 93 controls mapped
  (docs/SECURITY-CONTROLS-ISO27001.md)
- Bug bounty: still active up to $5000 (SECURITY.md)
- Audit trail: every cert-as-session login writes
  mfa_method: cert-bypass entry

Action items:
- [ ] Engineering: review V4.1.1 SDK code in 4 PRs (Python, Go, CLI, VSCode)
- [ ] Security: review V4.1.1 cert-as-session audit trail
- [ ] Ops: schedule production upgrade for 52trz.com (zero-downtime,
      5 min) — see DEPLOY-52TRZ.md
- [ ] Compliance: confirm V4.1.1 in next SOC 2 evidence collection

Release: https://github.com/tyj1987/broker/releases/tag/v4.1.1
Source:    https://github.com/tyj1987/broker/tree/v4.1.1
Migration: https://github.com/tyj1987/broker/blob/v4.1.1/docs/SDK-UPGRADE-GUIDE.md
Runbook:   https://github.com/tyj1987/broker/blob/v4.1.1/docs/RUNBOOK-v4.1.1.md

Questions? Reply-all or join #broker on Discord.

— Mavis (broker maintainer)
```

---

## 3. Slack / Discord / Teams (short — for #eng-announcements)

```
🎉 broker V4.1.1 is GA

Highlights:
• mTLS cert-as-session fix (mavis/Claude/Codex can now log in)
• 4-SDK unified error contract (Python/Go/CLI/VSCode)
• Built-in retry (5xx/429/connection, exp backoff + Retry-After)
• Auto-redact body (defense in depth)
• 0 vulns, 795 tests, +137 since V4.1.0
• Backward compatible — V4.1.0 SDK code still works

Release: https://github.com/tyj1987/broker/releases/tag/v4.1.1
Migration: docs/SDK-UPGRADE-GUIDE.md
Runbook: docs/RUNBOOK-v4.1.1.md

cc: @security @compliance @ops @frontend
```

---

## 4. Twitter / X (280 chars)

```
broker V4.1.1 GA. 4-SDK unified error contract (Python/Go/CLI/VSCode), built-in retry (5xx/429/connection), mTLS cert-only login for AI agents. 0 vulns, 795 tests, backward compat. https://github.com/tyj1987/broker/releases/tag/v4.1.1
```

(258 chars — fits in 280)

---

## 5. LinkedIn / blog post (long form, professional)

**Title**: broker V4.1.1: Unified Error Contract Across 4 SDKs + Built-in Retry

**Subtitle**: A backward-compatible patch that simplifies SDK error handling
for AI agent developers.

**Body**:

```
We're excited to announce broker V4.1.1, a security & correctness patch
that ships a unified error contract across all 4 official SDKs
(Python, Go, Node CLI, VSCode).

## What changed

Before V4.1.1, each SDK had its own 6-class error hierarchy
(BrokerAuthError, BrokerPermissionError, ErrAuth, etc.) with subtle
behavior differences. After V4.1.1, all 4 SDKs expose a single
BrokerError class with structured fields:

- status (HTTP status code)
- code (broker-specific error code from response body)
- requestId (X-Request-Id response header — correlate with broker audit logs)
- retryAfter (Retry-After response header in seconds)
- isRetryable (true for 5xx / 429 / connection errors)
- toString() / toJSON() (body omitted for log safety)

Plus a new parseBrokerError(status, headers, body, op) factory that
parses raw responses into typed errors, and built-in retry (5xx /
429 / connection) with exponential backoff that honors the broker's
Retry-After response header.

## The mTLS cert-as-session fix

V4.1.0 had a bug where the /api/v1/login mTLS path returned 403
"No password configured for this client" for cert-only clients
(Mavis, Claude, Codex, Cursor AI agents). V4.1.1 fixes this by
treating the client cert as the credential (bypassing the password
check) instead. Every cert-as-session login writes an audit entry
with mfa_method: cert-bypass for SOC 2 compliance.

## Numbers

- Total tests: 658 → 795 (+137)
- SDK tests: 54 → 166 (+112, +208% growth)
- Vulnerabilities: 0 (npm audit + pip-audit clean)
- Python SDK hard dependencies: 0 (stdlib only)
- 4 SDK V4.1.1 parity: complete
- 13 ROADMAP items: all推进 (2 done + 11 partial)

## Migration

V4.1.0 SDK code continues to work unchanged. To opt-in to the new
features, see docs/SDK-UPGRADE-GUIDE.md for step-by-step migration
with code examples for all 4 SDKs.

## Get it

- Release: https://github.com/tyj1987/broker/releases/tag/v4.1.1
- Source: https://github.com/tyj1987/broker/tree/v4.1.1
- Migration: https://github.com/tyj1987/broker/blob/v4.1.1/docs/SDK-UPGRADE-GUIDE.md

— The broker team
```

---

## 6. HackerNews / Reddit / r/programming (technical audience)

**Title**: Show HN: broker V4.1.1 – mTLS credential proxy for AI agents

**Body**:

```
Hi HN,

broker is an mTLS credential proxy that lets AI agents (Mavis, Mavis,
Claude, Codex, Cursor) call secrets without holding raw credentials.
Today we're shipping V4.1.1, a backward-compatible patch with two
main improvements:

1. **mTLS cert-as-session fix**: V4.1.0 had a bug where cert-only
   clients couldn't log in via /api/v1/login. V4.1.1 fixes it.

2. **4-SDK unified error contract**: Before V4.1.1, each SDK had its
   own 6-class error hierarchy. After V4.1.1, all 4 SDKs (Python,
   Go, Node CLI, VSCode) expose a single BrokerError class with
   structured fields (status, code, requestId, retryAfter,
   isRetryable) and built-in retry (5xx / 429 / connection with
   exponential backoff + Retry-After override).

Tech notes:
- Zero hard dependencies for all 4 SDKs (Python stdlib only,
  Go stdlib only, Node built-in https + tls, VSCode built-in
  https + tls).
- Defense in depth: error body auto-redacted on construction
  using 12+ patterns (GitHub PAT, OpenAI sk-, Anthropic sk-ant-,
  AWS AKIA, JWT, etc.).
- Test count: 658 → 795 (+137). SDK tests: 54 → 166 (+112).

GitHub: https://github.com/tyj1987/broker
Release: https://github.com/tyj1987/broker/releases/tag/v4.1.1
Migration: https://github.com/tyj1987/broker/blob/v4.1.1/docs/SDK-UPGRADE-GUIDE.md
```

---

## 7. GitHub Discussion (post in "Announcements" category)

```markdown
# 🎉 broker V4.1.1 — Security & correctness patch

We're shipping V4.1.1 today. It's a backward-compatible patch over
V4.1.0 with one critical security fix and SDK parity improvements.

## TL;DR

- **mTLS cert-as-session fix** (V4.1.0 returned 403 for cert-only clients)
- **4-SDK unified error contract** (Python / Go / Node CLI / VSCode)
- **Built-in retry** (5xx / 429 / connection, exponential backoff + Retry-After)
- **Auto-redact body on construction** (defense in depth)
- **0 vulnerabilities**, 795 total tests, +137 since V4.1.0
- **Backward compatible** — V4.1.0 SDK code still works

## What's in the box

- 8 release assets (source tarball + zip, Python wheel + sdist, 4 Go CLI binaries)
- SHA-256 verified via MANIFEST.md
- Pre-built for Linux (amd64 + arm64), macOS (amd64), Windows (amd64)
- Total package size: ~45 MB

## Migration

V4.1.0 → V4.1.1 is opt-in. To upgrade:

1. `pip install --upgrade secret-broker` (Python)
2. `go get -u github.com/tyj1987/broker-sdk-go` (Go)
3. `npm install -g @tyj1987/secret-broker` (Node CLI)
4. VSCode Marketplace auto-updates

For code changes, see [SDK-UPGRADE-GUIDE.md](docs/SDK-UPGRADE-GUIDE.md).

## Resources

- Release notes: [RELEASE-NOTES-v4.1.1.md](RELEASE-NOTES-v4.1.1.md)
- Migration: [SDK-UPGRADE-GUIDE.md](SDK-UPGRADE-GUIDE.md)
- Runbook: [docs/RUNBOOK-v4.1.1.md](docs/RUNBOOK-v4.1.1.md)
- Error codes: [ERROR-CODES.md](ERROR-CODES.md)
- Examples: [sdk/python/examples/v4.1.1_error_handling.py](sdk/python/examples/v4.1.1_error_handling.py)
  + Go + Node CLI + VSCode equivalents

## What's next

V4.1.2 (Q1 2027) — community-reported bug fixes + auto-rotate cache.
V4.2.0 (Q2 2027) — per-tenant rate limit, ABAC, secret versioning, approval workflow.

Feedback welcome in this thread or as GitHub issues.
```

---

## 8. Status page (status.broker.example.com)

**Component**: Broker Server
**Status**: Operational
**Title**: V4.1.1 released
**Body**:

```
broker V4.1.1 is now available. This is a backward-compatible patch
that fixes a mTLS cert-as-session bug and adds unified error handling
across all 4 official SDKs.

No action required. Existing V4.1.0 installations continue to work.
Upgrade at your convenience following docs/RUNBOOK-v4.1.1.md.

Release: https://github.com/tyj1987/broker/releases/tag/v4.1.1
Migration: https://github.com/tyj1987/broker/blob/v4.1.1/docs/SDK-UPGRADE-GUIDE.md

Affected services: broker server, 4 SDKs (Python / Go / Node CLI / VSCode).
Status: All systems operational.
```

---

## 9. Internal wiki / Confluence

```markdown
# broker V4.1.1 Released — <DATE>

**Audience**: All engineering, security, compliance, ops
**TL;DR**: V4.1.1 is GA. Backward-compatible patch. 4-SDK unified
error contract. 0 vulns. 795 tests.

## What changed for our team

| Team | Impact | Action |
|------|--------|--------|
| Eng | 4 SDK V4.1.1 parity (Python, Go, Node CLI, VSCode) | Review PRs; merge into our services |
| Security | mTLS cert-as-session fix; cert-bypass audit trail | Review docs/SECURITY-CONTROLS-SOC2.md |
| Compliance | SOC 2 / ISO 27001 controls mapping | Confirm V4.1.1 in next evidence collection |
| Ops | Production upgrade path: zero-downtime, 5 min | Schedule for 52trz.com per DEPLOY-52TRZ.md |

## Links

- Release: https://github.com/tyj1987/broker/releases/tag/v4.1.1
- Migration: docs/SDK-UPGRADE-GUIDE.md
- Runbook: docs/RUNBOOK-v4.1.1.md
- Roadmap: ROADMAP-post-1.0.md (13/13 items推进)

## Action items

- [ ] Eng lead: review 4 SDK V4.1.1 PRs
- [ ] Security: review cert-as-session audit trail
- [ ] Compliance: confirm V4.1.1 in SOC 2 evidence
- [ ] Ops: schedule 52trz.com production upgrade
```

---

## 10. Code review checklist (for PR reviewers)

When reviewing the 4 SDK V4.1.1 PRs (Python / Go / Node CLI / VSCode):

- [ ] `BrokerError` constructor: signature compatible with V4.1.0?
- [ ] New fields (`code`, `requestId`, `retryAfter`) optional in constructor?
- [ ] `is_retryable` getter correct (5xx / 429 / connection = true)?
- [ ] `toString()` / `toJSON()` / `toMap()` / `__repr__()` / `to_dict()` correct format?
- [ ] `toJSON()` / `toMap()` omits `body` (security)?
- [ ] `parse_broker_error` / `parseBrokerError` factory handles all body shapes?
- [ ] `mTLSRequest` / `mtlsRequest` retry: only on retryable errors?
- [ ] Backoff curve: 500ms → 1000ms → 2000ms (default)?
- [ ] `Retry-After` header honored (overrides backoff)?
- [ ] `BrokerConnectionError` separate class (always retryable)?
- [ ] Body auto-redacted on `BrokerError` construction (defense in depth)?
- [ ] Tests cover all is_retryable cases (4xx no, 5xx yes, 429 yes, 0 yes)?
- [ ] Tests cover retry exhaustion (4 failures → final error)?
- [ ] No regression in V4.1.0 tests (e.g. existing client.test.ts still passes)?
- [ ] User-Agent / version bumped to 4.1.1?
- [ ] CHANGELOG entry added (or PR description references V4.1.1)?

---

## Reference

- [RELEASE-NOTES-v4.1.1.md](../RELEASE-NOTES-v4.1.1.md) — official release body
- [SDK-UPGRADE-GUIDE.md](SDK-UPGRADE-GUIDE.md) — V4.1.0 → V4.1.1 migration
- [docs/RUNBOOK-v4.1.1.md](RUNBOOK-v4.1.1.md) — 8 步 release manual
- [ERROR-CODES.md](ERROR-CODES.md) — error code reference
- [AWAITING-USER.md V13](../AWAITING-USER.md) — 31 PR + merge order
- [ROADMAP-post-1.0.md](../ROADMAP-post-1.0.md) — 13/13 items status

---

**Document version**: 2026-09-06 (V4.1.1 release prep)
**Audience**: anyone announcing V4.1.1 (maintainer, marketing, eng, security, compliance)
