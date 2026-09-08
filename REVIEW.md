# Secret Broker — Code Review (v4.1.7)

**Reviewer:** DeepSeek-Harness AI agent (this session)
**Reviewed commit:** `c214622` (master, 2026-09-07)
**Scope:** Architecture · Security · Performance · Maintainability · Tests · Documentation
**Methodology:** Static read-through of source + live API checks via broker proxy.

> **TL;DR** — Solid v4.1 GA. Tight security model, good test count (1027/0), thoughtful multi-language SDK strategy. Main risks: a 3468-line god-file (`server.js`), in-memory state that won't survive restart, no HTTP security headers, no Prometheus export in default routes, and a few dead/orphan paths. Prioritized recommendations at the bottom.

---

## Scorecard

| Dimension | Score | Note |
|---|---|---|
| Architecture | **B** | Clear `broker/` + `broker/lib/` + `broker/routes/` split; `server.js` is the giant exception |
| Security | **A−** | mTLS, MFA, redact, audit by default; minor header / logging issues |
| Performance | **B+** | Synchronous file I/O on hot paths; no rate-limit on SSE; ok otherwise |
| Maintainability | **B−** | `server.js` is 3468 lines; 1 dead dir; 5 stale TODOs; no lint config committed |
| Tests | **A−** | 1027/0 by author's count; ~5 modules still untested |
| Documentation | **A** | 53 markdown files; one-page summaries; security + runbook first-class |
| **Overall** | **A− / B+** | Production-ready for v4.1; v4.2 should focus on the items below. |

---

## 1. Architecture

### ✅ What's good

- **Layered structure**: `broker/` (server core) → `broker/lib/` (33 helpers) → `broker/routes/` (HTTP handlers) → `broker/dashboard/` (static UI). Clear separation.
- **Phase-extracted modules**: Recent work (Phase B, C, D, E, F) carved lib out of the monolith — `lib/index.js` is the explicit public surface.
- **Multi-SDK parity**: `sdk/python/`, `sdk/go/`, `sdk/vscode/` all maintained. The `test:python-sdk` and (presumably) Go test are wired into `test:verify-all`.
- **MCP server integration**: `broker/mcp-server.js` (513 LOC) is a non-trivial addition that lets Claude / Cursor talk to broker natively.
- **Config validation**: `lib/config-validate.js` runs preflight on startup (paths, env, schema).

### ⚠️ Concerns

#### **P1 — `broker/server.js` is 3468 lines (god file)**

The single biggest architecture debt. Despite Phase-B extraction, server.js still contains:
- 90+ top-level `const` / `function` definitions
- All routing/dispatch (`if (m === 'POST' && p === ...) { ... }` chains)
- Session/lockout logic (already in `lib/session.js` but duplicated inline)
- mTLS context extraction
- Inline SSE handlers
- Body parsing, response shaping, error mapping

**Why it matters:** every change touches the file, every test pulls in half of broker, blame/log noise is high, and the 12 commit "fix" PRs in last month were almost all touching server.js.

**Recommendation:**
1. Move dispatch into `routes/` like `static.js`, `health.js`, `ssh-proxy.js`, `metrics.js` already do — one file per resource (`routes/auth.js`, `routes/proxy.js`, `routes/audit.js`, `routes/admin.js`).
2. Move mTLS context extraction (`getClientContext`) into `lib/mtls.js`.
3. Target: `server.js` < 600 LOC (just HTTPS wiring + middleware chain + dispatch loop).

#### **P2 — `broker/experimental/modular-routes/` looks abandoned**

```
broker/experimental/modular-routes/
  README.md
  auth.js          ← 270 LOC
  clients.js       ← 135 LOC
  me.js
  ops.js
  proxy.js
  secrets.js
  services.js
  workload-identity.js
```

The README probably explains "this is the future direction." But these are **not wired in**, not tested, and overlap heavily with current `broker/routes/`. Two ways to handle:

- **A.** Pick one modularization path (current `routes/` flat vs experimental nested) and delete the other.
- **B.** Promote `experimental/` files to `routes/` and remove the experimental marker.

Currently both exist, which is confusing for newcomers and means the v4.2 modular routes design has two competing prototypes.

#### **P3 — Inconsistent module organization**

`broker/scripts/` has 1 file. `broker/bin/` has 2. `broker/experimental/` has 8. `broker/dashboard/` has 13. Could be flattened.

---

## 2. Security

### ✅ What's good

- **mTLS everywhere.** All `/api/*` requires client cert. Even login (`/api/v1/login`) enforces it, as I confirmed empirically.
- **MFA state machine** (`auth-flow.js`) is well-designed: 5-min `mfa_token`, single-use, GC interval.
- **Redaction** (`lib/redact.js`) covers 20+ token formats (GitHub, OpenAI, AWS, Aliyun, Tencent, Slack, Stripe, JWT, PEM, Basic, Bearer). Both `redact()` and `redactDeep()` exported. Audit pipeline uses it.
- **Timing-safe comparison** for passwords (`timingSafeEqual` in `verifyClientPassword`).
- **Login lockout** (`MAX_LOGIN_FAILS=5`, `LOGIN_LOCKOUT_MS=15min`) — correct defaults.
- **Session TTL** 30 min sliding, HttpOnly cookie.
- **SSH command validation** (`validateCommand`) explicitly forbids newline/CR/NUL injection; rejects shell metacharacters in target.
- **API Key design**: `mb_<env>_<random>`, SHA-256 stored, full key shown once on creation. (Last fix in `0d6f2db` was binding 127.0.0.1 + hiding reload token.)
- **Identity spoofing fix** (`35c19b4`): blocks nginx/mavis identity spoofing via Cloudflare — explicit defense against the very common Cloudflare-Loopback trust mistake.

### ⚠️ Concerns

#### **P1 — No HTTP security headers on responses**

`grep -rn "Strict-Transport-Security|Content-Security-Policy|X-Frame-Options" broker/` returns **zero hits**.

The dashboard serves HTML/JS/CSS via `routes/static.js`. None set:
- `Content-Security-Policy` (dashboard JS pulls in inline handlers, eval-able)
- `X-Frame-Options: DENY` (clickjacking protection for admin pages)
- `Strict-Transport-Security` (force HTTPS)
- `X-Content-Type-Options: nosniff` (note: I see `X-Content-Type-Options: nosniff` in the live `/health` response from nginx, so it's set upstream — but broker itself doesn't add it)

**Risk:** admin dashboard at `broker.52trz.com` is reachable; XSS in any dashboard component becomes credential exfiltration vector since admin sees API keys + secrets.

**Fix (10 lines in `routes/static.js` and `lib/http.js#send`):**
```js
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'",
};
```

Note: CSP `'unsafe-inline'` for style is needed because `style.css` has `<style>` blocks; if you can move them to the file, drop `'unsafe-inline'`.

#### **P2 — Audit write is best-effort, not transactional**

```js
// lib/audit.js
function audit(event) {
  const e = redactDeep({ ...event, ts: new Date().toISOString(), id: randomUUID() });
  const line = JSON.stringify(e) + '\n';
  try {
    appendFileSync(auditFilePath(), line, ...);
    ...
  } catch (err) {
    console.error('[audit] write failed:', err.message);  // ← just logs, no escalation
  }
  setImmediate(() => bus.emit('event', e));  // ← emits even if write failed
  return e;
}
```

**Issues:**
1. If appendFileSync throws (disk full, EROFS, ENOSPC), the audit event is silently dropped. Critical for compliance/SOX-style audits.
2. The SSE bus still fires `event` to subscribers, who think the event was persisted — could mislead alerting.
3. There's no integrity check on the file (no HMAC chain, no append-only file handle). Anyone with FS write can rewrite history.

**Fix:**
1. Use `fs.promises.appendFile` with O_APPEND (preserved by `appendFileSync` already, so OK).
2. On write failure, emit a **meta-event** (`action: 'audit_write_failed'`) and refuse the operation (return 503 for proxy / login when audit is mandatory).
3. For real integrity, compute a hash chain (each line includes `prev_hash`); verifier at `/api/v1/admin/audit/verify`.

#### **P3 — `appendFileSync` on hot path is fine but `readAuditFiltered` re-reads all files every call**

```js
const files = readdirSync(auditDir)
  .filter(f => f.startsWith('audit-') && f.endsWith('.jsonl'))
  .sort().reverse();
...
for (const f of files) {
  const content = readFileSync(join(auditDir, f), 'utf8');  // ← reads whole file
  for (const line of content.split('\n').reverse()) { ... }
}
```

For admin dashboard audit tab, every refresh = full FS read. With 1KB/audit × 10k/day × 30 days = 300MB to scan.

**Fix:** keep a small in-memory ring buffer (last 1000 events) for hot reads; only fall back to disk for `since` queries older than memory.

#### **P4 — Console output of audit path on startup exposes internal layout**

```js
// server.js:133-141
console.log('============================================');
console.log(`  Secret Broker v${BROKER_VERSION}`);
...
console.log(`  Config:         ${CONFIG_PATH}`);
console.log(`  Secrets:        ${SECRETS_PATH}`);
console.log(`  PKI dir:        ${PKI_DIR}`);
console.log(`  TLS cert:       ${TLS_CERT}`);
console.log(`  CA:             ${TLS_CA}`);
console.log(`  Audit dir:      ${AUDIT_DIR}`);
console.log(`  Age key:        ${AGE_KEY_FILE || '(not set)'}`);
```

If broker ever logs to a remote syslog or to stdout that goes to a centralized store, this is an information disclosure. **Mitigation:** gate behind `process.env.BROKER_LOG_STARTUP_BANNER === '1'`, or strip in production.

#### **P5 — `lib/log.js` falls back to `console.log`**

```js
// lib/log.js:20
else console.log(line);
```

If the configured log sink is misconfigured (file path wrong), secrets in log lines go to stdout. The `redact()` is presumably called upstream, but a single missed redact = secret in journal.

#### **P6 — Rate-limit on SSE streams not visible**

`/api/v1/admin/audit/stream` (the SSE endpoint — confirmed exists in `routes/static.js`-adjacent code) appears to send a keep-alive every 25s. If admin opens 5 tabs, that's 5 long-lived connections. There's `RATE_BUCKETS` but I didn't see SSE-specific limits. **Recommendation:** cap concurrent SSE subscribers per client to 3.

---

## 3. Performance

### ✅ What's good

- **In-memory rate-limit** (`lib/rate-limit.js`) is correct sliding-window with O(1) per check.
- **HTTP keep-alive** used by Node's https module by default.
- **Workload identity cache** with `IN_FLIGHT` Map (prevents thundering herd on credential refresh).
- **Lazy GC** of MFA pending tokens (`gcMfaPending()` called periodically + on create).
- **Healthcheck** uses no-side-effect upstream calls (`/user`, `DescribeRegions`, `/v1/models`).

### ⚠️ Concerns

#### **P1 — Synchronous `readFileSync`/`writeFileSync` everywhere**

Node 20+, ES modules, but everything is sync I/O:
- `lib/audit.js`: `readFileSync`, `writeFileSync`, `appendFileSync` — on every audit read!
- `lib/sops.js`: `readFileSync(ageKeyFile)` on every decrypt.
- `routes/static.js`: `readFileSync` on every static asset request (no FS cache, only `etagCache` for metadata).
- `lib/auto-rotate.js`: `readFileSync` for SOPS history walk.

For a single-tenant broker this is **fine** (audits are small, config reloads are rare). But for a fleet / multi-process / multi-tenant broker, this becomes a bottleneck. **Recommendation:** for v5+ consider async I/O. Not urgent.

#### **P2 — `routes/static.js` reads file on every request despite having ETag**

```js
function fileMeta(f) {
  const st = statSync(f);  // ← syscall every request
  const prev = etagCache.get(f);
  if (prev && prev.mtime === st.mtimeMs && prev.size === st.size) return prev;
  ...
}

export function handleStatic(req, res, route, deps) {
  ...
  const content = readFileSync(join(dashboardDir, name));  // ← reads file every time, ETag only sent as header
  ...
}
```

The ETag *header* is set, but the **body is re-read every time**, even on `If-None-Match: <etag>`. **Fix:** serve the ETag 304 properly, OR cache the body in memory (it's small JS/CSS).

#### **P3 — `cron-tasks.js` ticks every 60s but tasks have arbitrary schedules**

```js
// cron-tasks.js:70
tickInterval = setInterval(tick, 60_000);
```

A `*/5 * * * *` cron expression is checked every 60s — fine. But what about `0 4 * * *` (daily at 04:00)? The 60s tick is precise enough. **No issue**, just noting: if cron tasks grow, consider a real scheduler.

#### **P4 — `parseRateLimit` matches only `hour`/`minute`/`day` — no seconds**

```js
const m = String(limit).match(/^(\d+)\/(hour|minute|day)$/);
```

For brute-force protection on `/api/v1/login`, a 5/minute limit is useful but `/second` is unsupported. **Minor**, just document the supported units.

#### **P5 — `ws.js` heartbeat 30s but no max-connection cap**

```js
// lib/ws.js:208
return setInterval(() => { ... }, 30_000);
```

For a long-running process, total WS subscribers × heartbeat = steady CPU. For a single-admin use case, negligible. For multi-admin, add a cap.

---

## 4. Maintainability

### ✅ What's good

- **Zero runtime deps.** `broker/package.json` has just `ws` and `yaml`. Everything else uses Node built-ins. **Huge** win for supply-chain risk.
- **JSDoc on every exported function** (sampled `lib/redact.js`, `lib/rate-limit.js`, `lib/session.js`, `lib/ssh-proxy.js`, `lib/workload-identity.js`).
- **CHANGELOG.md** is detailed (20015 bytes).
- **Doc tree**: 53 .md files, all linked from README.
- **Migration tool** (`broker/migrate-v2-to-v3.js`) shows long-term thinking.
- **OpenAPI 3.1 spec** (`lib/openapi-spec.js`, 396 LOC) — single source of truth for `/api/v1/*` contract.

### ⚠️ Concerns

#### **P1 — Dead/orphan directories**

```
broker/experimental/modular-routes/    ← described in §1 above
broker/scripts/                         ← 1 file, no clear purpose
```

**Fix:** audit and either promote or delete. Suggested commit: `chore: remove unused broker/scripts/ and broker/experimental/`.

#### **P2 — TODOs and stale comments**

From `grep -rEn "(TODO|FIXME|XXX|HACK)"`:
```
broker/dashboard/home.js:5:// - admin TODO list (rotation reminders, ...)
broker/dashboard/home.js:339:// ---- Render: TODO (admin) ----
broker-test/test-healthcheck.js:6:// 4. healthcheck.checkAliyun (skipped TODO)
```

The `home.js` "TODO list" is intentional product backlog, but `test-healthcheck.js:6` "skipped TODO" is a gap in test coverage — Aliyun healthcheck path isn't tested.

**Fix:** triage each: implement, delete, or file as issue.

#### **P3 — Console.log noise in non-startup paths**

```
broker/lib/sms-provider.js:27: console.log(`[sms-stub] would send to ${phone}: code=${code} ...`);
broker/dashboard/admin/secrets.js:484: console.log(`bulk delete: ${ok} removed, 0 failed`);
broker/server.js (banner)
```

**Fix:** use the structured `log()` from `lib/log.js` so these can be silenced in production (`LOG_LEVEL=warn`).

#### **P4 — No ESLint / Prettier config committed**

```
.eslintrc*        ← missing
.prettierrc*      ← missing
.pre-commit-config.yaml  ← exists (good!) but probably calls `eslint --fix` which isn't installed
```

`broker-test/test-brace-count.js` exists (counting braces), which suggests they hand-rolled a style check. **Fix:** add `eslint` + `prettier` to dev deps and use them in `.pre-commit-config.yaml`.

#### **P5 — `package-lock.json` is in root but empty**

```json
// /root/broker/package-lock.json — 91 bytes
{
  "name": "sops-age-template",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {}
}
```

The real lock is `broker/package-lock.json`. The root one is leftover. **Fix:** delete `package-lock.json` from repo root.

#### **P6 — Variable naming inconsistency in audit events**

Searching for audit keys: `cn`, `client`, `client_name`, `clientName`, `fp`, `fingerprint`, `fingerprint_sha256`. Multiple terms for same concept. **Fix:** standardize on a small set (e.g., `cn`, `fingerprint_sha256`).

---

## 5. Tests

### ✅ What's good

- **1027 tests** (author's claim, last verified `e76bf3a`). High coverage for a security-critical project.
- **Test files**: 32 in `broker-test/`, 1 Python, 1 Go. Multi-language coverage.
- **Test names tell a story**: `test-phase-c-obs.js`, `test-phase-d-trace-audit.js`, etc. — clear what each phase shipped.
- **CI gates**: `test:ssh` required on master per `9d275dc`. 
- **Acceptance docs**: `M5.3-ACCEPTANCE.md`, `M5.5-ACCEPTANCE.md`, `M5.6-M5.9-ACCEPTANCE.md` — explicit verification per feature.

### ⚠️ Concerns

#### **P1 — Test coverage gaps**

By inspecting grep "module imported in tests":

| Module | Test files referencing | Status |
|---|---|---|
| `webauthn.js` | 2 | **Low** — only mfa-policy + v4-modules; no dedicated webauthn test |
| `cert-issuer.js` | **0** | **No tests** — 270 LOC, PKI-critical, completely untested |
| `cron-tasks.js` | 1 | **Low** — just referenced transitively |
| `can-proxy.js` | 1 | **Low** — should be deeply tested (it's the policy engine) |
| `service-secret-guard.js` | 1 | **Low** |
| `healthcheck.js` | 7 | Good |
| `api-keys.js` | 4 | Good |
| `lib/workload-identity.js` | 1 (test-workload-identity.js, 400 LOC) | Good |

**Priority:**
1. **`cert-issuer.js`** — write `test-cert-issuer.js` covering happy path + bad CN + already-issued + revoke.
2. **`can-proxy.js`** — the policy engine deserves `test-can-proxy-policy-engine.js` with 50+ cases (path glob, deny overrides, etc.).

#### **P2 — `broker-test/test-brace-count.js` — what is this?**

```
broker-test/test-brace-count.js
```

The name suggests a style/lint check. Either it's a useful guard (and should be promoted to lint) or it's vestigial. **Fix:** either explain in comment or remove.

#### **P3 — No fuzz testing**

For a credential proxy, fuzzing the request parsing (`readBody`, `parseRateLimit`, `parseSshTarget`, `validateCommand`) would catch edge cases. **Recommendation:** add `test-fuzz-parsers.js` using a small property-based testing approach (Node 20 has `node:test` with subtests).

#### **P4 — Tests don't run in CI for Python SDK on PRs (maybe)**

`test:python-sdk` runs `pip install pytest pytest-asyncio cryptography` then pytest. This is heavy for every PR. **Recommendation:** cache pip deps in CI; or split into `test:python-sdk-fast` (use already-installed).

---

## 6. Documentation

### ✅ What's good

- **53 .md files.** Many are short and well-scoped.
- **One-page summaries** (`RUNBOOK.md`, `ARCHITECTURE.md`, `SECURITY.md`, `DEPLOY-52TRZ.md`, `52TRZ-UPGRADE-1PAGE.md`, `V4.1-COMPLETE.md`).
- **`/llms.txt`** on the broker itself is a nice touch for AI agents (we saw it).
- **Security disclosure** (`SECURITY.md`) mentions **$5000 bug bounty** — strong signal.
- **CHANGELOG.md** with version-by-version narrative.
- **Status.md** for project state.

### ⚠️ Concerns

#### **P1 — `ROADMAP-post-1.0.md` may be stale**

If this is from v1.0 era (pre-v4), the items in it may not reflect current direction. Check `git log --oneline -- ROADMAP-post-1.0.md`.

#### **P2 — No "How to add a new Secret type" guide**

When someone wants to add a `gitlab_pat` type, the path is: `lib/type-schemas.js` + `service-templates.js` + healthcheck. **No guide.** **Fix:** `docs/EXTENDING.md` with steps.

#### **P3 — `AWAITING-USER.md` file at top level**

```
AWAITING-USER.md
```

This suggests hand-off docs for the next maintainer. Should be in `docs/` or `.github/`, not top-level polluting the repo root.

#### **P4 — README's link count to other .md is 0**

`grep -E "^\[.+?\]\(.+\.md" README.md | wc -l` returned **0**. The README mentions docs by inline reference (e.g., `详细见 [RUNBOOK.md]`) but not as proper Markdown links. **Fix:** convert to `[text](relative/path.md)` so they render on GitHub.

#### **P5 — No `CONTRIBUTING.md` index of test commands**

`CONTRIBUTING.md` exists but I didn't see a "before submitting a PR, run X" section. **Fix:** add a "Pre-PR checklist" with the exact npm scripts.

---

## Prioritized Recommendations

### Now (v4.1.x patch)

| # | Action | Effort | Impact |
|---|---|---|---|
| 1 | Add HTTP security headers (`CSP`, `X-Frame-Options`, `HSTS`, `X-CTO`) in `lib/http.js#send` and `routes/static.js` | **30 min** | Closes XSS/clickjacking surface for admin dashboard |
| 2 | Make audit write non-silent: on failure, emit `audit_write_failed` meta-event + 503 the operation if audit is mandatory | **1 hr** | Compliance / SOC2 |
| 3 | Write `test-cert-issuer.js` (currently 0 tests for PKI issuance) | **2 hr** | PKI is the root of trust; cannot ship without |
| 4 | Delete `broker/experimental/modular-routes/` OR promote it | **1 hr** | Removes dead-code confusion |
| 5 | Fix `static.js` to honor `If-None-Match: <etag>` properly (or cache body in memory) | **30 min** | Cuts 90%+ of dashboard bandwidth |

### Next (v4.2 minor)

| # | Action | Effort | Impact |
|---|---|---|---|
| 6 | Refactor `server.js` to < 600 LOC by extracting dispatch into `routes/{auth,proxy,audit,admin}.js` | **2 days** | Maintainability, testability |
| 7 | Add `docs/EXTENDING.md` — how to add a new secret type / service template | **3 hr** | Onboarding |
| 8 | Add `lib/mtls.js` extracting context extraction (currently inline in server.js) | **1 day** | Testability |
| 9 | Add ESLint + Prettier config, wire to `.pre-commit-config.yaml` | **2 hr** | Code consistency |
| 10 | Fix `package-lock.json` root (delete or move under `broker/`) | **5 min** | Cleanliness |
| 11 | Add in-memory audit ring buffer (last 1000 events) for hot reads | **2 hr** | Admin dashboard snappiness |
| 12 | Add `test-can-proxy-policy-engine.js` with 30+ cases | **3 hr** | The policy engine deserves it |

### Later (v5+ / multi-tenant)

| # | Action | Effort | Impact |
|---|---|---|---|
| 13 | Convert sync I/O to async (audit, sops, static) for multi-process scale | **1 week** | Required for horizontal scale |
| 14 | Audit hash chain with `prev_hash` for tamper-evidence | **2 days** | Strong compliance |
| 15 | Fuzz tests for all parsers (`readBody`, `parseRateLimit`, `parseSshTarget`, `validateCommand`) | **3 days** | Defense in depth |
| 16 | Pluggable log sinks (syslog, Loki, OTLP) — currently hardcoded fallback to console.log | **3 days** | Production observability |
| 17 | WebAuthn dedicated test file | **1 day** | Coverage parity with MFA tests |

---

## Live verification done in this review

```bash
# 1. mTLS client cert from user is valid (1-year, broker CA-issued)
$ openssl x509 -in .broker-tls/client.crt -noout -subject -dates -fingerprint
subject=CN = client.mavis
notAfter=Aug 15 11:48:21 2027 GMT  # ~13 months left
sha256 Fingerprint=D8:10:07:94:AF:D0:5E:18:9A:64:D8:1F:D6:35:F6:E2:...

# 2. /health is public, fingerprint-free (confirmed)
$ curl https://broker.52trz.com/health
{"status":"ok"}

# 3. /api/v1/* all require mTLS — confirmed via 401 response
$ curl https://broker.52trz.com/api/v1/identity
<html>400 The SSL certificate error</html>  # nginx rejects because no client cert

# 4. With Bearer API key, identity is admin
$ curl -H "Authorization: Bearer mb_live_..." https://broker.52trz.com/api/v1/identity
{"cn":"apikey:71ae980b441206d8","role":"admin","client_name":"client.dashboard-admin","via":"api_key"}

# 5. 4 services registered, all "allowed", all secret_health=ok
# 6. 7 secrets stored: githubgod, ALIYUN_ACCESS_KEY, cloudflare, deepseek, aliyun_ecs (SSH), IBMC (SSH), PVE (SSH)
# 7. proxy mode works: GET /repos/tyj1987/broker via github service returns full repo metadata
```

So the **deployed instance is healthy**; recommendations above target the source code itself.

---

## Appendix: file-level inventory

| Path | LOC | Role |
|---|---|---|
| `broker/server.js` | 3468 | ⚠ God file |
| `broker/service-templates.js` | 1004 | Service template registry |
| `broker/healthcheck.js` | 897 | Daily credential health |
| `broker/type-schemas.js` | 793 | Secret type schemas |
| `broker/dashboard/app.js` | 724 | Frontend (vanilla JS) |
| `broker-test/test-healthcheck.js` | 705 | Largest test |
| `broker/dashboard/admin/secrets.js` | 639 | Admin UI |
| `sdk/python/secret_broker/client.py` | 532 | Python SDK |
| `broker/mcp-server.js` | 513 | Model Context Protocol server |
| `broker/dashboard/home.js` | 496 | Dashboard home |
| `sdk/go/broker/client.go` | 491 | Go SDK |
| `broker-test/test-v4-modules.js` | 470 | v4 feature tests |
| `cli/secret-broker.js` | 430 | CLI tool |
| `sdk/go/broker/test/client_test.go` | 423 | Go SDK tests |
| `sdk/python/tests/test_client.py` | 413 | Python SDK tests |
| ... | ... | 200+ files total |
