# Phase B.5 — Modular cutover

## Goal

Prefer `broker/routes/*` + `broker/lib/*` without a risky one-shot rewrite of the 140KB `server.js`.

## Strategy: opt-in dual-path

1. **Always**: unit tests for lib + routes (no server process required).
2. **Wire scripts** (idempotent): import modules, version, IP allowlist, public health/static.
3. **Runtime flag**: `USE_MODULAR_ROUTES=1` marks intent; expand dispatch as deps become complete.
4. **Final cutover**: delete legacy `if (m === …)` blocks only after smoke on a non-prod instance.

## Version

**3.4.0** — modular surface complete (lib + routes for health/static/auth/me/secrets/services/clients/proxy).

## Checklist

### Local

```bash
git pull origin master
cd broker && npm run test:modular

# Wire (once)
node ../scripts/broker/apply-phase-b2-server-wire.mjs
node ../scripts/broker/apply-phase-b4-server-wire.mjs
node ../scripts/broker/apply-phase-b5-cutover.mjs

# Smoke without modular flag (legacy path)
node server.js

# Smoke with flag (public modular path)
USE_MODULAR_ROUTES=1 node server.js
curl -k https://127.0.0.1:8443/health
```

### Commit wire result

```bash
git add broker/server.js
git commit -m "wire: Phase A–B.5 server.js imports + public modular routes"
git push
```

### Production cutover (later)

1. Deploy 3.4.0 with **flag off** — behavior identical to pre-modular.
2. Enable `USE_MODULAR_ROUTES=1` on standby; compare `/health` + login + one proxy call.
3. Promote flag; monitor audit JSONL.
4. PR: remove dead inlined `send`/`sops*`/`buildZip` bodies and unused legacy branches.
5. Tag release.

## Files

| Path | Role |
|------|------|
| `broker/lib/*` | helpers |
| `broker/lib/build-route-deps.js` | deps assembler + `useModularRoutes()` |
| `broker/routes/*` | handlers |
| `scripts/broker/apply-phase-b*.mjs` | surgical wire |
| `broker-test/test-*.js` | regression |

## Rollback

Unset `USE_MODULAR_ROUTES` or remove modular early-return blocks; legacy handlers remain until explicitly deleted.
