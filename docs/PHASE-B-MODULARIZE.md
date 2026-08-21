# Phase B — Modularize `server.js`

**Goal**: shrink the ~140KB monolith without changing runtime behavior or adding npm deps.

## Target layout

```
broker/
  server.js              # thin bootstrap + route dispatch (gradually shrinks)
  lib/
    index.js
    sops.js / http.js / zip.js / audit.js / rate-limit.js / ip-allowlist.js
    session.js           # Phase B.2
  routes/
    index.js             # dispatch()
    health.js            # GET /health
    static.js            # dashboard assets
    auth.js / me.js / ...  (next)
```

## Status

| Item | Status |
|------|--------|
| lib/* (B.1) | ✅ merged |
| `lib/session.js` | ✅ B.2 |
| `routes/health.js` | ✅ B.2 |
| `routes/static.js` | ✅ B.2 |
| `routes/index.js` + `dispatch` | ✅ B.2 |
| `scripts/broker/apply-phase-b2-server-wire.mjs` | ✅ Phase A+B.2 surgical wire |
| `broker-test/test-routes-phase-b2.js` | ✅ |
| Full body deletion of inlined helpers | ⏳ after wire proven |
| routes: auth / me / secrets / … | ⏳ B.3 |

## Apply wire (repo root)

```bash
node scripts/broker/apply-phase-b2-server-wire.mjs
node broker-test/test-lib-phase-b.js
node broker-test/test-routes-phase-b2.js
node broker-test/test-ip-allowlist.js
```

The wire script is **idempotent**. It:

1. Imports `BROKER_VERSION`, `isClientIpAllowed`, lib http/zip, routes
2. Fixes version banner / headers / health / User-Agent
3. Cert issue default 90d
4. API Key IP allowlist enforcement
5. Removes dead `return` in secrets list
6. Early-dispatches `handleHealth` + `handleStatic` before legacy blocks

## Route handler contract

```js
/**
 * @returns {boolean|Promise<boolean>} true if request was handled
 */
export function handleX(req, res, route, deps) { ... }

// route = { method, pathname }
// deps  = { send, config, secretCache, version, dashboardDir, ... }
```

## Phase B.3 (next)

- `routes/auth.js` — login / mfa / logout
- `routes/me.js` — self-service
- `lib` body removal: delete inlined `send`/`sops*`/`buildZip` once imports proven
- Keep zero new npm deps

## Version

- B.1 modules: **3.3.0**
- B.2 routes skeleton: stay on **3.3.0** (patch docs only) until server.js is fully rewired in production
