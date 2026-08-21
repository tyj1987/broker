# Phase B — Modularize `server.js`

**Goal**: shrink the ~140KB monolith without changing runtime behavior or adding npm deps.

## Target layout

```
broker/
  server.js              # thin bootstrap + route dispatch (gradually shrinks)
  lib/
    index.js             # re-exports
    sops.js              # sopsDecrypt / sopsEncryptAtomic
    http.js              # send / readBody / jsonError
    zip.js               # buildZip / computeCrc32
    audit.js             # createAudit()
    rate-limit.js        # createRateLimiter / parseRateLimit
    ip-allowlist.js      # (Phase A)
  routes/                # (Phase B.2+)
    health.js
    auth.js              # login / logout / mfa
    me.js
    api-keys.js          # HTTP handlers (not storage — storage stays api-keys.js)
    secrets.js
    services.js
    clients.js
    proxy.js
    audit-admin.js
    healthcheck.js
```

## Status

| Module | Status |
|--------|--------|
| `lib/sops.js` | ✅ extracted |
| `lib/http.js` | ✅ extracted (uses `BROKER_VERSION`) |
| `lib/zip.js` | ✅ extracted |
| `lib/audit.js` | ✅ extracted |
| `lib/rate-limit.js` | ✅ extracted |
| `lib/ip-allowlist.js` | ✅ Phase A |
| `broker-test/test-lib-phase-b.js` | ✅ |
| `server.js` re-import | ⏳ gradual (see below) |
| `routes/*` | ⏳ Phase B.2 |

## Why not one big server.js rewrite?

- Diff would be unreviewable (~140KB move).
- Risk of subtle breakage in auth / proxy paths.
- Prefer **extract → unit test → rewire imports → delete dead copies**.

## Wiring server.js (Phase B.1 complete path)

After this branch merges, optionally replace inlined helpers with:

```js
import { sopsDecrypt, sopsEncryptAtomic } from './lib/sops.js';
import { send, readBody, jsonError } from './lib/http.js';
import { buildZip } from './lib/zip.js';
import { createAudit } from './lib/audit.js';
import { createRateLimiter } from './lib/rate-limit.js';
import { BROKER_VERSION } from './version.js';
```

Then delete the local function bodies. Keep behavior identical.

## Phase B.2 (next)

Extract route groups into `routes/*.js` that accept a shared `deps` object:

```js
// deps = { CONFIG, SECRET_CACHE, audit, send, getIdentity, ... }
export async function handleMe(req, res, url, ctx, deps) { ... }
```

`server.js` becomes:

```js
if (await tryRoute(handleMe, ...)) return;
```

## Version

Phase B starts at **3.3.0** once modules land and tests pass.
