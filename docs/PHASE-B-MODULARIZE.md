# Phase B — Modularize `server.js`

**Goal**: shrink the ~140KB monolith without changing runtime behavior or adding npm deps.

## Layout

```
broker/
  server.js                 # still owns full runtime until cutover
  lib/                      # pure helpers
  routes/
    health.js / static.js   # public
    auth.js / me.js         # session flows
    secrets.js              # B.4
    services.js             # B.4
    clients.js              # B.4
    proxy.js                # B.4
    index.js
```

## Status

| Item | Status |
|------|--------|
| lib/* | ✅ |
| routes health/static/auth/me | ✅ |
| routes secrets/services/clients/proxy | ✅ B.4 (deps-injected surfaces) |
| `apply-phase-b2-server-wire.mjs` | ✅ Phase A + public routes |
| `apply-phase-b4-server-wire.mjs` | ✅ expands route imports |
| Full cutover (delete legacy blocks) | ⏳ after production smoke |

## Tests

```bash
node broker-test/test-lib-phase-b.js
node broker-test/test-routes-phase-b2.js
node broker-test/test-routes-auth-me.js
node broker-test/test-routes-b4.js
node broker-test/test-ip-allowlist.js
```

## Wire order

```bash
node scripts/broker/apply-phase-b2-server-wire.mjs
node scripts/broker/apply-phase-b4-server-wire.mjs
```

B.4 modules are **safe dual-path**: they implement the same handler contract but are not the sole runtime path until you replace legacy `if (m === ...)` blocks with `dispatch([...])`.

## Handler contract

```js
export async function handleX(req, res, route, deps) {
  // return true if handled
}
```

Admin mutations require `ctx.client.role === 'admin'`. Proxy uses `deps.proxyRequest` + optional `canProxy`.

## Next (B.5 / cutover)

1. Production smoke with dual-path
2. Replace legacy route blocks in `server.js` with `dispatch`
3. Delete dead inlined helpers already in `lib/`
4. Bump version + CHANGELOG when cutover lands
