# Phase B — Modularize `server.js`

**Goal**: shrink the ~140KB monolith without changing runtime behavior or adding npm deps.

## Layout

```
broker/
  server.js
  lib/          # pure helpers (sops, http, zip, audit, rate-limit, session, ip-allowlist)
  routes/
    health.js / static.js     # B.2 public
    auth.js                   # B.3 login / mfa / logout
    me.js                     # B.3 GET /me (+ recovery remaining)
    index.js                  # dispatch()
```

## Status

| Item | Status |
|------|--------|
| lib/* B.1 | ✅ |
| routes health/static B.2 | ✅ |
| `lib/session.js` | ✅ |
| `routes/auth.js` | ✅ B.3 (deps-injected; mirror of server login paths) |
| `routes/me.js` | ✅ B.3 (GET /me + recovery remaining) |
| `test-routes-auth-me.js` | ✅ |
| server.js full cutover | ⏳ run wire scripts + optional early dispatch for auth/me |
| routes: secrets/services/clients/proxy | ⏳ B.4 |

## Tests

```bash
node broker-test/test-lib-phase-b.js
node broker-test/test-routes-phase-b2.js
node broker-test/test-routes-auth-me.js
node broker-test/test-ip-allowlist.js
node scripts/broker/apply-phase-b2-server-wire.mjs   # if server.js not wired yet
```

## Handler contract

```js
export async function handleX(req, res, route, deps) {
  // return true if handled
}
```

Auth/me handlers expect a rich `deps` object (send, audit, config, MFA helpers, session store).
`server.js` remains source of truth for wiring until early-dispatch is expanded.

## Phase B.4 (next)

- `routes/secrets.js`, `routes/services.js`, `routes/clients.js`, `routes/proxy.js`
- Expand wire script to dispatch auth/me before legacy blocks
- Delete duplicated inlined bodies after green production smoke
