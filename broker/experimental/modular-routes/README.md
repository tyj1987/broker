# `broker/experimental/modular-routes/` — UNSUPPORTED reference implementations

> **Status: experimental, not wired to production.**
> These handlers were created during Phase B (broker modularization). The
> production request pipeline in `broker/server.js` does **not** dispatch
> through them — every endpoint is served by inline `if (m === … && p === …)`
> blocks or by direct calls to specific handlers in `broker/routes/`
> (currently `health.js`, `static.js`, `metrics.js`, `ssh-proxy.js`).
>
> The dispatcher machinery (`API_HANDLERS`, `dispatch`, `useModularRoutes`,
> `buildRouteDeps`, `routes/index.js`) was removed in chore/oss-modular-security
> because it was never invoked by the production path.

## Why these files still exist

Each handler carries the same auth/audit/scope logic that the inline
`broker/server.js` blocks re-implement, and several of them have peer tests
under `broker-test/test-routes-*.js`. Cutting them would either lose test
coverage for the inline behaviour or force a large refactor of the production
request pipeline. Both are out of scope for the OSS trunk chore.

They are moved here so that:

1. The production-active set (`broker/routes/{health,static,metrics,ssh-proxy}.js`)
   is the only thing the inline request pipeline imports.
2. Anyone exploring the repo can see, in one folder, the historical
   modularization work and the corresponding tests.
3. Future cuts or migrations are obvious — pick a handler, port it to
   `server.js`, delete both the experimental file and the test that
   exercises it.

## How to migrate a handler back into production

If a future change wants to actually wire one of these handlers:

1. **Verify the implementation matches the inline path.** The handler must
   produce the same status code, response body, and audit events as the
   equivalent block in `broker/server.js`. Read both side-by-side first.
2. **Replace the inline block with a direct call** like the SSH proxy
   pattern at `broker/server.js:3078`. Do **not** re-introduce a
   global dispatcher — that is the dead-flag pattern chore/oss-modular-security
   removed.
3. **Add a peer test that exercises both the inline and the handler path
   under the same auth/role/secret fixtures** (see `broker-test/test-routes-auth-me.js`
   for the prior style).
4. **Move the file from `experimental/modular-routes/` to `broker/routes/`**,
   update the import in `server.js`, and delete the corresponding test
   fixture from this folder.
5. **No env flag, no opt-in switch.** A handler that is good enough to
   migrate is good enough to be the only path.

## Files in this folder

| File | Endpoint surface (was) | Test fixture |
|---|---|---|
| `auth.js` | `/api/v1/login`, `/api/v1/logout`, `/api/v1/login/mfa` | `broker-test/test-routes-auth-me.js` (partial) |
| `me.js` | `/api/v1/me` and self-service routes | `broker-test/test-routes-auth-me.js` |
| `secrets.js` | `/api/v1/secrets` (list/get/put/delete) | `broker-test/test-routes-b4.js` |
| `services.js` | `/api/v1/services` (and admin) | `broker-test/test-routes-b4.js` |
| `clients.js` | `/api/v1/admin/clients/*` | `broker-test/test-routes-b4.js` |
| `proxy.js` | `/api/v1/proxy/:service` | `broker-test/test-routes-b4.js` |
| `ops.js` | `/api/v1/ops` | `broker-test/test-phase-f-backup-probes.js` |
| `workload-identity.js` | `/api/v1/workload-identity/*` | (none after chore cut) |

## What this folder is NOT

- It is **not** a stable API surface. Do not import these handlers from
  anywhere outside the test suite.
- It is **not** a compatibility shim. The exports are reference
  implementations, not versioned handlers.
- It is **not** a fallback. There is no `if (useModularRoutes()) …`
  toggle. Production takes the inline path always.

## Threat-model note

`docs/THREAT-MODEL.md` is the source of truth for what paths the broker
serves. None of the experimental handlers introduce new endpoints — they
are alternative implementations of endpoints already present in
`broker/server.js`.
