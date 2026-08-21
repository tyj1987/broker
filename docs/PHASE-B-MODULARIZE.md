# Phase B — Modularize `server.js`

**Goal**: shrink the ~140KB monolith without changing runtime behavior or adding npm deps.

## Status (B.5)

| Item | Status |
|------|--------|
| lib helpers | ✅ |
| routes public + auth/me + admin/proxy | ✅ |
| `buildRouteDeps` / `useModularRoutes` | ✅ B.5 |
| `PUBLIC_HANDLERS` / `API_HANDLERS` | ✅ |
| Version **3.4.0** | ✅ modular surface complete |
| Legacy body deletion | ⏳ after prod smoke |

See **[PHASE-B5-CUTOVER.md](./PHASE-B5-CUTOVER.md)** for the opt-in cutover checklist.

## Tests

```bash
cd broker && npm run test:modular
```

## Wire

```bash
node scripts/broker/apply-phase-b2-server-wire.mjs
node scripts/broker/apply-phase-b4-server-wire.mjs
node scripts/broker/apply-phase-b5-cutover.mjs
```
