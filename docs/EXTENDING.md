# Extending Secret Broker

> How to add new secret types, service templates, and audit actions.

This guide is for operators who want to teach their broker about a new provider
(e.g. `hashicorp_vault`, `okta_token`, `kubernetes_secret`) without forking
the repo.

---

## 1. Adding a new Secret type

A "secret type" defines:
- What fields it stores (e.g. `token`, `username`, `password`)
- How to redact it in logs / audit
- How to healthcheck it (optional)
- How to auto-rotate it (optional — most providers require manual)

### Step 1. Add the schema in `broker/lib/type-schemas.js`

```js
export const TYPE_SCHEMAS = {
  // ...existing types...

  my_new_type: {
    label: 'My New Type',
    fields: [
      { name: 'token', label: 'API Token', required: true, secret: true },
      { name: 'region', label: 'Region', required: false },
    ],
    redact_keys: ['token'],
  },
};
```

`secret: true` flags the field so the audit logger never writes its plaintext.
`required: true` enforces presence at validation time.

### Step 2. Add a redact pattern (if your tokens don't match existing patterns)

In `broker/lib/redact.js`, append a new pattern:

```js
{ name: 'my_new_type_token',
  regex: /my_[A-Za-z0-9]{20,}/g,
  replace: 'my_***' },
```

Add a unit test to `broker-test/test-redact.js`.

### Step 3. Add a healthcheck (optional)

In `broker/healthcheck.js`, find the switch on `secret.type` and add:

```js
case 'my_new_type':
  return await checkMyNewType(secret);
```

Implement `checkMyNewType(secret)` to:
1. Make a no-side-effect API call (e.g. `GET /me`)
2. Return `{ status: 'ok'|'expired'|'unreachable'|'misconfigured'|'fail', detail, latency_ms }`

Add tests to `broker-test/test-healthcheck.js`.

### Step 4. Document the new type

In the dashboard, types are auto-discovered via `/api/v1/admin/types`. After
the schema update, the new type appears in the Secrets → New dropdown.

---

## 2. Adding a new Service template

A "service template" defines:
- Upstream URL
- Auth strategy (`bearer`, `header`, `github_token`, `aliyun_v2`)
- Pre-canned actions for the dashboard

### Step 1. Add to `broker/service-templates.js`

```js
export const SERVICE_TEMPLATES = {
  // ...existing templates...

  my_service: {
    label: 'My Service',
    upstream: 'https://api.myservice.com',
    type: 'bearer',
    token_secret: null, // user fills in via Secrets UI
    actions: [
      { label: 'Who am I', method: 'GET', path: '/v1/me' },
      { label: 'List resources', method: 'GET', path: '/v1/resources', query: { limit: 10 } },
    ],
    docs: 'https://docs.myservice.com',
  },
};
```

### Step 2. Test

Add tests to `broker-test/test-service-templates.js` (create if missing):
- Template renders correctly
- Pre-canned actions have valid method/path
- `matchServiceTemplate('my_service')` returns the template

### Step 3. Register in `publicTemplateList` if it should appear in the dashboard

```js
export function publicTemplateList() {
  return Object.entries(SERVICE_TEMPLATES)
    .filter(([k]) => !k.startsWith('_'))
    .map(([k, v]) => ({ key: k, ...v }));
}
```

---

## 3. Adding a custom audit action

Audit actions are free-form strings. To add a new one:

1. Pick a stable name (snake_case, ≤ 32 chars, e.g. `secret_rotated`).
2. Emit it: `audit({ action: 'secret_rotated', cn, secret: name, by: 'admin' })`.
3. Add to `SENSITIVE_ACTIONS` in `broker/lib/risk-score.js` if it should trigger MFA.

---

## 4. Adding a new HTTP route

1. Add a handler in `broker/routes/my-route.js`:
   ```js
   export function handleMyRoute(req, res, route, deps) {
     if (route.method !== 'GET' || route.pathname !== '/api/v1/my-thing') return false;
     // ... do work ...
     send(res, 200, { ok: true });
     return true;
   }
   ```
2. Register in `server.js` dispatch loop:
   ```js
   if (handleMyRoute(req, res, { method, pathname: p }, routeDeps)) return;
   ```
3. Add to `OpenAPI` spec (`broker/lib/openapi-spec.js`).
4. Add tests to `broker-test/test-routes-*.js`.

---

## 5. Conventions

- **One handler per file** in `broker/routes/`.
- **Handlers return `true` if handled, `false` to fall through** (lets static /
  metrics / health handle their own paths).
- **Always call `send()` or `jsonError()`** — never `res.end()` directly (you'd
  skip security headers).
- **Always audit sensitive ops** with `audit({ action: '...' })`. Make audit
  mandatory for compliance-critical ops: `audit({ action: 'login', mandatory: true })`.
- **Test names**: `test-<module>-<aspect>.js` (e.g. `test-can-proxy-policy-engine.js`).

---

## 6. Verification checklist before opening a PR

```bash
npm run test:v4           # all V4 unit tests
npm run test:v4-modules   # new V4.1 modules
npm run test:python-sdk   # Python SDK tests
npm run lint              # ESLint
npm run format:check      # Prettier
```

CI runs all of the above + `test:verify-all`. Local pre-commit runs ESLint +
Prettier on staged files.
