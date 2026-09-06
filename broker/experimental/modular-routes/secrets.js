// broker/routes/secrets.js — secret list / get / put / delete (handler surface)
// Phase B.4: deps-injected. Full cutover after wire + smoke.
//
// Expected deps:
//   send, jsonError, readBody, audit, ctx, config, secretCache
//   sopsEncryptAtomic, persistConfig?, requireRole / requireScope helpers
//   canAccessSecret(name, ctx) -> boolean

function requireAuth(ctx, res, jsonError) {
  if (!ctx || !ctx.client) {
    jsonError(res, 401, 'Authentication required');
    return false;
  }
  return true;
}

/**
 * @returns {Promise<boolean>}
 */
export async function handleSecrets(req, res, route, deps) {
  const { method, pathname: p } = route;
  if (!p.startsWith('/api/v1/secrets')) return false;

  const {
    send, jsonError, readBody, audit, ctx, config, secretCache,
    canAccessSecret, sopsEncryptAtomic, reloadSecrets,
  } = deps;

  if (!requireAuth(ctx, res, jsonError)) return true;

  // GET /api/v1/secrets — list (names only / metadata)
  if (method === 'GET' && p === '/api/v1/secrets') {
    const names = [...(secretCache?.keys?.() || Object.keys(secretCache || {}))];
    const out = [];
    for (const name of names) {
      if (canAccessSecret && !canAccessSecret(name, ctx)) continue;
      out.push({ name });
    }
    send(res, 200, { secrets: out });
    return true;
  }

  // GET /api/v1/secrets/:name
  const getMatch = p.match(/^\/api\/v1\/secrets\/([^/]+)$/);
  if (method === 'GET' && getMatch) {
    const name = decodeURIComponent(getMatch[1]);
    if (canAccessSecret && !canAccessSecret(name, ctx)) {
      audit?.({ action: 'secret_get', status: 'denied', name, cn: ctx.cn });
      jsonError(res, 403, 'Forbidden');
      return true;
    }
    const val = secretCache?.get?.(name) ?? secretCache?.[name];
    if (val == null) {
      jsonError(res, 404, 'Secret not found');
      return true;
    }
    audit?.({ action: 'secret_get', status: 'ok', name, cn: ctx.cn });
    send(res, 200, { name, value: val });
    return true;
  }

  // PUT /api/v1/secrets/:name — admin write
  if (method === 'PUT' && getMatch) {
    if (ctx.client.role !== 'admin') {
      jsonError(res, 403, 'Admin role required');
      return true;
    }
    const name = decodeURIComponent(getMatch[1]);
    const body = (await readBody?.(req)) || {};
    if (body.value === undefined) {
      jsonError(res, 400, 'Missing {value}');
      return true;
    }
    if (typeof deps.putSecret === 'function') {
      await deps.putSecret(name, body.value, ctx);
    } else if (secretCache?.set) {
      secretCache.set(name, body.value);
    }
    audit?.({ action: 'secret_put', status: 'ok', name, cn: ctx.cn });
    send(res, 200, { name, updated: true });
    return true;
  }

  // DELETE /api/v1/secrets/:name
  if (method === 'DELETE' && getMatch) {
    if (ctx.client.role !== 'admin') {
      jsonError(res, 403, 'Admin role required');
      return true;
    }
    const name = decodeURIComponent(getMatch[1]);
    if (typeof deps.deleteSecret === 'function') {
      await deps.deleteSecret(name, ctx);
    } else if (secretCache?.delete) {
      secretCache.delete(name);
    }
    audit?.({ action: 'secret_delete', status: 'ok', name, cn: ctx.cn });
    send(res, 200, { name, deleted: true });
    return true;
  }

  return false;
}
