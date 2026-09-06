// broker/routes/clients.js — client registry (handler surface)
// Phase B.4

function publicClientView(name, c) {
  return {
    name,
    role: c.role,
    description: c.description || '',
    allow_password_login: !!c.allow_password_login,
    has_password: !!c.password,
    totp_enabled: !!c.totp_secret,
    cert_fingerprint_sha256: c.cert_fingerprint_sha256 || null,
    cert_expires_at: c.cert_expires_at || null,
    rate_limit: c.rate_limit || null,
    allowed_secrets: c.allowed_secrets || null,
    allowed_services: c.allowed_services || null,
  };
}

/**
 * @returns {Promise<boolean>}
 */
export async function handleClients(req, res, route, deps) {
  const { method, pathname: p } = route;
  if (!p.startsWith('/api/v1/clients')) return false;

  const { send, jsonError, readBody, audit, ctx, config, persistConfig } = deps;
  if (!ctx?.client) {
    jsonError(res, 401, 'Authentication required');
    return true;
  }

  // GET /api/v1/clients
  if (method === 'GET' && p === '/api/v1/clients') {
    if (ctx.client.role !== 'admin') {
      jsonError(res, 403, 'Admin role required');
      return true;
    }
    const clients = Object.entries(config.clients || {}).map(([name, c]) => publicClientView(name, c));
    send(res, 200, { clients });
    return true;
  }

  // GET /api/v1/clients/:name
  const m = p.match(/^\/api\/v1\/clients\/([^/]+)$/);
  if (method === 'GET' && m) {
    const name = decodeURIComponent(m[1]);
    if (ctx.client.role !== 'admin' && ctx.clientName !== name) {
      jsonError(res, 403, 'Forbidden');
      return true;
    }
    const c = (config.clients || {})[name];
    if (!c) {
      jsonError(res, 404, 'Client not found');
      return true;
    }
    send(res, 200, publicClientView(name, c));
    return true;
  }

  // PUT /api/v1/clients/:name (admin create/update metadata)
  if (method === 'PUT' && m) {
    if (ctx.client.role !== 'admin') {
      jsonError(res, 403, 'Admin role required');
      return true;
    }
    const name = decodeURIComponent(m[1]);
    const body = (await readBody?.(req)) || {};
    // never allow setting password/totp via this generic path without dedicated helpers
    const { password, totp_secret, totp_recovery_codes_hash, ...safe } = body;
    config.clients = config.clients || {};
    config.clients[name] = { ...(config.clients[name] || {}), ...safe };
    if (typeof persistConfig === 'function') await persistConfig();
    audit?.({ action: 'client_put', status: 'ok', name, cn: ctx.cn });
    send(res, 200, { name, updated: true });
    return true;
  }

  // DELETE /api/v1/clients/:name
  if (method === 'DELETE' && m) {
    if (ctx.client.role !== 'admin') {
      jsonError(res, 403, 'Admin role required');
      return true;
    }
    const name = decodeURIComponent(m[1]);
    if (!config.clients?.[name]) {
      jsonError(res, 404, 'Client not found');
      return true;
    }
    delete config.clients[name];
    if (typeof persistConfig === 'function') await persistConfig();
    audit?.({ action: 'client_delete', status: 'ok', name, cn: ctx.cn });
    send(res, 200, { name, deleted: true });
    return true;
  }

  return false;
}
