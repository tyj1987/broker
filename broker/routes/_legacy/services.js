// broker/routes/services.js — service registry CRUD (handler surface)
// Phase B.4

/**
 * @returns {Promise<boolean>}
 */
export async function handleServices(req, res, route, deps) {
  const { method, pathname: p } = route;
  if (!p.startsWith('/api/v1/services')) return false;

  const { send, jsonError, readBody, audit, ctx, config, persistConfig } = deps;
  if (!ctx?.client) {
    jsonError(res, 401, 'Authentication required');
    return true;
  }

  // GET /api/v1/services
  if (method === 'GET' && p === '/api/v1/services') {
    const services = config.services || {};
    const list = Object.entries(services).map(([name, s]) => ({
      name,
      type: s.type || null,
      description: s.description || '',
      healthcheck: s.healthcheck ? true : false,
    }));
    send(res, 200, { services: list });
    return true;
  }

  // GET /api/v1/services/:name
  const m = p.match(/^\/api\/v1\/services\/([^/]+)$/);
  if (method === 'GET' && m) {
    const name = decodeURIComponent(m[1]);
    const s = (config.services || {})[name];
    if (!s) {
      jsonError(res, 404, 'Service not found');
      return true;
    }
    send(res, 200, { name, ...s, secrets: undefined }); // avoid leaking bound secrets in list detail if needed
    return true;
  }

  // PUT /api/v1/services/:name (admin)
  if (method === 'PUT' && m) {
    if (ctx.client.role !== 'admin') {
      jsonError(res, 403, 'Admin role required');
      return true;
    }
    const name = decodeURIComponent(m[1]);
    const body = (await readBody?.(req)) || {};
    config.services = config.services || {};
    config.services[name] = { ...(config.services[name] || {}), ...body, name };
    if (typeof persistConfig === 'function') await persistConfig();
    audit?.({ action: 'service_put', status: 'ok', name, cn: ctx.cn });
    send(res, 200, { name, updated: true });
    return true;
  }

  // DELETE /api/v1/services/:name (admin)
  if (method === 'DELETE' && m) {
    if (ctx.client.role !== 'admin') {
      jsonError(res, 403, 'Admin role required');
      return true;
    }
    const name = decodeURIComponent(m[1]);
    if (!config.services?.[name]) {
      jsonError(res, 404, 'Service not found');
      return true;
    }
    delete config.services[name];
    if (typeof persistConfig === 'function') await persistConfig();
    audit?.({ action: 'service_delete', status: 'ok', name, cn: ctx.cn });
    send(res, 200, { name, deleted: true });
    return true;
  }

  return false;
}
