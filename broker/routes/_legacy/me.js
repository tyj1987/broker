// broker/routes/me.js — self-service profile endpoints
// Phase B.3: GET /api/v1/me and related routes (handler surface).
// Full TOTP setup/rotate still live in server.js until full cutover;
// this module owns the read-only /me profile path first.

/**
 * Handle self-service routes that only need identity + cert paths.
 * @returns {Promise<boolean>}
 */
export async function handleMe(req, res, route, deps) {
  const { method, pathname: p } = route;
  if (!p.startsWith('/api/v1/me')) return false;

  const { send, jsonError, ctx, certPaths, existsSync } = deps;
  // ctx must be authenticated identity; server dispatches only after auth
  if (!ctx || !ctx.client) {
    jsonError(res, 401, 'mTLS client certificate required');
    return true;
  }

  // GET /api/v1/me
  if (method === 'GET' && p === '/api/v1/me') {
    const c = ctx.client;
    const cp = certPaths.clientPaths(ctx.clientName);
    const certOnDisk = existsSync(cp.crt) && existsSync(cp.key);
    send(res, 200, {
      name: ctx.clientName,
      cn: ctx.cn,
      role: c.role,
      description: c.description || '',
      allow_password_login: !!c.allow_password_login,
      has_password: !!c.password,
      password_set_at: c.password_set_at || null,
      password_expires_at: c.password_expires_at || null,
      totp_enabled: !!c.totp_secret,
      totp_enabled_at: c.totp_enabled_at || null,
      totp_recovery_codes_remaining: (c.totp_recovery_codes_hash || []).length,
      preferred_2fa: c.preferred_2fa || (c.totp_secret ? 'totp' : 'none'),
      cert_fingerprint_sha256: c.cert_fingerprint_sha256 || null,
      cert_present_on_disk: certOnDisk,
      cert_expires_at: c.cert_expires_at || null,
      last_password_change: c.last_password_change || null,
      last_cert_rotation: c.last_cert_rotation || null,
      rate_limit: c.rate_limit || '100/hour',
    });
    return true;
  }

  // GET /api/v1/me/recovery-codes/remaining
  if (method === 'GET' && p === '/api/v1/me/recovery-codes/remaining') {
    const c = ctx.client;
    send(res, 200, {
      remaining: (c.totp_recovery_codes_hash || []).length,
      warning: c.totp_recovery_codes_hash && c.totp_recovery_codes_hash.length < 3
        ? 'Few recovery codes left. Consider re-setup.'
        : undefined,
    });
    return true;
  }

  return false;
}
