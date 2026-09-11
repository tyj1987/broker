// broker/routes/auth.js — login / login/mfa / logout
// Phase B.3: extracted handler surface. Logic mirrors server.js; deps injected.
//
// deps expected:
//   send, jsonError, readBody, audit
//   config (CONFIG), getIdentity
//   verifyClientPassword, isMfaRequired, createMfaPending, getMfaPending,
//   consumeMfaPending, verifyMfaCode, MFA_TOKEN_TTL_MS
//   makeSession, deleteSession, checkLoginLock, recordLoginFail, clearLoginLock
//   SESSION_TTL_MS, SESSION_HEADER

/**
 * @returns {Promise<boolean>} true if handled
 */
export async function handleAuth(req, res, route, deps) {
  const { method, pathname: p } = route;
  const {
    send, jsonError, readBody, audit, config,
    getIdentity, verifyClientPassword,
    isMfaRequired, createMfaPending, getMfaPending, consumeMfaPending,
    verifyMfaCode, MFA_TOKEN_TTL_MS,
    makeSession, deleteSession,
    checkLoginLock, recordLoginFail, clearLoginLock,
    SESSION_TTL_MS, SESSION_HEADER,
  } = deps;

  // ----- POST /api/v1/login -----
  if (method === 'POST' && p === '/api/v1/login') {
    const body = await readBody(req) || {};
    const password = body.password;
    if (!password) { jsonError(res, 400, 'Missing {password}'); return true; }
    const ctx0 = getIdentity(req);
    let targetClient = null, targetName = null, lockKey = null, via = 'mtls';
    if (ctx0 && ctx0.via === 'mtls') {
      if (!ctx0.client.password) { jsonError(res, 403, 'No password configured for this client'); return true; }
      targetClient = ctx0.client;
      targetName = ctx0.clientName;
      lockKey = `${targetName}|mtls`;
    } else {
      const clientName = (body.client || '').trim();
      const c = clientName ? config.clients[clientName] : null;
      if (!c || !c.allow_password_login) {
        audit({ action: 'login', status: 'denied', reason: 'password_login_not_allowed', client: clientName || '(none)' });
        jsonError(res, 401, 'mTLS client certificate required; or pass {client} with allow_password_login: true');
        return true;
      }
      targetClient = c;
      targetName = clientName;
      lockKey = `${clientName}|pw`;
      via = 'password';
    }
    if (!checkLoginLock(lockKey)) {
      audit({ action: 'login', status: 'denied', reason: 'lockout', client: lockKey });
      jsonError(res, 429, 'Too many failed login attempts. Locked until later.');
      return true;
    }
    const ok = await verifyClientPassword(password, targetClient.password);
    if (!ok) {
      recordLoginFail(lockKey);
      audit({ action: 'login', status: 'denied', reason: 'bad_password', client: lockKey });
      jsonError(res, 401, 'Bad password');
      return true;
    }
    clearLoginLock(lockKey);

    const fp = ctx0 ? ctx0.fp : null;
    if (isMfaRequired(targetClient, via)) {
      const mfaToken = createMfaPending(targetName, fp);
      audit({ action: 'login', status: 'mfa_required', client: targetName, via });
      send(res, 200, {
        ok: false,
        mfa_required: true,
        mfa_token: mfaToken,
        expires_in: MFA_TOKEN_TTL_MS / 1000,
        method: via,
      });
      return true;
    }

    const cn = ctx0 ? ctx0.cn : `${targetName}@web`;
    const token = makeSession({
      cn, fp, role: targetClient.role, clientName: targetName,
      cert: { subject: { CN: cn } }, client: targetClient,
    });
    audit({ action: 'login', status: 'ok', cn, client: targetName, via });
    res.setHeader('Set-Cookie', `broker_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_MS / 1000}`);
    send(res, 200, {
      token,
      expires_at: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
      cn,
      role: targetClient.role,
      via,
    });
    return true;
  }

  // ----- POST /api/v1/login/mfa -----
  if (method === 'POST' && p === '/api/v1/login/mfa') {
    const body = await readBody(req) || {};
    const { mfa_token: mfaToken, code } = body;
    if (!mfaToken || !code) { jsonError(res, 400, 'Missing {mfa_token, code}'); return true; }
    const pending = getMfaPending(mfaToken);
    if (!pending) {
      audit({ action: 'login_mfa', status: 'denied', reason: 'invalid_token' });
      jsonError(res, 401, 'Invalid or expired mfa_token');
      return true;
    }
    const targetClient = config.clients[pending.clientName];
    if (!targetClient) {
      consumeMfaPending(mfaToken);
      audit({ action: 'login_mfa', status: 'denied', reason: 'client_gone', client: pending.clientName });
      jsonError(res, 404, 'Client no longer exists');
      return true;
    }
    const mfaResult = verifyMfaCode(targetClient, code);
    if (!mfaResult.ok) {
      audit({ action: 'login_mfa', status: 'denied', reason: 'bad_code', client: pending.clientName });
      jsonError(res, 401, 'Bad TOTP code or recovery code');
      return true;
    }
    consumeMfaPending(mfaToken);
    const cn = pending.fp ? `${pending.clientName}@mtls` : `${pending.clientName}@web`;
    const token = makeSession({
      cn, fp: pending.fp, role: targetClient.role, clientName: pending.clientName,
      cert: { subject: { CN: cn } }, client: targetClient,
    });
    audit({ action: 'login', status: 'ok', cn, client: pending.clientName, via: 'mfa', mfa_method: mfaResult.method });
    res.setHeader('Set-Cookie', `broker_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_MS / 1000}`);
    send(res, 200, {
      token,
      expires_at: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
      cn,
      role: targetClient.role,
      via: 'mfa',
      mfa_method: mfaResult.method,
    });
    return true;
  }

  // ----- POST /api/v1/logout -----
  if (method === 'POST' && p === '/api/v1/logout') {
    const token = req.headers[SESSION_HEADER]
      || (req.headers.cookie || '').match(/broker_session=([^;]+)/)?.[1];
    if (token) {
      // session lookup is optional; caller may pass sessions map via deps
      if (deps.sessions?.get) {
        const s = deps.sessions.get(token);
        if (s) audit({ action: 'logout', cn: s.cn, fp: s.fp, status: 'ok' });
      }
      deleteSession(token);
    }
    res.setHeader('Set-Cookie', 'broker_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
    send(res, 200, { logged_out: true });
    return true;
  }

  return false;
}
