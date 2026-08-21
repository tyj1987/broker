// broker/lib/build-route-deps.js — assemble deps for routes/* handlers
// Phase B.5: keeps server.js wiring in one place.

/**
 * Build a deps object for modular route handlers.
 * Pass only what you have; missing hooks fall back to no-ops or 501 inside handlers.
 *
 * @param {object} parts
 * @returns {object} deps
 */
export function buildRouteDeps(parts = {}) {
  const {
    send,
    jsonError,
    readBody,
    audit = () => {},
    config,
    secretCache,
    version,
    dashboardDir,
    ctx = null,
    // session
    makeSession,
    deleteSession,
    sessions,
    checkLoginLock = () => true,
    recordLoginFail = () => {},
    clearLoginLock = () => {},
    SESSION_TTL_MS = 30 * 60 * 1000,
    SESSION_HEADER = 'x-auth-token',
    // auth-flow
    getIdentity = () => null,
    verifyClientPassword,
    isMfaRequired = () => false,
    createMfaPending,
    getMfaPending,
    consumeMfaPending,
    verifyMfaCode,
    MFA_TOKEN_TTL_MS = 5 * 60 * 1000,
    // secrets / config
    canAccessSecret = () => true,
    putSecret,
    deleteSecret,
    persistConfig,
    // proxy
    canProxy,
    proxyRequest,
    // me
    certPaths,
    existsSync,
  } = parts;

  return {
    send,
    jsonError,
    readBody,
    audit,
    config,
    secretCache,
    version,
    dashboardDir,
    ctx,
    makeSession,
    deleteSession,
    sessions,
    checkLoginLock,
    recordLoginFail,
    clearLoginLock,
    SESSION_TTL_MS,
    SESSION_HEADER,
    getIdentity,
    verifyClientPassword,
    isMfaRequired,
    createMfaPending,
    getMfaPending,
    consumeMfaPending,
    verifyMfaCode,
    MFA_TOKEN_TTL_MS,
    canAccessSecret,
    putSecret,
    deleteSecret,
    persistConfig,
    canProxy,
    proxyRequest,
    certPaths,
    existsSync,
  };
}

/**
 * Env flag: set USE_MODULAR_ROUTES=1 to prefer routes/* dispatch when wired.
 */
export function useModularRoutes() {
  return process.env.USE_MODULAR_ROUTES === '1'
    || process.env.USE_MODULAR_ROUTES === 'true';
}
