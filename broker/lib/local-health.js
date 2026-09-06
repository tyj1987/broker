const ALLOWED_PATHS = new Set(['/health', '/live', '/livez', '/ready', '/readyz']);

export function validateHealthSocketPath(value) {
  const path = String(value || '');
  if (!/^\/tmp\/[A-Za-z0-9._-]+\.sock$/.test(path)) {
    throw new Error('HEALTH_SOCKET_PATH must be an absolute socket path directly under /tmp');
  }
  return path;
}

export function isAllowedLocalHealthRequest(method, requestUrl) {
  if (String(method || '').toUpperCase() !== 'GET') return false;
  const rawUrl = String(requestUrl || '/');
  if (!rawUrl.startsWith('/') || rawUrl.startsWith('//') || rawUrl.includes('\\')) return false;
  const pathname = new URL(rawUrl, 'http://local.health').pathname;
  return ALLOWED_PATHS.has(pathname);
}
