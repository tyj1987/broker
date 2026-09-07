// Thin authenticated reverse proxy: broker → this Worker → api.cloudflare.com
// Only /client/v4/* is forwarded. RELAY_SECRET must match X-Broker-Relay-Secret.

const UPSTREAM = 'https://api.cloudflare.com';
const ALLOW_PREFIX = '/client/v4';

function json(body, status) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: { 'access-control-allow-origin': '*' } });
    }
    const expected = env.RELAY_SECRET || '';
    const got = request.headers.get('X-Broker-Relay-Secret') || '';
    if (!expected || got !== expected) {
      return json({ success: false, error: 'unauthorized' }, 401);
    }
    const src = new URL(request.url);
    let pathname = src.pathname;
    if (pathname !== ALLOW_PREFIX && !pathname.startsWith(`${ALLOW_PREFIX}/`)) {
      pathname = ALLOW_PREFIX + (pathname.startsWith('/') ? pathname : `/${pathname}`);
    }
    if (pathname !== ALLOW_PREFIX && !pathname.startsWith(`${ALLOW_PREFIX}/`)) {
      return json({ success: false, error: 'path not allowed' }, 403);
    }
    const dest = new URL(pathname + src.search, UPSTREAM);
    const headers = new Headers(request.headers);
    headers.delete('X-Broker-Relay-Secret');
    headers.delete('Host');
    headers.delete('cf-connecting-ip');
    headers.delete('cf-ipcountry');
    headers.delete('cf-ray');
    headers.delete('cdn-loop');
    headers.set('Host', 'api.cloudflare.com');
    const init = { method: request.method, headers, redirect: 'manual' };
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      init.body = request.body;
    }
    return fetch(dest.toString(), init);
  },
};
