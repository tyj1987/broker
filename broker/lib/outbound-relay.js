// Optional HTTPS relay for upstreams that the broker host cannot reach
// (Aliyun ECS → api.cloudflare.com stalls). The Worker authenticates with
// X-Broker-Relay-Secret and forwards to a fixed allowlisted origin.

export const RELAY_SECRET_HEADER = 'X-Broker-Relay-Secret';

export function relayConfig(env = process.env) {
  const url = String(env.CF_RELAY_URL || env.OUTBOUND_RELAY_URL || '').replace(/\/+$/, '');
  const secret = String(env.CF_RELAY_SECRET || env.OUTBOUND_RELAY_SECRET || '');
  const hosts = String(env.CF_RELAY_HOSTS || 'api.cloudflare.com')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  return { url, secret, hosts, enabled: Boolean(url && secret) };
}

export function shouldRelay(hostname, cfg = relayConfig()) {
  if (!cfg.enabled) return false;
  return cfg.hosts.includes(String(hostname || '').toLowerCase());
}

/**
 * Rewrite an upstream URL through the relay. Host header becomes the relay
 * host; original path/query is kept. Caller still sets Authorization.
 */
export function applyRelay(upstreamUrl, headers = {}, cfg = relayConfig()) {
  const url = upstreamUrl instanceof URL ? upstreamUrl : new URL(String(upstreamUrl));
  if (!shouldRelay(url.hostname, cfg)) {
    return { url, headers: { ...headers }, relayed: false };
  }
  const base = cfg.url.endsWith('/') ? cfg.url : `${cfg.url}/`;
  const relayed = new URL(url.pathname.replace(/^\//, '') + url.search, base);
  return {
    url: relayed,
    headers: {
      ...headers,
      Host: relayed.host,
      [RELAY_SECRET_HEADER]: cfg.secret,
    },
    relayed: true,
    originalHost: url.hostname,
  };
}
