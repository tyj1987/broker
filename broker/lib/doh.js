// DNS-over-HTTPS pre-resolver.
// Aliyun ECS (and similar) often block outbound UDP/53; Node c-ares then
// fails with ENOTFOUND even though TCP/443 works. Resolve A records over
// HTTPS (AliDNS, then Cloudflare 1.1.1.1) and connect to the IP with SNI
// set to the original hostname.

import { request as httpsRequest } from 'node:https';

export const DOH_TTL_MS = 5 * 60 * 1000;

const _cache = new Map();      // hostname -> { ip, expiresAt }
const _inFlight = new Map();   // hostname -> Promise

export function isIpLiteral(hostname) {
  const h = String(hostname || '');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return true;
  if (h.includes(':')) return true; // IPv6
  return false;
}

export function shouldSkipDoH(hostname) {
  const h = String(hostname || '').toLowerCase();
  if (!h) return true;
  if (isIpLiteral(h)) return true;
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local')) return true;
  return false;
}

export function pickARecord(dohJson) {
  const answer = dohJson?.Answer;
  if (!Array.isArray(answer)) return null;
  const a = answer.find((x) => x && (x.type === 1 || x.type === 'A') && x.data);
  return a ? String(a.data).replace(/\.$/, '') : null;
}

export function clearDoHCache() {
  _cache.clear();
  _inFlight.clear();
}

function defaultEndpoints(hostname) {
  const q = encodeURIComponent(hostname);
  return [
    { url: `https://dns.alidns.com/resolve?name=${q}&type=A`, ip: '223.5.5.5', host: 'dns.alidns.com' },
    { url: `https://1.1.1.1/dns-query?name=${q}&type=A`, ip: '1.1.1.1', host: '1.1.1.1' },
  ];
}

function defaultDohGet(ep, timeout) {
  const u = new URL(ep.url);
  return new Promise((resolve, reject) => {
    const req = httpsRequest({
      hostname: ep.ip,
      port: 443,
      path: u.pathname + u.search,
      method: 'GET',
      servername: ep.host || u.hostname,
      headers: { Host: ep.host || u.host, Accept: 'application/dns-json' },
      timeout,
    }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`DoH HTTP ${res.statusCode}`));
        return;
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('DoH timeout')));
    req.end();
  });
}

/**
 * Resolve hostname to IPv4 via DoH. IP literals and localhost are returned as-is.
 * @param {string} hostname
 * @param {{ endpoints?: Array<{url:string,ip:string,host?:string}>, request?: Function, timeout?: number, ttlMs?: number }} [opts]
 */
export async function resolveHostnameDoH(hostname, opts = {}) {
  if (shouldSkipDoH(hostname)) return hostname;
  const cached = _cache.get(hostname);
  if (cached && cached.expiresAt > Date.now()) return cached.ip;
  if (_inFlight.has(hostname)) return _inFlight.get(hostname);

  const p = (async () => {
    const endpoints = opts.endpoints || defaultEndpoints(hostname);
    const requestFn = opts.request || defaultDohGet;
    const timeout = opts.timeout ?? 5000;
    for (const ep of endpoints) {
      try {
        const body = await requestFn(ep, timeout);
        const parsed = typeof body === 'string' ? JSON.parse(body) : body;
        const ip = pickARecord(parsed);
        if (ip) {
          _cache.set(hostname, { ip, expiresAt: Date.now() + (opts.ttlMs ?? DOH_TTL_MS) });
          return ip;
        }
      } catch { /* try next endpoint */ }
    }
    throw new Error(`DoH resolve failed for ${hostname}`);
  })();

  _inFlight.set(hostname, p);
  try { return await p; } finally { _inFlight.delete(hostname); }
}

/**
 * Options for https.request: connect to the resolved IP, SNI + Host stay on the name.
 * @returns {Promise<{ hostname: string, servername: string }>}
 */
export async function dohConnect(hostname, opts = {}) {
  if (opts.skip || shouldSkipDoH(hostname)) {
    return { hostname, servername: hostname };
  }
  const ip = await resolveHostnameDoH(hostname, opts);
  return { hostname: ip, servername: hostname };
}
