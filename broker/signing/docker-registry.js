// Docker Registry HTTP API V2 bearer-token authentication.
// The token realm is administrator-pinned or challenge-discovered and then
// checked against an explicit hostname allowlist before credentials are sent.

import { request as httpsRequest } from 'node:https';
import { URL } from 'node:url';
import { lookup as dnsLookup } from 'node:dns/promises';
import { assertSafeDestination } from '../lib/outbound-policy.js';

const MAX_AUTH_RESPONSE_BYTES = 64 * 1024;
const SCOPE_RE = /^[a-z0-9]+:[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*:[a-z]+(?:,[a-z]+)*$/;

function assertHttpsEndpoint(value, label, allowedHosts) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443')) {
    throw new Error(`docker-registry: ${label} must be a credential-free HTTPS endpoint on port 443`);
  }
  if (allowedHosts && !allowedHosts.includes(url.hostname.toLowerCase())) {
    throw new Error(`docker-registry: ${label} host is not allowlisted`);
  }
  return url;
}

function headerValue(response, name) {
  if (response?.headers?.get) return response.headers.get(name);
  const headers = response?.headers || {};
  return headers[name.toLowerCase()] || headers[name] || headers[name.toUpperCase()] || '';
}

async function responseJson(response) {
  if (typeof response?.json === 'function') return response.json();
  if (response?.json && typeof response.json === 'object') return response.json;
  if (typeof response?.body === 'string') return JSON.parse(response.body);
  throw new Error('docker-registry: token service returned an invalid response');
}

function parseBearerChallenge(value) {
  if (!/^Bearer\s/i.test(value || '')) throw new Error('docker-registry: registry did not return a Bearer challenge');
  const params = {};
  for (const match of value.slice(7).matchAll(/([a-z]+)="([^"]*)"/gi)) params[match[1].toLowerCase()] = match[2];
  if (!params.realm) throw new Error('docker-registry: no Bearer realm in 401 response');
  return params;
}

export async function getDockerRegistryToken(args) {
  if (!args?.registry) throw new Error('docker-registry: registry required');
  const registry = assertHttpsEndpoint(args.registry, 'registry', args.allowedRegistryHosts);
  if (args.scope && !SCOPE_RE.test(args.scope)) throw new Error('docker-registry: invalid repository scope');
  const fetchFn = args.fetchImpl || ((value, options) => secureFetch(value, options, args.resolveHostname));

  let realm = args.realm;
  let service = args.service || '';
  if (!realm) {
    const probeRes = await fetchFn(new URL('/v2/', registry).toString(), { method: 'GET', redirect: 'manual' });
    if (probeRes.status === 200) return { token: '' };
    if (probeRes.status !== 401) throw new Error(`docker-registry: registry probe failed: ${probeRes.status}`);
    const challenge = parseBearerChallenge(headerValue(probeRes, 'www-authenticate'));
    realm = challenge.realm;
    if (service && challenge.service && challenge.service !== service) {
      throw new Error('docker-registry: challenge service does not match configured audience');
    }
    service = service || challenge.service || '';
  }

  const authHosts = (args.allowedAuthHosts || []).map(host => String(host).toLowerCase());
  if (authHosts.length === 0) throw new Error('docker-registry: allowedAuthHosts is required');
  const tokenUrl = assertHttpsEndpoint(realm, 'token realm', authHosts);
  if (service) tokenUrl.searchParams.set('service', service);
  if (args.scope) tokenUrl.searchParams.set('scope', args.scope);

  const headers = {};
  if (args.username) {
    if (!args.password) throw new Error('docker-registry: PAT required when username is configured');
    headers.Authorization = `Basic ${Buffer.from(`${args.username}:${args.password}`).toString('base64')}`;
  }
  const tokenRes = await fetchFn(tokenUrl.toString(), { method: 'GET', headers, redirect: 'manual' });
  if (tokenRes.status < 200 || tokenRes.status >= 300) {
    throw new Error(`docker-registry: token fetch failed: ${tokenRes.status}`);
  }
  const body = await responseJson(tokenRes);
  const token = body?.token || body?.access_token;
  if (typeof token !== 'string' || token.length < 16) throw new Error('docker-registry: token service returned no usable token');
  const expiresIn = Number(body.expires_in);
  return { token, ...(Number.isFinite(expiresIn) && expiresIn > 0 ? { expires_in: expiresIn } : {}) };
}

export async function signDockerRegistry(args) {
  const result = await getDockerRegistryToken(args);
  return result.token ? { Authorization: `Bearer ${result.token}` } : {};
}

async function secureFetch(value, opts = {}, resolveHostname) {
  const url = assertHttpsEndpoint(value, 'request');
  const resolved = resolveHostname
    ? await resolveHostname(url.hostname)
    : (await dnsLookup(url.hostname, { all: false, verbatim: true })).address;
  assertSafeDestination(url.hostname, resolved);
  return new Promise((resolve, reject) => {
    const request = httpsRequest({
      protocol: 'https:', hostname: resolved, servername: url.hostname, port: url.port || 443,
      path: url.pathname + url.search, method: opts.method || 'GET',
      headers: { Host: url.host, ...(opts.headers || {}) }, rejectUnauthorized: true, timeout: 10_000,
    }, response => {
      const chunks = [];
      let size = 0;
      response.on('data', chunk => {
        size += chunk.length;
        if (size > MAX_AUTH_RESPONSE_BYTES) response.destroy(new Error('docker-registry: auth response too large'));
        else chunks.push(chunk);
      });
      response.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');
        resolve({ status: response.statusCode, headers: response.headers, body, json: () => JSON.parse(body) });
      });
    });
    request.on('error', reject);
    request.on('timeout', () => request.destroy(new Error('docker-registry: auth request timeout')));
    request.end();
  });
}

export default { getDockerRegistryToken, signDockerRegistry };
