// broker/signing/docker-registry.js — V4 Docker Registry V2 auth
// Reference: https://docs.docker.com/reference/api/registry/auth/
//
// Flow:
//   1. GET /v2/ -> 401 with WWW-Authenticate: Bearer realm="...", service="...", scope="..."
//   2. GET <realm>?service=...&scope=... -> { token: "..." }
//   3. Subsequent requests: Authorization: Bearer <token>
//
// Implementations often pre-cache the realm/service from the first response
// or accept a pre-fetched token. We provide both styles.

import { request as httpsRequest, request as httpRequest } from 'node:http';
import { request as httpsRequestHttps, request as httpRequestHttps } from 'node:https';
import { URL } from 'node:url';

/**
 * @param {{
 *   registry: string,            // e.g. 'https://registry-1.docker.io'
 *   scope?: string,              // e.g. 'repository:library/alpine:pull'
 *   username?: string,           // for index.docker.io
 *   password?: string,
 *   fetchImpl?: typeof fetch,    // optional injection
 * }} args
 * @returns {Promise<{token: string, expires_in?: number}>}
 */
export async function getDockerRegistryToken(args) {
  if (!args || !args.registry) throw new Error('docker-registry: registry required');
  const u = new URL(args.registry);
  const isHttps = u.protocol === 'https:';
  const fetchFn = args.fetchImpl || (isHttps ? httpsFetch : httpFetch);

  // Step 1: probe /v2/ to get the auth challenge
  const probeUrl = `${args.registry.replace(/\/$/, '')}/v2/`;
  const probeRes = await fetchFn(probeUrl, { method: 'GET' });
  if (probeRes.status !== 401) {
    // registry says "no auth needed" — return a dummy bearer (some private ones)
    return { token: '' };
  }
  const wwwAuth = (probeRes.headers && (probeRes.headers.get ? probeRes.headers.get('www-authenticate') : probeRes.headers['www-authenticate'] || probeRes.headers['WWW-Authenticate'])) || '';
  // Format: Bearer realm="https://auth...",service="...",scope="..."
  const realmMatch = /realm="([^"]+)"/.exec(wwwAuth);
  const serviceMatch = /service="([^"]+)"/.exec(wwwAuth);
  if (!realmMatch) throw new Error('docker-registry: no Bearer realm in 401 response');
  const realm = realmMatch[1];
  const service = serviceMatch ? serviceMatch[1] : '';

  // Step 2: get token
  const tokenUrl = new URL(realm);
  tokenUrl.searchParams.set('service', service);
  if (args.scope) tokenUrl.searchParams.set('scope', args.scope);
  const headers = {};
  if (args.username) {
    const basic = Buffer.from(`${args.username}:${args.password || ''}`).toString('base64');
    headers['Authorization'] = `Basic ${basic}`;
  }
  const tokRes = await fetchFn(tokenUrl.toString(), { method: 'GET', headers });
  if (!tokRes.ok) {
    throw new Error(`docker-registry: token fetch failed: ${tokRes.status}`);
  }
  const body = await tokRes.json();
  return { token: body.token || body.access_token, expires_in: body.expires_in };
}

export async function signDockerRegistry(args) {
  const tok = await getDockerRegistryToken(args);
  return { 'Authorization': tok.token ? `Bearer ${tok.token}` : '' };
}

// Tiny fetch implementations over node:http(s)
function httpsFetch(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = httpsRequestHttps({
      method: opts.method || 'GET',
      hostname: u.hostname,
      port: u.port || 443,
      path: u.pathname + u.search,
      headers: opts.headers || {},
    }, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch (_) {}
        resolve({ status: res.statusCode, headers: res.headers, body: text, json });
      });
    });
    req.on('error', reject);
    req.end();
  });
}
function httpFetch(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = httpRequestHttps({
      method: opts.method || 'GET',
      hostname: u.hostname,
      port: u.port || 80,
      path: u.pathname + u.search,
      headers: opts.headers || {},
    }, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch (_) {}
        resolve({ status: res.statusCode, headers: res.headers, body: text, json });
      });
    });
    req.on('error', reject);
    req.end();
  });
}

export default { getDockerRegistryToken, signDockerRegistry };
