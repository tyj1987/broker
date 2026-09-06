// broker/signing/tencent-v3.js — V4 腾讯云 TC3-HMAC-SHA256 签名
// Reference: https://cloud.tencent.com/document/api/1723/101843
//
// Required headers:
//   Authorization: TC3-HMAC-SHA256 Credential=<SecretId>/<date>/<service>/tc3_request, ...
//   X-TC-Timestamp: <unix seconds>
//   X-TC-Action: <API action, e.g. DescribeInstances>
//   X-TC-Version: <API version, e.g. 2017-03-12>
//   X-TC-Region: <region, e.g. ap-guangzhou>

import { createHmac, createHash } from 'node:crypto';

function sha256Hex(s) {
  return createHash('sha256').update(s || '').digest('hex');
}
function hmac(key, data) {
  return createHmac('sha256', key).update(data).digest();
}

function canonicalQueryString(query) {
  if (!query) return '';
  const entries = Object.entries(query)
    .filter(([, v]) => v !== undefined && v !== null)
    .map(([k, v]) => [encodeURIComponent(k), encodeURIComponent(String(v))])
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return entries.map(([k, v]) => `${k}=${v}`).join('&');
}

function canonicalHeaders(headers) {
  return Object.entries(headers)
    .filter(([, v]) => v != null && v !== '')
    .map(([k, v]) => `${k.toLowerCase().trim()}:${String(v).trim()}\n`)
    .sort()
    .join('');
}

function signedHeaders(headers) {
  return Object.keys(headers)
    .map(k => k.toLowerCase().trim())
    .filter(Boolean)
    .sort()
    .join(';');
}

/**
 * @param {{
 *   method: string,
 *   host: string,
 *   path: string,
 *   query?: object,
 *   headers?: object,
 *   body?: string|object|null,
 *   service: string,
 *   action: string,
 *   version: string,
 *   region: string,
 *   timestamp?: number,
 *   secret: { secret_id: string, secret_key: string, token?: string },
 * }} args
 * @returns {object} headers to merge
 */
export function signTencentV3({
  method, host, path, query, headers = {}, body,
  service, action, version, region,
  timestamp, secret,
}) {
  const normalizedMethod = String(method || 'POST').toUpperCase();
  if (!['GET', 'POST'].includes(normalizedMethod)) throw new Error('Tencent V3 method must be GET or POST');
  if (typeof host !== 'string' || !/^[a-z0-9.-]+(?::\d+)?$/i.test(host)) throw new Error('Tencent V3 host is invalid');
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || path.includes('\\')) throw new Error('Tencent V3 path is invalid');
  for (const [label, value] of Object.entries({ service, action, version, region })) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_.-]{1,128}$/.test(value)) throw new Error(`Tencent V3 ${label} is invalid`);
  }
  if (!secret || typeof secret.secret_id !== 'string' || !secret.secret_id ||
      typeof secret.secret_key !== 'string' || !secret.secret_key) {
    throw new Error('Tencent V3 credentials are invalid');
  }
  const ts = timestamp || Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(ts) || ts <= 0) throw new Error('Tencent V3 timestamp is invalid');
  const bodyStr = body == null ? '' : (typeof body === 'string' ? body : JSON.stringify(body));
  const payloadHash = sha256Hex(bodyStr);

  // Required headers for signing
  const allHeaders = {
    'content-type': headers['content-type'] || 'application/json; charset=utf-8',
    host,
    'x-tc-action': action,
    'x-tc-timestamp': String(ts),
    'x-tc-version': version,
    'x-tc-region': region,
    ...Object.fromEntries(
      Object.entries(headers).filter(([k]) => !['content-type', 'host', 'authorization'].includes(k.toLowerCase()))
    ),
  };

  const canonical = canonicalHeaders(allHeaders);
  const signed = signedHeaders(allHeaders);
  const canonicalRequest = [
    normalizedMethod,
    path || '/',
    canonicalQueryString(query),
    canonical,
    signed,
    payloadHash,
  ].join('\n');

  const date = new Date(ts * 1000).toISOString().split('T')[0];
  const credentialScope = `${date}/${service}/tc3_request`;
  const stringToSign = [
    'TC3-HMAC-SHA256',
    ts,
    credentialScope,
    sha256Hex(canonicalRequest),
  ].join('\n');

  // Signing chain
  const kDate = hmac('TC3' + secret.secret_key, date);
  const kService = hmac(kDate, service);
  const kSigning = hmac(kService, 'tc3_request');
  const signature = createHmac('sha256', kSigning).update(stringToSign).digest('hex');

  const authz = `TC3-HMAC-SHA256 Credential=${secret.secret_id}/${credentialScope}, SignedHeaders=${signed}, Signature=${signature}`;

  const out = {
    ...headers,
    'Authorization': authz,
    'Content-Type': allHeaders['content-type'],
    'Host': host,
    'X-TC-Action': action,
    'X-TC-Timestamp': String(ts),
    'X-TC-Version': version,
    'X-TC-Region': region,
  };
  if (secret.token) out['X-TC-Token'] = secret.token;
  return out;
}

export default { signTencentV3 };
