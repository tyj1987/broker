// broker/signing/aliyun-v3.js — V4 阿里云 API v3 签名 (HMAC-SHA256)
// Reference: https://help.aliyun.com/document_detail/315526.htm
//
// Headers injected:
//   Authorization: ACS3-HMAC-SHA256 Credential=<ak>,SignedHeaders=<list>,Signature=<hex>
//   x-acs-date: <RFC 1123 date, e.g. "Mon, 26 Aug 2026 09:12:34 GMT">
//   x-acs-content-sha256: <hex of body sha256>
//   Accept: application/json
//
// Used for newer Aliyun OpenAPI (e.g. ACK, ECS 2024+).
// Falls back to aliyun-v2 for older endpoints.

import { createHmac, createHash, randomUUID } from 'node:crypto';

function sha256Hex(s) {
  return createHash('sha256').update(s || '').digest('hex');
}
function hmacSha256(key, data) {
  return createHmac('sha256', key).update(data).digest();
}

function canonicalQueryString(query) {
  if (!query) return '';
  const entries = Object.entries(query)
    .filter(([, v]) => v !== undefined && v !== null)
    .map(([k, v]) => [
      encodeURIComponent(k),
      encodeURIComponent(String(v)),
    ])
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return entries.map(([k, v]) => `${k}=${v}`).join('&');
}

function canonicalHeaders(headers) {
  const entries = Object.entries(headers)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => [k.toLowerCase().trim(), String(v).trim()])
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return entries.map(([k, v]) => `${k}:${v}\n`).join('');
}

function signedHeaders(headers) {
  return Object.keys(headers)
    .map(k => k.toLowerCase().trim())
    .filter(Boolean)
    .sort()
    .join(';');
}

/**
 * Compute Aliyun v3 signature headers.
 * @param {{
 *   method: string,
 *   host: string,
 *   path: string,
 *   query?: object,
 *   headers?: object,
 *   body?: string|object|null,
 *   secret: { access_key_id: string, access_key_secret: string },
 *   now?: Date,
 * }} args
 * @returns {object} headers to merge (Authorization, x-acs-date, x-acs-content-sha256)
 */
export function signAliyunV3({ method, host, path, query, headers = {}, body, secret, action, version, nonce, now }) {
  if (!action || !version) throw new Error('Aliyun V3 requires action and version');
  const date = now || new Date();
  const acsDate = date.toISOString().replace(/\.\d{3}Z$/, 'Z');
  const bodyStr = body == null ? '' : (typeof body === 'string' ? body : JSON.stringify(body));
  const payloadHash = sha256Hex(bodyStr);

  // Always required headers
  const allHeaders = {
    host,
    'x-acs-action': action,
    'x-acs-version': version,
    'x-acs-date': acsDate,
    'x-acs-content-sha256': payloadHash,
    'x-acs-signature-nonce': nonce || randomUUID().replaceAll('-', ''),
    ...(secret.security_token ? { 'x-acs-security-token': secret.security_token } : {}),
    ...Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])),
  };
  const canonical = canonicalHeaders(allHeaders);
  const signed = signedHeaders(allHeaders);

  const canonicalRequest = [
    (method || 'GET').toUpperCase(),
    path || '/',
    canonicalQueryString(query),
    canonical,
    signed,
    payloadHash,
  ].join('\n');

  const hashedCanonical = sha256Hex(canonicalRequest);
  const stringToSign = `ACS3-HMAC-SHA256\n${hashedCanonical}`;

  // Signing chain: kDate -> kRegion -> kProduct -> kSigning
  // Aliyun v3 doesn't require region/product in signing (they're metadata).
  const kSecret = Buffer.from(secret.access_key_secret, 'utf8');
  const signature = createHmac('sha256', kSecret).update(stringToSign).digest('hex');

  return {
    ...headers,
    'host': host,
    'Authorization': `ACS3-HMAC-SHA256 Credential=${secret.access_key_id},SignedHeaders=${signed},Signature=${signature}`,
    'x-acs-action': action,
    'x-acs-version': version,
    'x-acs-date': acsDate,
    'x-acs-content-sha256': payloadHash,
    'x-acs-signature-nonce': allHeaders['x-acs-signature-nonce'],
    ...(secret.security_token ? { 'x-acs-security-token': secret.security_token } : {}),
  };
}

export default { signAliyunV3 };
