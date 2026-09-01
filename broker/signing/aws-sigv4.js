// broker/signing/aws-sigv4.js — V4 AWS Signature Version 4
// Reference: https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
//
// Steps:
//  1. Canonical request
//  2. String to sign
//  3. Signing key (4-step HMAC chain)
//  4. Signature
//  5. Authorization header

import { createHmac, createHash } from 'node:crypto';

function sha256Hex(s) {
  return createHash('sha256').update(s || '').digest('hex');
}
function hmac(key, data) {
  return createHmac('sha256', key).update(data).digest();
}

function uriEscape(path) {
  // AWS path encoding: unreserved set is ALPHA / DIGIT / '-' / '.' / '_' / '~'
  // Path segments must be normalized. We do best-effort: percent-encode everything else.
  return String(path || '/').split('/').map(seg => encodeURIComponent(seg).replace(/%2F/g, '/').replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase())).join('/');
}

function canonicalQueryString(query) {
  if (!query) return '';
  return Object.entries(query)
    .filter(([, v]) => v !== undefined && v !== null)
    .map(([k, v]) => [encodeURIComponent(k).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase()),
                      encodeURIComponent(String(v)).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase())])
    .sort(([a1, a2], [b1, b2]) => a1 < b1 ? -1 : a1 > b1 ? 1 : (a2 < b2 ? -1 : a2 > b2 ? 1 : 0))
    .map(([k, v]) => `${k}=${v}`)
    .join('&');
}

function canonicalHeaders(headers) {
  return Object.entries(headers)
    .filter(([, v]) => v != null && v !== '')
    .map(([k, v]) => [k.toLowerCase().trim(), String(v).trim().replace(/\s+/g, ' ')])
    .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
    .map(([k, v]) => `${k}:${v}\n`)
    .join('');
}

function signedHeaders(headers) {
  return Object.keys(headers)
    .map(k => k.toLowerCase().trim())
    .filter(Boolean)
    .sort()
    .join(';');
}

function amzDateFormat(d) {
  // YYYYMMDD'T'HHMMSS'Z'
  const pad = (n) => String(n).padStart(2, '0');
  return (
    d.getUTCFullYear() +
    pad(d.getUTCMonth() + 1) +
    pad(d.getUTCDate()) +
    'T' +
    pad(d.getUTCHours()) +
    pad(d.getUTCMinutes()) +
    pad(d.getUTCSeconds()) +
    'Z'
  );
}

function shortDate(d) {
  const pad = (n) => String(n).padStart(2, '0');
  return d.getUTCFullYear() + pad(d.getUTCMonth() + 1) + pad(d.getUTCDate());
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
 *   region: string,
 *   now?: Date,
 *   secret: { access_key_id: string, secret_access_key: string, session_token?: string },
 * }} args
 * @returns {object} headers
 */
export function signAwsSigV4({ method, host, path, query, headers = {}, body, service, region, now, secret }) {
  const t = now || new Date();
  const amzDate = amzDateFormat(t);
  const date = shortDate(t);
  const bodyStr = body == null ? '' : (typeof body === 'string' ? body : JSON.stringify(body));
  const payloadHash = sha256Hex(bodyStr);

  const allHeaders = {
    host,
    'x-amz-date': amzDate,
    'x-amz-content-sha256': payloadHash,
    ...Object.fromEntries(
      Object.entries(headers).filter(([k]) => !['host', 'authorization', 'x-amz-date'].includes(k.toLowerCase()))
    ),
  };
  if (secret.session_token) {
    allHeaders['x-amz-security-token'] = secret.session_token;
  }

  const canonical = canonicalHeaders(allHeaders);
  const signed = signedHeaders(allHeaders);

  const canonicalRequest = [
    (method || 'GET').toUpperCase(),
    uriEscape(path),
    canonicalQueryString(query),
    canonical,
    signed,
    payloadHash,
  ].join('\n');

  const credentialScope = `${date}/${region}/${service}/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    sha256Hex(canonicalRequest),
  ].join('\n');

  // Signing key chain
  const kDate = hmac('AWS4' + secret.secret_access_key, date);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  const kSigning = hmac(kService, 'aws4_request');
  const signature = createHmac('sha256', kSigning).update(stringToSign).digest('hex');

  const authz = `AWS4-HMAC-SHA256 Credential=${secret.access_key_id}/${credentialScope}, SignedHeaders=${signed}, Signature=${signature}`;

  return {
    ...headers,
    'Authorization': authz,
    'X-Amz-Date': amzDate,
    'X-Amz-Content-Sha256': payloadHash,
    ...(secret.session_token ? { 'X-Amz-Security-Token': secret.session_token } : {}),
  };
}

export default { signAwsSigV4 };
