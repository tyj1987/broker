// Alibaba Cloud OpenAPI Signature V3 (ACS3-HMAC-SHA256).
// Reference: https://www.alibabacloud.com/help/en/sdk/product-overview/v3-request-structure-and-signature

import { createHash, createHmac, randomUUID } from 'node:crypto';

const SIGNATURE_ALGORITHM = 'ACS3-HMAC-SHA256';
const HEADER_NAME_RE = /^[a-z0-9-]+$/;
const CONTROL_CHARACTER_RE = /[\u0000-\u001f\u007f]/;

function sha256Hex(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function assertNonEmptyString(name, value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  if (CONTROL_CHARACTER_RE.test(value)) {
    throw new TypeError(`${name} contains control characters`);
  }
  return value;
}

function percentEncode(value) {
  return encodeURIComponent(String(value)).replace(
    /[!'()*]/g,
    (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function canonicalQueryString(query) {
  if (query == null) return '';
  if (typeof query !== 'object' || Array.isArray(query)) {
    throw new TypeError('query must be an object');
  }

  return Object.entries(query)
    .filter(([, value]) => value !== undefined && value !== null)
    .map(([name, value]) => {
      if (typeof value === 'object') {
        throw new TypeError(`query parameter ${name} must be a scalar value`);
      }
      return [percentEncode(name), percentEncode(value)];
    })
    .sort(
      ([leftName, leftValue], [rightName, rightValue]) =>
        compareUtf8(leftName, rightName) || compareUtf8(leftValue, rightValue),
    )
    .map(([name, value]) => `${name}=${value}`)
    .join('&');
}

function normalizeHeaders(headers) {
  if (headers == null || typeof headers !== 'object' || Array.isArray(headers)) {
    throw new TypeError('headers must be an object');
  }

  const normalized = {};
  for (const [rawName, rawValue] of Object.entries(headers)) {
    if (rawValue === undefined || rawValue === null) continue;
    const name = rawName.trim().toLowerCase();
    if (!HEADER_NAME_RE.test(name)) throw new TypeError(`invalid header name: ${rawName}`);
    if (name === 'authorization') {
      throw new TypeError('caller-supplied authorization header is forbidden');
    }
    if (Object.hasOwn(normalized, name)) throw new TypeError(`duplicate header: ${name}`);

    const value = String(rawValue).trim();
    if (value.length === 0 || CONTROL_CHARACTER_RE.test(value)) {
      throw new TypeError(`invalid header value: ${name}`);
    }
    normalized[name] = value;
  }
  return normalized;
}

function formatAcsDate(value) {
  const date = value instanceof Date ? value : new Date(value ?? Date.now());
  if (Number.isNaN(date.getTime())) throw new TypeError('now must be a valid date');
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * Compute the headers required for an Alibaba Cloud OpenAPI V3 request.
 * The caller must send the exact method, host, path, query, headers and body used here.
 */
export function signAliyunV3({
  method,
  host,
  path,
  query,
  headers = {},
  body,
  secret,
  now,
  nonce,
}) {
  const normalizedMethod = assertNonEmptyString('method', method).toUpperCase();
  const normalizedHost = assertNonEmptyString('host', host).toLowerCase();
  const normalizedPath = assertNonEmptyString('path', path);
  if (!normalizedPath.startsWith('/')) throw new TypeError('path must start with /');
  if (!secret || typeof secret !== 'object') throw new TypeError('secret is required');
  const accessKeyId = assertNonEmptyString('access_key_id', secret.access_key_id);
  const accessKeySecret = assertNonEmptyString('access_key_secret', secret.access_key_secret);
  const signatureNonce = assertNonEmptyString('nonce', nonce ?? randomUUID());
  const bodyString = body == null ? '' : typeof body === 'string' ? body : JSON.stringify(body);
  const payloadHash = sha256Hex(bodyString);

  const signedHeaderValues = {
    ...normalizeHeaders(headers),
    host: normalizedHost,
    'x-acs-content-sha256': payloadHash,
    'x-acs-date': formatAcsDate(now),
    'x-acs-signature-nonce': signatureNonce,
  };
  assertNonEmptyString('x-acs-action', signedHeaderValues['x-acs-action']);
  assertNonEmptyString('x-acs-version', signedHeaderValues['x-acs-version']);
  if (secret.security_token != null) {
    signedHeaderValues['x-acs-security-token'] = assertNonEmptyString(
      'security_token',
      secret.security_token,
    );
  }

  const sortedHeaderNames = Object.keys(signedHeaderValues).sort(compareUtf8);
  const canonicalHeaders = sortedHeaderNames
    .map((name) => `${name}:${signedHeaderValues[name]}\n`)
    .join('');
  const signedHeaders = sortedHeaderNames.join(';');
  const canonicalRequest = [
    normalizedMethod,
    normalizedPath,
    canonicalQueryString(query),
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');
  const stringToSign = `${SIGNATURE_ALGORITHM}\n${sha256Hex(canonicalRequest)}`;
  const signature = createHmac('sha256', accessKeySecret)
    .update(stringToSign, 'utf8')
    .digest('hex');

  return {
    ...signedHeaderValues,
    Authorization:
      `${SIGNATURE_ALGORITHM} Credential=${accessKeyId},` +
      `SignedHeaders=${signedHeaders},Signature=${signature}`,
  };
}

export default { signAliyunV3 };
