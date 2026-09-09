import dns from 'node:dns/promises';
import https from 'node:https';

import { assertPublicResolvedAddress, buildPinnedUrl, validateMethod } from './outbound-policy.js';

const MAX_ALLOWED_RESPONSE_BYTES = 10 * 1024 * 1024;
const MAX_REQUEST_BYTES = 1024 * 1024;
const FORBIDDEN_HEADERS = new Set([
  'connection',
  'content-length',
  'host',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

export class PinnedRequestError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'PinnedRequestError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new PinnedRequestError(code, message);
}

function normalizeHeaders(headers, body) {
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) {
    fail('PINNED_HEADERS_INVALID', 'Pinned request headers are invalid');
  }
  const normalized = {};
  const seen = new Set();
  for (const [name, value] of Object.entries(headers)) {
    const lower = String(name).toLowerCase();
    if (
      !/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(lower) ||
      seen.has(lower) ||
      FORBIDDEN_HEADERS.has(lower)
    ) {
      fail('PINNED_HEADERS_INVALID', 'Pinned request headers are invalid');
    }
    if (Array.isArray(value) || /[\r\n]/.test(String(value))) {
      fail('PINNED_HEADERS_INVALID', 'Pinned request headers are invalid');
    }
    seen.add(lower);
    normalized[lower] = String(value);
  }
  if (body) normalized['content-length'] = String(body.byteLength);
  return normalized;
}

function normalizeBody(body, method) {
  if (body === undefined || body === null) return null;
  if (method === 'GET' || method === 'HEAD')
    fail('PINNED_BODY_DENIED', 'Pinned request body is not permitted');
  if (typeof body !== 'string' && !Buffer.isBuffer(body) && !(body instanceof Uint8Array)) {
    fail('PINNED_BODY_INVALID', 'Pinned request body is invalid');
  }
  const value = Buffer.from(body);
  if (value.byteLength > MAX_REQUEST_BYTES)
    fail('PINNED_BODY_TOO_LARGE', 'Pinned request body exceeded the configured limit');
  return value;
}

function responseLimit(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > MAX_ALLOWED_RESPONSE_BYTES) {
    fail('PINNED_RESPONSE_LIMIT_INVALID', 'Pinned response limit is invalid');
  }
  return value;
}

function createLookup(expectedHostname, address) {
  return (hostname, options, callback) => {
    if (String(hostname).toLowerCase().replace(/\.$/, '') !== expectedHostname) {
      callback(new PinnedRequestError('PINNED_DNS_MISMATCH', 'Pinned DNS hostname changed'));
      return;
    }
    if (options?.all) callback(null, [address]);
    else callback(null, address.address, address.family);
  };
}

async function defaultResolve(hostname) {
  return dns.lookup(hostname, { all: true, verbatim: true });
}

function resolveWithTimeout(resolveHost, hostname, signal, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (handler, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      handler(value);
    };
    const abort = () =>
      finish(
        reject,
        new PinnedRequestError('PINNED_REQUEST_ABORTED', 'Pinned request was aborted'),
      );
    const timer = setTimeout(
      () =>
        finish(
          reject,
          new PinnedRequestError(
            'PINNED_DNS_TIMEOUT',
            'Pinned destination DNS resolution timed out',
          ),
        ),
      timeoutMs,
    );
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) {
      abort();
      return;
    }
    Promise.resolve()
      .then(() => resolveHost(hostname, { signal }))
      .then(
        (value) => finish(resolve, value),
        () =>
          finish(
            reject,
            new PinnedRequestError('PINNED_DNS_FAILED', 'Pinned destination DNS resolution failed'),
          ),
      );
  });
}

export function createPinnedHttpsRequest({
  resolveHost = defaultResolve,
  requestImpl = https.request,
  timeoutMs = 10_000,
} = {}) {
  if (typeof resolveHost !== 'function' || typeof requestImpl !== 'function') {
    throw new TypeError('Pinned HTTPS transport dependencies are invalid');
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60_000) {
    throw new TypeError('Pinned HTTPS transport timeout is invalid');
  }

  return async function pinnedHttpsRequest(input) {
    if (input?.redirect !== 'manual')
      fail('PINNED_REDIRECT_POLICY_REQUIRED', 'Pinned requests must deny redirects');
    const url = buildPinnedUrl(input?.origin, input?.path);
    const method = validateMethod(input?.method, ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']);
    const body = normalizeBody(input?.body, method);
    const headers = normalizeHeaders(input?.headers, body);
    const maxResponseBytes = responseLimit(input?.max_response_bytes);

    const addresses = await resolveWithTimeout(resolveHost, url.hostname, input?.signal, timeoutMs);
    if (!Array.isArray(addresses) || addresses.length < 1) {
      fail('PINNED_DNS_FAILED', 'Pinned destination DNS resolution failed');
    }
    let validated;
    try {
      validated = addresses.map((entry) => ({
        address: assertPublicResolvedAddress(entry?.address),
        family: entry?.family,
      }));
    } catch {
      fail('PINNED_DNS_DENIED', 'Pinned destination DNS resolution was denied');
    }
    if (validated.some((entry) => ![4, 6].includes(entry.family))) {
      fail('PINNED_DNS_FAILED', 'Pinned destination DNS resolution failed');
    }
    const pinned = validated[0];

    return new Promise((resolve, reject) => {
      let settled = false;
      let deadlineTimer;
      const rejectSafe = (code, message) => {
        if (settled) return;
        settled = true;
        clearTimeout(deadlineTimer);
        reject(new PinnedRequestError(code, message));
      };
      let request;
      deadlineTimer = setTimeout(() => {
        if (settled) return;
        request?.destroy();
        rejectSafe('PINNED_REQUEST_TIMEOUT', 'Pinned request timed out');
      }, timeoutMs);
      try {
        request = requestImpl(
          {
            protocol: 'https:',
            hostname: url.hostname,
            port: url.port || 443,
            method,
            path: `${url.pathname}${url.search}`,
            headers,
            lookup: createLookup(url.hostname, pinned),
            servername: url.hostname,
            rejectUnauthorized: true,
            signal: input?.signal,
          },
          (response) => {
            const chunks = [];
            let total = 0;
            const declaredLength = Number(response.headers?.['content-length']);
            if (Number.isFinite(declaredLength) && declaredLength > maxResponseBytes) {
              response.destroy();
              rejectSafe(
                'PINNED_RESPONSE_TOO_LARGE',
                'Pinned response exceeded the configured limit',
              );
              return;
            }
            response.on('data', (chunk) => {
              if (settled) return;
              const value = Buffer.from(chunk);
              total += value.byteLength;
              if (total > maxResponseBytes) {
                response.destroy();
                rejectSafe(
                  'PINNED_RESPONSE_TOO_LARGE',
                  'Pinned response exceeded the configured limit',
                );
                return;
              }
              chunks.push(value);
            });
            response.on('end', () => {
              if (settled) return;
              settled = true;
              clearTimeout(deadlineTimer);
              resolve({
                status: response.statusCode,
                headers: response.headers,
                body: Buffer.concat(chunks),
              });
            });
            response.on('error', () =>
              rejectSafe('PINNED_RESPONSE_FAILED', 'Pinned response failed'),
            );
          },
        );
        request.setTimeout(timeoutMs, () => {
          if (settled) return;
          request.destroy();
          rejectSafe('PINNED_REQUEST_TIMEOUT', 'Pinned request timed out');
        });
        request.on('error', () => rejectSafe('PINNED_REQUEST_FAILED', 'Pinned request failed'));
        request.end(body || undefined);
      } catch {
        request?.destroy?.();
        rejectSafe('PINNED_REQUEST_FAILED', 'Pinned request failed');
      }
    });
  };
}

export const PINNED_HTTPS_LIMITS = Object.freeze({
  maximum_request_bytes: MAX_REQUEST_BYTES,
  maximum_response_bytes: MAX_ALLOWED_RESPONSE_BYTES,
  maximum_timeout_ms: 60_000,
});
