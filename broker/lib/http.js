// broker/lib/http.js — small HTTP response helpers (zero deps)
// Phase B extraction from server.js.

import { BROKER_VERSION } from '../version.js';
import { securityHeaders } from './security-headers.js';

/**
 * Send JSON or plain-text response with standard broker headers.
 * Security headers (CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy,
 * Permissions-Policy, COOP/CORP) are merged in by default. Pass `{ noSecurityHeaders: true }`
 * to opt out (rare; only used by the local-health server which has its own header set).
 *
 * @param {import('node:http').ServerResponse} res
 * @param {number} status
 * @param {object|string} body
 * @param {Record<string, string>} [extraHeaders]
 */
export function send(res, status, body, extraHeaders = {}) {
  if (res.headersSent || res.writableEnded) return;
  const isJson = typeof body === 'object';
  const payload = isJson ? JSON.stringify(body) : body;
  // Caller can request HTML kind for CSP purposes, but JSON is the safer default.
  const kind = extraHeaders?._kind || (isJson ? 'json' : 'text');
  const sec = extraHeaders?.noSecurityHeaders ? {} : securityHeaders({ kind });
  // Strip the internal flag before merging into real headers
  const extras = { ...extraHeaders };
  delete extras._kind;
  delete extras.noSecurityHeaders;
  // Do not fingerprint unauthenticated responses with X-Broker-Version.
  // Callers that want it pass the header explicitly (authenticated send()).
  const headers = {
    'Content-Type': isJson ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload, 'utf8'),
    ...sec,
    ...(isJson ? { 'Cache-Control': 'no-store', Pragma: 'no-cache' } : {}),
    ...extras,
  };
  delete headers.exposeVersion;
  if (extraHeaders.exposeVersion === true && headers['X-Broker-Version'] == null) {
    headers['X-Broker-Version'] = BROKER_VERSION;
  }
  res.writeHead(status, headers);
  res.end(payload);
}

/**
 * Send an opaque binary payload with the same hardened headers and no-store
 * cache policy used by sensitive JSON responses.
 *
 * @param {import('node:http').ServerResponse} res
 * @param {number} status
 * @param {Buffer|Uint8Array} body
 * @param {string} contentType
 * @param {Record<string, string>} [extraHeaders]
 */
export function sendBuffer(
  res,
  status,
  body,
  contentType = 'application/octet-stream',
  extraHeaders = {},
) {
  if (res.headersSent || res.writableEnded) return;
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(body);
  const kind = extraHeaders?._kind || 'json';
  const sec = extraHeaders?.noSecurityHeaders ? {} : securityHeaders({ kind });
  const extras = { ...extraHeaders };
  delete extras._kind;
  delete extras.noSecurityHeaders;
  const headers = {
    'Content-Type': contentType,
    'Content-Length': payload.length,
    'Cache-Control': 'no-store',
    Pragma: 'no-cache',
    ...sec,
    ...extras,
  };
  delete headers.exposeVersion;
  if (extraHeaders.exposeVersion === true && headers['X-Broker-Version'] == null) {
    headers['X-Broker-Version'] = BROKER_VERSION;
  }
  res.writeHead(status, headers);
  res.end(payload);
}

/**
 * Read request body (max 1MB). Parses JSON when possible.
 * @param {import('node:http').IncomingMessage} req
 * @returns {Promise<object|null>}
 */
export const DEFAULT_MAX_REQUEST_BODY_BYTES = 1024 * 1024;

export class RequestBodyTooLargeError extends Error {
  constructor(maxBytes = DEFAULT_MAX_REQUEST_BODY_BYTES) {
    super(`Request body too large (max ${maxBytes} bytes)`);
    this.name = 'RequestBodyTooLargeError';
    this.code = 'REQUEST_BODY_TOO_LARGE';
    this.statusCode = 413;
  }
}

export function readBody(req, { maxBytes = DEFAULT_MAX_REQUEST_BODY_BYTES } = {}) {
  return new Promise((resolve, reject) => {
    const limit =
      Number.isSafeInteger(maxBytes) && maxBytes > 0 ? maxBytes : DEFAULT_MAX_REQUEST_BODY_BYTES;
    const chunks = [];
    let size = 0;
    let settled = false;
    let tooLarge = false;

    const contentLength = Number(req.headers?.['content-length']);
    if (Number.isFinite(contentLength) && contentLength > limit) {
      settled = true;
      tooLarge = true;
      // Do not drain an oversized body onto a keep-alive connection. The
      // async wrapper marks the 413 response as Connection: close, so pausing
      // here prevents subsequent request bytes from being consumed as body.
      if (typeof req.pause === 'function') req.pause();
      reject(new RequestBodyTooLargeError(limit));
      return;
    }

    req.on('data', (chunk) => {
      if (tooLarge) return;
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += buf.length;
      if (size > limit) {
        tooLarge = true;
        settled = true;
        chunks.length = 0;
        if (typeof req.pause === 'function') req.pause();
        reject(new RequestBodyTooLargeError(limit));
        return;
      }
      chunks.push(buf);
    });
    req.on('end', () => {
      if (settled) return;
      settled = true;
      const buf = Buffer.concat(chunks, size).toString('utf8');
      if (!buf) return resolve(null);
      try {
        resolve(JSON.parse(buf));
      } catch {
        resolve({ _raw: buf });
      }
    });
    req.on('error', (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    });
  });
}

/**
 * JSON error helper.
 * @param {import('node:http').ServerResponse} res
 * @param {number} status
 * @param {string} msg
 */
export function jsonError(res, status, msg) {
  return send(res, status, { error: msg, status });
}

/**
 * Convert an async request handler into an EventEmitter-safe listener.
 * Node's HTTP server does not await a returned Promise; without this wrapper,
 * a rejected async handler can become an unhandled rejection and terminate the
 * process. Error details are deliberately not reflected to clients.
 */
export function wrapAsyncRequestHandler(handler, opts = {}) {
  if (typeof handler !== 'function') throw new TypeError('handler must be a function');
  const errorResponder =
    typeof opts.errorResponder === 'function' ? opts.errorResponder : jsonError;
  const onError = typeof opts.onError === 'function' ? opts.onError : null;

  return function safeRequestListener(req, res) {
    Promise.resolve()
      .then(() => handler(req, res))
      .catch((err) => {
        try {
          onError?.(err, req, res);
        } catch {}

        if (res.headersSent || res.writableEnded) {
          if (!res.writableEnded && typeof res.destroy === 'function') res.destroy(err);
          return;
        }

        const status =
          Number.isInteger(err?.statusCode) && err.statusCode >= 400 && err.statusCode <= 599
            ? err.statusCode
            : 500;
        const message = status === 413 ? 'Request body too large' : 'Internal server error';
        if (status === 413) {
          // An oversized or malformed Content-Length leaves unread request
          // bytes on the socket. Reusing that connection can corrupt the next
          // HTTP request, so make the close explicit before writing the 413.
          try {
            res.shouldKeepAlive = false;
            res.setHeader?.('Connection', 'close');
          } catch {}
        }
        try {
          errorResponder(res, status, message);
        } catch {
          try {
            res.destroy?.(err);
          } catch {}
        }
      });
  };
}
