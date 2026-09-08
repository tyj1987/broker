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
export function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    const MAX = 1024 * 1024;
    req.on('data', c => {
      size += c.length;
      if (size > MAX) {
        reject(new Error('Request body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      const buf = Buffer.concat(chunks).toString('utf8');
      if (!buf) return resolve(null);
      try { resolve(JSON.parse(buf)); }
      catch { resolve({ _raw: buf }); }
    });
    req.on('error', reject);
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
