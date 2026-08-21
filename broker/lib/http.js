// broker/lib/http.js — small HTTP response helpers (zero deps)
// Phase B extraction from server.js.

import { BROKER_VERSION } from '../version.js';

/**
 * Send JSON or plain-text response with standard broker headers.
 * @param {import('node:http').ServerResponse} res
 * @param {number} status
 * @param {object|string} body
 * @param {Record<string, string>} [extraHeaders]
 */
export function send(res, status, body, extraHeaders = {}) {
  const isJson = typeof body === 'object';
  const payload = isJson ? JSON.stringify(body) : body;
  res.writeHead(status, {
    'Content-Type': isJson ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload, 'utf8'),
    'X-Broker-Version': BROKER_VERSION,
    ...extraHeaders,
  });
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
