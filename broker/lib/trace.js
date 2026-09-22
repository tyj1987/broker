// broker/lib/trace.js — W3C traceparent + request id (no deps)
// Phase D: parse / generate / inject for proxy upstream calls.
// Spec: https://www.w3.org/TR/trace-context/

import { randomBytes } from 'node:crypto';

const TRACEPARENT_RE = /^([\da-f]{2})-([\da-f]{32})-([\da-f]{16})-([\da-f]{2})$/i;

/**
 * @typedef {{ version: string, traceId: string, parentId: string, flags: string }}
 */

/**
 * Parse traceparent header value.
 * @param {string|undefined|null} header
 * @returns {import('./trace.js').TraceContext|null}
 */
export function parseTraceparent(header) {
  if (!header || typeof header !== 'string') return null;
  const m = header.trim().match(TRACEPARENT_RE);
  if (!m) return null;
  const [, version, traceId, parentId, flags] = m;
  if (traceId === '0'.repeat(32) || parentId === '0'.repeat(16)) return null;
  return {
    version: version.toLowerCase(),
    traceId: traceId.toLowerCase(),
    parentId: parentId.toLowerCase(),
    flags: flags.toLowerCase(),
  };
}

/** 16 random bytes → 32 hex (trace-id) */
export function newTraceId() {
  return randomBytes(16).toString('hex');
}

/** 8 random bytes → 16 hex (span/parent id) */
export function newSpanId() {
  return randomBytes(8).toString('hex');
}

/**
 * Create a new root context or child of incoming.
 * @param {string|undefined} incomingHeader
 * @returns {{ traceId: string, spanId: string, parentId: string|null, flags: string, traceparent: string, sampled: boolean }}
 */
export function continueOrCreateTrace(incomingHeader) {
  const parsed = parseTraceparent(incomingHeader);
  const spanId = newSpanId();
  if (parsed) {
    const flags = parsed.flags;
    const sampled = (parseInt(flags, 16) & 0x1) === 1;
    const traceparent = `00-${parsed.traceId}-${spanId}-${flags}`;
    return {
      traceId: parsed.traceId,
      spanId,
      parentId: parsed.parentId,
      flags,
      traceparent,
      sampled,
    };
  }
  const traceId = newTraceId();
  const flags = '01'; // sampled by default for new roots
  const traceparent = `00-${traceId}-${spanId}-${flags}`;
  return {
    traceId,
    spanId,
    parentId: null,
    flags,
    traceparent,
    sampled: true,
  };
}

/**
 * Headers to inject on upstream (proxy) requests.
 * @param {{ traceparent: string, requestId?: string }}
 * @returns {Record<string, string>}
 */
export function outboundTraceHeaders(ctx) {
  const h = {
    traceparent: ctx.traceparent,
  };
  if (ctx.requestId) {
    h['x-request-id'] = ctx.requestId;
    h['x-correlation-id'] = ctx.requestId;
  }
  return h;
}

/**
 * Extract request id from common headers or generate.
 */
export function resolveRequestId(reqHeaders = {}) {
  const h = reqHeaders;
  const existing = h['x-request-id'] || h['x-correlation-id'] || h['x-amzn-trace-id'] || null;
  if (existing && typeof existing === 'string' && existing.length < 200) {
    return existing.split(',')[0].trim();
  }
  return newSpanId() + newSpanId(); // 32 hex
}

// ============================================================
// v4.6.0: OTLP/HTTP exporter (zero-dep, best-effort)
// Env: BROKER_OTLP_ENDPOINT  (e.g. http://otel-collector:4318)
// Env: BROKER_OTLP_HEADERS    (optional, comma-separated "k=v")
// Env: BROKER_OTLP_SAMPLE    (optional 0-1, default 0.1 = 10%)
// When BROKER_OTLP_ENDPOINT is unset, all calls are no-ops.
// ============================================================

import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { URL } from 'node:url';

const OTLP_ENDPOINT = process.env.BROKER_OTLP_ENDPOINT || '';
const OTLP_HEADERS_RAW = process.env.BROKER_OTLP_HEADERS || '';
const OTLP_SAMPLE = Math.min(1, Math.max(0, parseFloat(process.env.BROKER_OTLP_SAMPLE || '0.1')));

/** @type {Record<string,string>|null} */
let otlpHeaders = null;
if (OTLP_ENDPOINT) {
  try {
    otlpHeaders = { 'content-type': 'application/json' };
    if (OTLP_HEADERS_RAW) {
      for (const pair of OTLP_HEADERS_RAW.split(',')) {
        const eq = pair.indexOf('=');
        if (eq > 0) otlpHeaders[pair.slice(0, eq).trim()] = pair.slice(eq + 1).trim();
      }
    }
  } catch {
    otlpHeaders = null;
  }
}

/**
 * Send a minimal OTLP/HTTP JSON span payload. Best-effort; failures are
 * swallowed (logging at debug level). No retries — trace export must never
 * block the request path.
 *
 * @param {{
 *   traceId: string, spanId: string, parentSpanId?: string|null,
 *   name: string, kind?: 'SPAN_KIND_SERVER'|'SPAN_KIND_CLIENT'|'SPAN_KIND_INTERNAL',
 *   startMs: number, endMs: number,
 *   attributes?: Record<string, string|number|boolean>,
 *   status?: { code: 'STATUS_CODE_OK'|'STATUS_CODE_ERROR', message?: string }
 * }} span
 */
export function exportSpan(span) {
  if (!OTLP_ENDPOINT || !otlpHeaders) return;
  if (Math.random() > OTLP_SAMPLE) return; // sample before building payload

  const startNs = BigInt(span.startMs) * 1000000n;
  const endNs = BigInt(span.endMs) * 1000000n;
  const attributes = Object.entries(span.attributes || {}).map(([k, v]) => ({
    key: k,
    value: { stringValue: String(v) },
  }));
  const body = {
    resourceSpans: [
      {
        resource: {
          attributes: [
            { key: 'service.name', value: { stringValue: 'secret-broker' } },
            {
              key: 'service.version',
              value: { stringValue: process.env.BROKER_VERSION || 'unknown' },
            },
          ],
        },
        scopeSpans: [
          {
            scope: { name: 'broker.lib.trace', version: '4.6.0' },
            spans: [
              {
                traceId: span.traceId,
                spanId: span.spanId,
                parentSpanId: span.parentSpanId || undefined,
                name: span.name,
                kind: span.kind || 'SPAN_KIND_INTERNAL',
                startTimeUnixNano: startNs.toString(),
                endTimeUnixNano: endNs.toString(),
                attributes,
                status: span.status || { code: 'STATUS_CODE_OK' },
              },
            ],
          },
        ],
      },
    ],
  };
  try {
    const u = new URL('/v1/traces', OTLP_ENDPOINT);
    const isHttps = u.protocol === 'https:';
    const req = (isHttps ? httpsRequest : httpRequest)({
      hostname: u.hostname,
      port: u.port || (isHttps ? 443 : 80),
      path: u.pathname + (u.search || ''),
      method: 'POST',
      headers: otlpHeaders,
      timeout: 2000,
    });
    req.on('error', () => {
      /* swallow */
    });
    req.on('timeout', () => {
      try {
        req.destroy();
      } catch {
        /* */
      }
    });
    req.write(JSON.stringify(body));
    req.end();
  } catch {
    /* swallow */
  }
}
