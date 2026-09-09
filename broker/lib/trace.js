// broker/lib/trace.js — W3C traceparent + request id (no deps)
// Phase D: parse / generate / inject for proxy upstream calls.
// Spec: https://www.w3.org/TR/trace-context/

import { randomBytes } from 'node:crypto';

const TRACEPARENT_RE =
  /^([\da-f]{2})-([\da-f]{32})-([\da-f]{16})-([\da-f]{2})$/i;

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
  return { version: version.toLowerCase(), traceId: traceId.toLowerCase(), parentId: parentId.toLowerCase(), flags: flags.toLowerCase() };
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
  const existing =
    h['x-request-id'] ||
    h['x-correlation-id'] ||
    h['x-amzn-trace-id'] ||
    null;
  if (existing && typeof existing === 'string') {
    const candidate = existing.trim();
    if (/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(candidate)) return candidate;
  }
  return newSpanId() + newSpanId(); // 32 hex
}
