// broker/lib/request-context.js — AsyncLocalStorage request scope (no deps)
// Phase D: requestId + trace available to audit/log/proxy without param drilling.

import { AsyncLocalStorage } from 'node:async_hooks';
import { continueOrCreateTrace, resolveRequestId } from './trace.js';

const storage = new AsyncLocalStorage();

/**
 * @returns {{ requestId: string, traceId: string, spanId: string, traceparent: string, sampled: boolean, parentId: string|null }|undefined}
 */
export function getRequestContext() {
  return storage.getStore();
}

export function getRequestId() {
  return storage.getStore()?.requestId;
}

export function getTraceparent() {
  return storage.getStore()?.traceparent;
}

/**
 * Run fn inside a new request context derived from incoming headers.
 * @param {Record<string, string|string[]|undefined>} headers
 * @param {() => any} fn
 */
export function runWithRequestContext(headers, fn) {
  const flat = normalizeHeaders(headers);
  const requestId = resolveRequestId(flat);
  const trace = continueOrCreateTrace(flat.traceparent);
  const ctx = {
    requestId,
    traceId: trace.traceId,
    spanId: trace.spanId,
    parentId: trace.parentId,
    flags: trace.flags,
    traceparent: trace.traceparent,
    sampled: trace.sampled,
  };
  return storage.run(ctx, fn);
}

function normalizeHeaders(headers) {
  const out = {};
  if (!headers) return out;
  for (const [k, v] of Object.entries(headers)) {
    const key = k.toLowerCase();
    out[key] = Array.isArray(v) ? v[0] : v;
  }
  return out;
}

/** Merge trace + request id into response headers (mutates res). */
export function setResponseTraceHeaders(res) {
  const ctx = getRequestContext();
  if (!ctx || !res?.setHeader) return;
  try {
    res.setHeader('x-request-id', ctx.requestId);
    res.setHeader('traceparent', ctx.traceparent);
  } catch {
    // headers may already be sent
  }
}
