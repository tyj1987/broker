// broker/lib/proxy-body.js — bounded upstream response buffering.

export const DEFAULT_MAX_UPSTREAM_RESPONSE_BYTES = 16 * 1024 * 1024;
export const ABSOLUTE_MAX_UPSTREAM_RESPONSE_BYTES = 256 * 1024 * 1024;

export function maxUpstreamResponseBytes(env = process.env) {
  const raw = env.BROKER_MAX_UPSTREAM_RESPONSE_BYTES;
  if (raw == null || raw === '') return DEFAULT_MAX_UPSTREAM_RESPONSE_BYTES;
  const n = Number(raw);
  if (!Number.isSafeInteger(n) || n <= 0) return DEFAULT_MAX_UPSTREAM_RESPONSE_BYTES;
  return Math.min(n, ABSOLUTE_MAX_UPSTREAM_RESPONSE_BYTES);
}

export async function readLimitedResponseBody(
  stream,
  maxBytes = DEFAULT_MAX_UPSTREAM_RESPONSE_BYTES,
) {
  if (!stream || typeof stream[Symbol.asyncIterator] !== 'function') {
    throw new TypeError('upstream response is not an async-readable stream');
  }
  const limit =
    Number.isSafeInteger(maxBytes) && maxBytes > 0
      ? Math.min(maxBytes, ABSOLUTE_MAX_UPSTREAM_RESPONSE_BYTES)
      : DEFAULT_MAX_UPSTREAM_RESPONSE_BYTES;

  const contentLength = Number(stream.headers?.['content-length']);
  if (Number.isFinite(contentLength) && contentLength > limit) {
    if (typeof stream.destroy === 'function') stream.destroy();
    throw new Error(
      `Upstream response too large: advertised ${contentLength} bytes exceeds ${limit}`,
    );
  }

  const chunks = [];
  let total = 0;
  for await (const chunk of stream) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buf.length;
    if (total > limit) {
      if (typeof stream.destroy === 'function') stream.destroy();
      throw new Error(`Upstream response too large: exceeds ${limit} bytes`);
    }
    chunks.push(buf);
  }
  return Buffer.concat(chunks, total);
}
