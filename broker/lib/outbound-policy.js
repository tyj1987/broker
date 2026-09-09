import { BlockList, isIP } from 'node:net';

const BLOCKED_NAMES = new Set([
  'localhost', 'localhost.localdomain', 'metadata', 'metadata.google.internal', 'instance-data',
]);

const BLOCKED_V4 = new BlockList();
for (const [network, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
  ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
]) BLOCKED_V4.addSubnet(network, prefix, 'ipv4');

const BLOCKED_V6 = new BlockList();
for (const [network, prefix] of [
  ['::', 128], ['::1', 128], ['::ffff:0:0', 96],
  ['64:ff9b::', 96], ['64:ff9b:1::', 48], ['100::', 64],
  ['2001::', 23], ['2001:db8::', 32], ['2002::', 16],
  ['fc00::', 7], ['fe80::', 10], ['ff00::', 8],
]) BLOCKED_V6.addSubnet(network, prefix, 'ipv6');

const ALWAYS_FORBIDDEN_HEADERS = new Set([
  'authorization', 'cookie', 'host', 'proxy-authorization', 'proxy-authenticate',
  'connection', 'content-length', 'transfer-encoding', 'upgrade', 'te', 'trailer',
  'forwarded', 'via', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto',
  'x-real-ip', 'x-ssl-client-cert', 'x-ssl-client-verify',
  'x-broker-relay-secret', 'x-broker-upstream-authorization',
]);

const DEFAULT_ALLOWED_HEADERS = new Set(['accept', 'content-type', 'if-match', 'if-none-match']);

export class OutboundPolicyError extends Error {
  constructor(message, code = 'OUTBOUND_POLICY_DENIED') {
    super(message);
    this.name = 'OutboundPolicyError';
    this.code = code;
  }
}

function normalizeHostname(hostname) {
  return String(hostname || '').toLowerCase().replace(/\.$/, '');
}

export function assertPublicDestination(hostname) {
  const host = normalizeHostname(hostname).replace(/^\[|\]$/g, '');
  if (!host || BLOCKED_NAMES.has(host) || host.endsWith('.localhost') || host.endsWith('.local')) {
    throw new OutboundPolicyError('Destination host is not permitted');
  }
  const family = isIP(host);
  if (family === 4 && BLOCKED_V4.check(host, 'ipv4')) {
    throw new OutboundPolicyError('Private or reserved IPv4 destinations are not permitted');
  }
  if (family === 6 && BLOCKED_V6.check(host, 'ipv6')) {
    throw new OutboundPolicyError('Private or reserved IPv6 destinations are not permitted');
  }
  if (family !== 0) throw new OutboundPolicyError('IP-literal destinations are not permitted');
  return host;
}

export function assertPublicResolvedAddress(address) {
  const host = normalizeHostname(address).replace(/^\[|\]$/g, '');
  const family = isIP(host);
  if (family === 4 && !BLOCKED_V4.check(host, 'ipv4')) return host;
  if (family === 6 && !BLOCKED_V6.check(host, 'ipv6')) return host;
  throw new OutboundPolicyError('DNS resolved to a private, reserved, or invalid address');
}

export function parsePinnedUpstream(upstream) {
  let base;
  try { base = new URL(String(upstream || '')); } catch {
    throw new OutboundPolicyError('Service upstream is not a valid URL');
  }
  if (base.protocol !== 'https:') throw new OutboundPolicyError('Service upstream must use HTTPS');
  if (base.username || base.password || base.hash || base.search) {
    throw new OutboundPolicyError('Service upstream must not contain credentials, query, or fragment');
  }
  assertPublicDestination(base.hostname);
  return base;
}

export function buildPinnedUrl(upstream, requestPath, query) {
  const base = parsePinnedUpstream(upstream);
  const rawPath = String(requestPath || '/');
  if (!rawPath.startsWith('/') || rawPath.startsWith('//') || rawPath.includes('\\') || /[\u0000-\u001f\u007f]/.test(rawPath)) {
    throw new OutboundPolicyError('Request path must be a normalized absolute path');
  }
  let decoded = rawPath;
  for (let i = 0; i < 2; i += 1) {
    try { decoded = decodeURIComponent(decoded); } catch {
      throw new OutboundPolicyError('Request path contains invalid encoding');
    }
  }
  if (decoded.includes('\\') || decoded.startsWith('//') || /(^|\/)\.\.?($|\/)/.test(decoded) || /[\r\n\0]/.test(decoded)) {
    throw new OutboundPolicyError('Request path contains a forbidden escape or traversal');
  }
  const url = new URL(rawPath, base.origin);
  if (url.origin !== base.origin || url.username || url.password || url.hash) {
    throw new OutboundPolicyError('Request URL escaped the configured upstream');
  }
  if (query !== undefined && query !== null) {
    if (typeof query !== 'object' || Array.isArray(query)) throw new OutboundPolicyError('Query must be an object');
    for (const [key, value] of Object.entries(query)) {
      if (value !== null && value !== undefined) url.searchParams.set(key, String(value));
    }
  }
  return url;
}

export function validateMethod(method, allowedMethods = ['GET', 'POST']) {
  const normalized = String(method || 'GET').toUpperCase();
  const allowed = new Set((allowedMethods || []).map((item) => String(item).toUpperCase()));
  if (!allowed.has(normalized)) throw new OutboundPolicyError(`HTTP method ${normalized} is not permitted`);
  return normalized;
}

export function sanitizeCallerHeaders(headers, allowedHeaders = []) {
  if (headers === undefined || headers === null) return {};
  if (typeof headers !== 'object' || Array.isArray(headers)) throw new OutboundPolicyError('Headers must be an object');
  const allowed = new Set([...DEFAULT_ALLOWED_HEADERS, ...allowedHeaders.map((h) => String(h).toLowerCase())]);
  const result = {};
  for (const [name, value] of Object.entries(headers)) {
    const lower = String(name).toLowerCase();
    if (ALWAYS_FORBIDDEN_HEADERS.has(lower) || lower.startsWith('sec-') || lower.startsWith('x-forwarded-')) {
      throw new OutboundPolicyError(`Caller header ${lower} is not permitted`);
    }
    if (!allowed.has(lower)) throw new OutboundPolicyError(`Caller header ${lower} is not allowlisted`);
    if (Array.isArray(value) || /[\r\n]/.test(String(value))) throw new OutboundPolicyError(`Caller header ${lower} is invalid`);
    result[lower] = String(value);
  }
  return result;
}
