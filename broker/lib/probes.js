// broker/lib/probes.js — dependency probes for readiness (no deps)
// Phase F. TCP / HTTP checks with timeout; no external libraries.

import net from 'node:net';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';

/**
 * TCP connect probe.
 * @param {string} host
 * @param {number} port
 * @param {number} [timeoutMs=2000]
 * @returns {Promise<{ ok: boolean, ms: number, error?: string }>}
 */
export function probeTcp(host, port, timeoutMs = 2000) {
  const t0 = Date.now();
  return new Promise((resolve) => {
    const socket = net.connect({ host, port }, () => {
      socket.destroy();
      resolve({ ok: true, ms: Date.now() - t0 });
    });
    socket.setTimeout(timeoutMs);
    socket.on('timeout', () => {
      socket.destroy();
      resolve({ ok: false, ms: Date.now() - t0, error: 'timeout' });
    });
    socket.on('error', (e) => {
      resolve({ ok: false, ms: Date.now() - t0, error: 'probe_failed' });
    });
  });
}

/**
 * HTTP(S) GET probe — status < 500 => ok by default.
 * @param {string} url
 * @param {{ timeoutMs?: number, okStatus?: (n: number) => boolean }} [opts]
 */
export function probeHttp(url, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? 3000;
  const okStatus = opts.okStatus || ((n) => n > 0 && n < 500);
  const t0 = Date.now();
  return new Promise((resolve) => {
    let u;
    try {
      u = new URL(url);
    } catch (e) {
      resolve({ ok: false, ms: 0, error: 'invalid url' });
      return;
    }
    const lib = u.protocol === 'https:' ? httpsRequest : httpRequest;
    const req = lib(
      {
        protocol: u.protocol,
        hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname + u.search,
        method: 'GET',
        timeout: timeoutMs,
        rejectUnauthorized: opts.rejectUnauthorized !== false,
      },
      (res) => {
        res.resume();
        resolve({
          ok: okStatus(res.statusCode || 0),
          ms: Date.now() - t0,
          statusCode: res.statusCode,
        });
      },
    );
    req.on('timeout', () => {
      req.destroy();
      resolve({ ok: false, ms: Date.now() - t0, error: 'timeout' });
    });
    req.on('error', (e) => {
      resolve({ ok: false, ms: Date.now() - t0, error: 'probe_failed' });
    });
    req.end();
  });
}

/**
 * Run a list of named probes.
 * @param {Array<{ name: string, type: 'tcp'|'http', host?: string, port?: number, url?: string, critical?: boolean, timeoutMs?: number }>}
 * @returns {Promise<{ ok: boolean, probes: object[] }>}
 */
export async function runProbes(specs = []) {
  const probes = [];
  for (const s of specs) {
    let result;
    if (s.type === 'tcp') {
      result = await probeTcp(s.host, s.port, s.timeoutMs);
    } else if (s.type === 'http') {
      result = await probeHttp(s.url, { timeoutMs: s.timeoutMs });
    } else {
      result = { ok: false, ms: 0, error: 'unknown type' };
    }
    probes.push({
      name: s.name,
      type: s.type,
      critical: s.critical !== false,
      ...result,
    });
  }
  const ok = probes.every((p) => !p.critical || p.ok);
  return { ok, probes };
}

/**
 * Build probe specs from config.services[*].healthcheck or base_url (optional).
 * Env READY_PROBES=0 to disable.
 */
export function probesFromConfig(config) {
  if (process.env.READY_PROBES === '0' || process.env.READY_PROBES === 'false') {
    return [];
  }
  const out = [];
  const services = config?.services || {};
  for (const [name, s] of Object.entries(services)) {
    if (!s || typeof s !== 'object') continue;
    if (s.healthcheck?.url) {
      out.push({
        name: `service:${name}`,
        type: 'http',
        url: s.healthcheck.url,
        critical: !!s.healthcheck.critical,
        timeoutMs: s.healthcheck.timeout_ms || 3000,
      });
    } else if (s.probe?.host && s.probe?.port) {
      out.push({
        name: `service:${name}`,
        type: 'tcp',
        host: s.probe.host,
        port: Number(s.probe.port),
        critical: !!s.probe.critical,
        timeoutMs: s.probe.timeout_ms || 2000,
      });
    }
  }
  return out;
}
