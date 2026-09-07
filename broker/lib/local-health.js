// broker/lib/local-health.js — loopback / unix-socket health listener (not public).
// Serves only /health /live /ready (and aliases). mode 0600 on unix sockets.

import { createServer } from 'node:http';
import { chmodSync, existsSync, unlinkSync } from 'node:fs';
import { platform } from 'node:os';

/**
 * @returns {{ path: string } | { host: string, port: number }}
 */
export function defaultHealthBind() {
  if (process.env.BROKER_HEALTH_SOCKET) {
    return { path: process.env.BROKER_HEALTH_SOCKET };
  }
  if (process.env.BROKER_HEALTH_BIND) {
    const raw = process.env.BROKER_HEALTH_BIND;
    const idx = raw.lastIndexOf(':');
    const host = idx === -1 ? '127.0.0.1' : raw.slice(0, idx) || '127.0.0.1';
    const port = parseInt(idx === -1 ? raw : raw.slice(idx + 1), 10);
    return { host, port: Number.isFinite(port) ? port : 9080 };
  }
  if (platform() === 'win32') {
    return { host: '127.0.0.1', port: parseInt(process.env.BROKER_HEALTH_PORT || '9080', 10) };
  }
  return { path: '/tmp/broker-health.sock' };
}

export function describeHealthBind(listen) {
  if (listen.path) return listen.path;
  return `${listen.host}:${listen.port}`;
}

/**
 * @param {{ listen: { path?: string, host?: string, port?: number }, onRequest: Function, log?: Function }} opts
 * @returns {Promise<import('node:http').Server>}
 */
export function startLocalHealthServer(opts) {
  const { listen, onRequest, log } = opts;
  const server = createServer((req, res) => {
    Promise.resolve(onRequest(req, res)).catch(() => {
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: 'local health handler failed', status: 500 }));
      }
    });
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    if (listen.path && existsSync(listen.path)) {
      try { unlinkSync(listen.path); } catch { /* stale socket */ }
    }
    const onListening = () => {
      server.removeListener('error', reject);
      if (listen.path) {
        try { chmodSync(listen.path, 0o600); } catch { /* win32 / already 0600 */ }
      }
      if (typeof log === 'function') {
        log(`[broker] local health listener on ${describeHealthBind(listen)}`);
      }
      resolve(server);
    };
    if (listen.path) server.listen(listen.path, onListening);
    else server.listen(listen.port, listen.host || '127.0.0.1', onListening);
  });
}
