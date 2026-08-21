// broker/lib/shutdown.js — graceful SIGTERM/SIGINT drain (no deps)
// Phase E.

import { log } from './log.js';

/**
 * @typedef {{ close: (cb?: (err?: Error) => void) => void, close?: Function }}
 */

/**
 * Install process signal handlers for graceful shutdown.
 *
 * @param {object} opts
 * @param {import('node:http').Server|import('node:https').Server|null} opts.server
 * @param {Array<() => void|Promise<void>>} [opts.onShutdown] cleanup hooks (cron stop, etc.)
 * @param {number} [opts.timeoutMs=15000] force exit after
 * @param {(msg: string, fields?: object) => void} [opts.logger]
 * @returns {{ shuttingDown: () => boolean, shutdown: (reason?: string) => Promise<void> }}
 */
export function installGracefulShutdown(opts = {}) {
  const {
    server = null,
    onShutdown = [],
    timeoutMs = Number(process.env.SHUTDOWN_TIMEOUT_MS) || 15_000,
    logger = (msg, fields) => log.info(msg, fields),
  } = opts;

  let shuttingDown = false;

  async function shutdown(reason = 'signal') {
    if (shuttingDown) return;
    shuttingDown = true;
    logger('shutdown_start', { reason, timeout_ms: timeoutMs });

    const forceTimer = setTimeout(() => {
      logger('shutdown_force_exit', { reason });
      process.exit(1);
    }, timeoutMs);
    forceTimer.unref?.();

    try {
      for (const hook of onShutdown) {
        try {
          await hook();
        } catch (e) {
          logger('shutdown_hook_error', { error: String(e?.message || e) });
        }
      }

      if (server) {
        await new Promise((resolve) => {
          try {
            server.close(() => resolve());
            // stop accepting; existing connections drain via close
          } catch {
            resolve();
          }
          // also destroy idle if Node supports closeIdleConnections
          try {
            server.closeIdleConnections?.();
          } catch { /* ignore */ }
        });
      }

      clearTimeout(forceTimer);
      logger('shutdown_complete', { reason });
      process.exit(0);
    } catch (e) {
      clearTimeout(forceTimer);
      logger('shutdown_error', { error: String(e?.message || e) });
      process.exit(1);
    }
  }

  function onSignal(sig) {
    shutdown(sig).catch(() => process.exit(1));
  }

  process.once('SIGTERM', () => onSignal('SIGTERM'));
  process.once('SIGINT', () => onSignal('SIGINT'));

  return {
    shuttingDown: () => shuttingDown,
    shutdown,
  };
}

/**
 * Middleware-style: if shutting down, reject new work with 503.
 */
export function rejectIfShuttingDown(shuttingDownFn, res, jsonError) {
  if (!shuttingDownFn?.()) return false;
  if (typeof jsonError === 'function') {
    jsonError(res, 503, 'Server is shutting down');
  } else if (res && !res.headersSent) {
    res.writeHead(503, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Server is shutting down', status: 503 }));
  }
  return true;
}
