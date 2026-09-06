// broker/routes/ops.js — admin ops: backup manifest, redacted config
// Phase F. Requires admin ctx.

import { buildBackupManifest, redactConfigForExport } from '../../lib/backup.js';

/**
 * @returns {boolean|Promise<boolean>}
 */
export async function handleOps(req, res, route, deps) {
  const { method, pathname: p } = route;
  if (!p.startsWith('/api/v1/ops')) return false;

  const { send, jsonError, ctx } = deps;
  if (!ctx?.client || ctx.client.role !== 'admin') {
    jsonError(res, 403, 'Admin role required');
    return true;
  }

  // GET /api/v1/ops/backup-manifest
  if (method === 'GET' && p === '/api/v1/ops/backup-manifest') {
    const paths = deps.backupPaths || {};
    const manifest = typeof deps.buildBackupManifest === 'function'
      ? deps.buildBackupManifest(paths)
      : buildBackupManifest(paths);
    send(res, 200, manifest);
    return true;
  }

  // GET /api/v1/ops/config-export (redacted)
  if (method === 'GET' && p === '/api/v1/ops/config-export') {
    const redacted = redactConfigForExport(deps.config || {});
    send(res, 200, { exported_at: new Date().toISOString(), config: redacted });
    return true;
  }

  return false;
}
