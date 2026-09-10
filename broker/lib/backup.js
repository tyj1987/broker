// broker/lib/backup.js — backup inventory + redacted config export (no deps)
// Phase F. Does NOT copy private keys by default — emits a checklist/manifest.

import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  openSync,
  readdirSync,
  readFileSync,
  writeFileSync,
  mkdirSync,
} from 'node:fs';
import { join, basename } from 'node:path';

/**
 * File inventory entry for backup documentation.
 * @param {string} path
 * @param {{ required?: boolean, sensitive?: boolean }} meta
 */
function fileEntry(path, meta = {}) {
  if (!path) {
    return { path: null, present: false, ...meta };
  }
  let present = false;
  let size = null;
  let mtime = null;
  let sha256 = null;
  let descriptor;
  try {
      const flags = constants.O_RDONLY | (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW);
      descriptor = openSync(path, flags);
      const st = fstatSync(descriptor);
      if (!st.isFile()) throw new Error('not a regular file');
      present = true;
      size = st.size;
      mtime = st.mtime.toISOString();
      if (!meta.sensitive && st.size < 5 * 1024 * 1024) {
        sha256 = createHash('sha256').update(readFileSync(descriptor)).digest('hex');
      }
  } catch {
    /* absent, inaccessible and unsafe paths are all excluded */
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
  return {
    path,
    name: path ? basename(path) : null,
    present,
    size,
    mtime,
    sha256,
    required: !!meta.required,
    sensitive: !!meta.sensitive,
  };
}

/**
 * Build a backup manifest (what to copy / verify), not the archive itself.
 *
 * @param {object} paths
 * @param {string} [paths.configPath]
 * @param {string} [paths.secretsSopsPath] encrypted secrets file
 * @param {string} [paths.ageKeyPath] sensitive
 * @param {string} [paths.caCert]
 * @param {string} [paths.caKey] sensitive
 * @param {string} [paths.serverCert]
 * @param {string} [paths.serverKey] sensitive
 * @param {string} [paths.auditDir]
 * @param {string} [paths.clientsDir] client certs dir
 * @returns {object} manifest
 */
export function buildBackupManifest(paths = {}) {
  const files = [
    fileEntry(paths.configPath, { required: true, sensitive: false }),
    fileEntry(paths.secretsSopsPath, { required: true, sensitive: false }), // ciphertext ok to hash
    fileEntry(paths.ageKeyPath, { required: true, sensitive: true }),
    fileEntry(paths.caCert, { required: true, sensitive: false }),
    fileEntry(paths.caKey, { required: true, sensitive: true }),
    fileEntry(paths.serverCert, { required: true, sensitive: false }),
    fileEntry(paths.serverKey, { required: true, sensitive: true }),
  ].filter((e) => e.path);

  let auditFiles = [];
  if (paths.auditDir && existsSync(paths.auditDir)) {
    try {
      auditFiles = readdirSync(paths.auditDir)
        .filter((f) => f.startsWith('audit-'))
        .map((f) => fileEntry(join(paths.auditDir, f), { sensitive: false }));
    } catch {
      auditFiles = [];
    }
  }

  let clientCertCount = 0;
  if (paths.clientsDir && existsSync(paths.clientsDir)) {
    try {
      clientCertCount = readdirSync(paths.clientsDir, { withFileTypes: true })
        .filter((d) => d.isDirectory() || d.name.endsWith('.crt') || d.name.endsWith('.pem'))
        .length;
    } catch {
      clientCertCount = 0;
    }
  }

  const missingRequired = files.filter((f) => f.required && !f.present).map((f) => f.path);
  const checklist = [
    'Copy encrypted SOPS secrets file (ciphertext)',
    'Copy broker config YAML (redact if it embeds secrets)',
    'Copy CA cert + server cert (public)',
    'Store age private key + CA key in offline/HSM — never in git',
    'Record client cert inventory count and renew schedule',
    'Retain audit JSONL per AUDIT_RETAIN_DAYS policy',
    'Verify restore on standby with preflightPaths + validateBrokerConfig',
  ];

  return {
    generated_at: new Date().toISOString(),
    ok: missingRequired.length === 0,
    missing_required: missingRequired,
    files,
    audit_files: auditFiles,
    client_cert_entries: clientCertCount,
    checklist,
  };
}

/**
 * Deep-clone config with secrets redacted for export/debug.
 * @param {object} config
 * @returns {object}
 */
export function redactConfigForExport(config) {
  if (!config || typeof config !== 'object') return config;
  const out = JSON.parse(JSON.stringify(config));

  if (out.clients) {
    for (const c of Object.values(out.clients)) {
      if (!c || typeof c !== 'object') continue;
      if (c.password) c.password = '[REDACTED]';
      if (c.totp_secret) c.totp_secret = '[REDACTED]';
      if (c.totp_recovery_codes_hash) c.totp_recovery_codes_hash = ['[REDACTED]'];
    }
  }
  if (out.api_keys) {
    const keys = Array.isArray(out.api_keys) ? out.api_keys : Object.values(out.api_keys);
    for (const k of keys) {
      if (!k || typeof k !== 'object') continue;
      if (k.secret) k.secret = '[REDACTED]';
      if (k.key_hash) k.key_hash = '[REDACTED]';
      if (k.hash) k.hash = '[REDACTED]';
    }
  }
  return out;
}

/**
 * Write manifest JSON to a directory (for ops scripts).
 * @returns {string} path written
 */
export function writeBackupManifest(dir, paths, filename = 'backup-manifest.json') {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  const manifest = buildBackupManifest(paths);
  const out = join(dir, filename);
  writeFileSync(out, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  return out;
}
