#!/usr/bin/env node

import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { lstatSync, realpathSync, fstatSync } from 'node:fs';
import { readProtectedInputFile } from '../lib/protected-input-file.js';
import { runAuditRecoveryCheck } from './audit-recovery-check.js';
import { safeAuditRecoveryCheckCode } from '../lib/audit-recovery-check.js';

export const RECOVERY_SERVICE_PATHS = Object.freeze({
  config: '/etc/secret-broker/audit/recovery.json',
  checkpoint: '/etc/secret-broker/audit/recovery-checkpoint.json',
});

// Service inputs contain public pins and operator evidence, not secret keys.
// Root controls them; the recovery group can read but cannot change them.
export function readRecoveryServiceInput(path, label, maxBytes, {
  stat = lstatSync, realpath = realpathSync.native,
  read = readProtectedInputFile, fstat = fstatSync, groups = process.getgroups?.() ?? [],
} = {}) {
  if (!Object.values(RECOVERY_SERVICE_PATHS).includes(path)) throw new Error('Recovery input unavailable');
  for (const directory of ['/etc', '/etc/secret-broker', '/etc/secret-broker/audit']) {
    const value = stat(directory);
    if (!value.isDirectory() || value.isSymbolicLink() || value.uid !== 0
      || (value.mode & 0o022) || realpath(directory) !== directory) throw new Error('Recovery input unavailable');
  }
  // Repeat the check through the actual opened descriptor in readProtectedInputFile.
  return read(path, label, maxBytes, { sensitive: false, effectiveUid: 0,
    fstatImpl: descriptor => {
      const value = fstat(descriptor);
      if (value.uid !== 0 || value.nlink !== 1 || (value.mode & 0o777) !== 0o440
        || !groups.includes(value.gid)) throw new Error('Recovery input unavailable');
      return value;
    },
  });
}

export async function runRecoveryServiceCheck(argv, { read = readRecoveryServiceInput, ...dependencies } = {}) {
  if (!Array.isArray(argv) || argv.length !== 2 || argv[0] !== '--config'
    || argv[1] !== RECOVERY_SERVICE_PATHS.config) throw new Error('Recovery arguments invalid');
  return runAuditRecoveryCheck(['--config-file', RECOVERY_SERVICE_PATHS.config,
    '--checkpoint-file', RECOVERY_SERVICE_PATHS.checkpoint], { ...dependencies, readFile: read });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try { await runRecoveryServiceCheck(process.argv.slice(2)); }
  catch (error) {
    console.error(JSON.stringify({ status: 'failed', code: safeAuditRecoveryCheckCode(error) }));
    process.exitCode = 1;
  }
}
