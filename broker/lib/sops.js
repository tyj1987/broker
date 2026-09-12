// broker/lib/sops.js — SOPS encrypt/decrypt helpers (zero deps beyond node:fs/spawn)
// Extracted from server.js in Phase B for testability and reuse by MCP / CLI.

import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, unlinkSync, renameSync } from 'node:fs';
import { join, dirname, resolve as resolvePath } from 'node:path';

function sopsFailure(code, cause) {
  const error = new Error(code);
  if (cause) error.cause = cause;
  return error;
}

/**
 * Decrypt a SOPS-encrypted file to plaintext string.
 * @param {string} filePath
 * @param {{ ageKeyFile?: string }} [opts]
 * @returns {Promise<string>}
 */
export function sopsDecrypt(filePath, opts = {}) {
  const ageKeyFile = opts.ageKeyFile || process.env.AGE_KEY_FILE || process.env.SOPS_AGE_KEY_FILE;
  return new Promise((resolve, reject) => {
    if (!existsSync(filePath)) {
      return reject(sopsFailure('sops_file_unavailable'));
    }
    const env = { ...process.env };
    if (ageKeyFile) env.SOPS_AGE_KEY_FILE = ageKeyFile;

    const args = ['--decrypt'];
    if (ageKeyFile && existsSync(ageKeyFile)) {
      const pub = readFileSync(ageKeyFile, 'utf8').match(/public key: (\S+)/)?.[1];
      if (pub) args.push('--age', pub);
    }
    args.push(filePath);

    const child = spawn('sops', args, { env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let out = '', err = '';
    child.stdout.on('data', d => out += d.toString());
    child.stderr.on('data', d => err += d.toString());
    child.on('error', e => reject(sopsFailure('sops_decrypt_unavailable', e)));
    child.on('close', code => {
      if (code !== 0) return reject(sopsFailure('sops_decrypt_failed', { code, stderr: err }));
      resolve(out);
    });
  });
}

/**
 * Atomic SOPS encrypt: write plaintext to .tmp, sops --encrypt --in-place, rename.
 * Tmp path preserves the target extension so .sops.yaml path_regex still matches.
 * @param {string} targetPath
 * @param {string} plaintext
 * @param {{ ageKeyFile?: string }} [opts]
 * @returns {Promise<void>}
 */
export function sopsEncryptAtomic(targetPath, plaintext, opts = {}) {
  const ageKeyFile = opts.ageKeyFile || process.env.AGE_KEY_FILE || process.env.SOPS_AGE_KEY_FILE;
  return new Promise((resolve, reject) => {
    const env = { ...process.env };
    if (ageKeyFile) env.SOPS_AGE_KEY_FILE = ageKeyFile;
    const dir = dirname(targetPath);
    const base = targetPath.slice(dir.length + 1);
    const dot = base.lastIndexOf('.');
    const stem = dot > 0 ? base.slice(0, dot) : base;
    const ext = dot > 0 ? base.slice(dot) : '';
    const tmpPath = join(dir, `.${stem}.tmp.${process.pid}.${Date.now()}${ext}`);
    try {
      writeFileSync(tmpPath, plaintext, { encoding: 'utf8', mode: 0o600 });
    } catch (e) {
      return reject(sopsFailure('sops_temp_write_failed', e));
    }
    const args = ['--encrypt', '--in-place', tmpPath];
    if (ageKeyFile && existsSync(ageKeyFile)) {
      const pub = readFileSync(ageKeyFile, 'utf8').match(/public key: (\S+)/)?.[1];
      if (pub) args.unshift('--age', pub);
    }
    const child = spawn('sops', args, { env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let err = '';
    child.stderr.on('data', d => err += d.toString());
    child.on('error', e => reject(sopsFailure('sops_encrypt_unavailable', e)));
    child.on('close', code => {
      if (code !== 0) {
        try { unlinkSync(tmpPath); } catch {}
        return reject(sopsFailure('sops_encrypt_failed', { code, stderr: err }));
      }
      try {
        renameSync(tmpPath, targetPath);
        resolve();
      } catch (e) {
        try { unlinkSync(tmpPath); } catch {}
        reject(sopsFailure('sops_target_replace_failed', e));
      }
    });
  });
}
