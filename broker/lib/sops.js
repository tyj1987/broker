// SOPS subprocesses have bounded time/output; atomic writes never share a
// plaintext scratch filename and clean up on every spawn/exit/rename failure.
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, unlinkSync, renameSync } from 'node:fs';
import { join, dirname, basename, extname } from 'node:path';
import { randomUUID } from 'node:crypto';

function settings(opts) {
  const ageKeyFile = opts.ageKeyFile || process.env.AGE_KEY_FILE || process.env.SOPS_AGE_KEY_FILE;
  const env = { ...process.env };
  if (ageKeyFile) env.SOPS_AGE_KEY_FILE = ageKeyFile;
  const publicKey =
    ageKeyFile && existsSync(ageKeyFile)
      ? readFileSync(ageKeyFile, 'utf8').match(/public key: (\S+)/)?.[1]
      : null;
  return { env, publicKey };
}

function runSops(args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn('sops', args, {
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const output = [];
    let bytes = 0;
    let stopped = null;
    const deadline = setTimeout(() => {
      stopped = new Error('sops operation timed out');
      child.kill();
    }, 30_000);
    deadline.unref?.();
    child.stdout.on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes > 64 * 1024 * 1024) {
        stopped = new Error('sops output limit exceeded');
        child.kill();
      } else output.push(chunk);
    });
    // Drain diagnostic output without propagating plaintext or private paths.
    child.stderr.resume();
    child.once('error', (error) => {
      clearTimeout(deadline);
      reject(new Error(`sops spawn failed (${error.code || 'unknown'})`));
    });
    child.once('close', (code) => {
      clearTimeout(deadline);
      if (stopped) reject(stopped);
      else if (code !== 0) reject(new Error(`sops operation failed (code ${code})`));
      else resolve(Buffer.concat(output).toString('utf8'));
    });
  });
}

export async function sopsDecrypt(filePath, opts = {}) {
  if (!existsSync(filePath)) throw new Error(`File not found: ${filePath}`);
  const { env, publicKey } = settings(opts);
  return runSops(['--decrypt', ...(publicKey ? ['--age', publicKey] : []), filePath], env);
}

export async function sopsEncryptAtomic(targetPath, plaintext, opts = {}) {
  const { env, publicKey } = settings(opts);
  const ext = extname(targetPath);
  const stem = basename(targetPath, ext);
  const tmpPath = join(dirname(targetPath), `.${stem}.tmp.${process.pid}.${randomUUID()}${ext}`);
  let created = false;
  try {
    writeFileSync(tmpPath, plaintext, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    created = true;
    await runSops(
      [...(publicKey ? ['--age', publicKey] : []), '--encrypt', '--in-place', tmpPath],
      env,
    );
    renameSync(tmpPath, targetPath);
  } finally {
    if (created) {
      try {
        unlinkSync(tmpPath);
      } catch (error) {
        if (error.code !== 'ENOENT')
          throw new Error('SOPS scratch cleanup failed', { cause: error });
      }
    }
  }
}
