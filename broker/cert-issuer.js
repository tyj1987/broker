// cert-issuer.js — Phase 1.3: client certificate lifecycle helpers.
// Thin wrapper around `openssl` for issuing / revoking client certs. The CA
// key + cert live in pki/ca/; per-client files go under pki/clients/.
//
// Why shell out to openssl instead of node crypto:
//   1. We already use openssl in the install script; same cert format / SAN
//      semantics, predictable behavior across platforms.
//   2. CRL generation in node would require `node-forge` (extra dep).
//   3. Days/extensions match install-ecs.sh exactly — operator can audit.
//
// Errors throw an Error with the openssl stderr so callers can surface
// a useful message to the admin UI without exposing the secret key paths.

import { spawn } from 'node:child_process';
import { existsSync, unlinkSync, readFileSync, writeFileSync, mkdirSync, chmodSync } from 'node:fs';
import { join } from 'node:path';

// Path resolution. We accept two layouts:
//   (A) standard: PKI_DIR/ca/ca.crt, PKI_DIR/clients/, PKI_DIR/server/
//   (B) local-test: PKI_DIR/ca.crt, PKI_DIR/clients/  (no ca/ subdir)
// We pick the first path that exists on disk.
function findFirst(...paths) {
  for (const p of paths) {
    if (p && existsSync(p)) return p;
  }
  return paths[0] || null;
}
function pickClientsDir() {
  if (process.env.CLIENTS_DIR) return process.env.CLIENTS_DIR;
  if (process.env.PKI_DIR) return join(process.env.PKI_DIR, 'clients');
  return null;
}

const CA_CRT   = findFirst(process.env.CA_CERT_PATH, process.env.TLS_CA);
const CA_KEY   = findFirst(process.env.CA_KEY_PATH, CA_CRT && CA_CRT.replace(/ca\.crt$/, 'ca.key'));
const CLIENTS_DIR = pickClientsDir();
if (!CA_CRT) throw new Error('CA cert not found: set CA_CERT_PATH or TLS_CA env');
if (!CA_KEY) throw new Error('CA key not found: set CA_KEY_PATH or place ca.key next to ca.crt');
if (!CLIENTS_DIR) throw new Error('CLIENTS_DIR not set and PKI_DIR not provided');

// Resolve openssl binary. On Windows, `spawn` won't auto-append .exe, so we
// honor OPENSSL_BIN env first, then probe the executable extension.
import { execFileSync } from 'node:child_process';
const OPENSSL_BIN_ENV = process.env.OPENSSL_BIN;
const OPENSSL_BIN = (() => {
  if (OPENSSL_BIN_ENV) return OPENSSL_BIN_ENV;
  const isWin = process.platform === 'win32';
  const candidates = isWin ? ['openssl.exe', 'openssl'] : ['openssl'];
  for (const c of candidates) {
    try { execFileSync(c, ['version'], { stdio: 'ignore' }); return c; } catch {}
  }
  return candidates[0]; // best-effort; spawn will throw a clear ENOENT
})();

function run(cmd, args, opts = {}) {
  // Always route openssl invocations through the resolved binary.
  const realCmd = cmd === 'openssl' ? OPENSSL_BIN : cmd;
  return new Promise((resolve, reject) => {
    const child = spawn(realCmd, args, { ...opts, windowsHide: true });
    let err = '', out = '';
    child.stdout.on('data', d => out += d.toString());
    child.stderr.on('data', d => err += d.toString());
    child.on('error', e => reject(new Error(`${cmd} spawn failed: ${e.message}`)));
    child.on('close', code => {
      if (code !== 0) reject(new Error(`${cmd} exited ${code}: ${err.trim()}`));
      else resolve(out.trim());
    });
  });
}

function clientPaths(cn) {
  return {
    key:  join(CLIENTS_DIR, `${cn}.key`),
    csr:  join(CLIENTS_DIR, `${cn}.csr`),
    crt:  join(CLIENTS_DIR, `${cn}.crt`),
    ext:  join(CLIENTS_DIR, `${cn}.ext`),
  };
}

// Issue a fresh client cert: generate 2048-bit key, build CSR, sign with CA.
// Returns { fingerprint_sha256, cert_pem, key_pem } — key_pem is the secret
// to bundle into the install zip; cert_pem is also bundled; fingerprint
// goes into broker.yaml for the server to recognize the new cert.
export async function issueClientCert(cn, { days = 365 } = {}) {
  if (!existsSync(CA_KEY)) throw new Error(`CA key not found: ${CA_KEY}`);
  if (!existsSync(CA_CRT)) throw new Error(`CA cert not found: ${CA_CRT}`);
  if (!existsSync(CLIENTS_DIR)) mkdirSync(CLIENTS_DIR, { recursive: true });

  const p = clientPaths(cn);
  // 1. Generate key
  await run('openssl', ['genrsa', '-out', p.key, '2048']);
  // 2. Build CSR
  await run('openssl', ['req', '-new', '-key', p.key, '-out', p.csr, '-subj', `/CN=${cn}`]);
  // 3. Build ext file
  const ext = [
    'authorityKeyIdentifier=keyid,issuer',
    'basicConstraints=CA:FALSE',
    'keyUsage = digitalSignature, keyEncipherment',
    'extendedKeyUsage = clientAuth',
  ].join('\n') + '\n';
  writeFileSync(p.ext, ext);
  // 4. Sign
  await run('openssl', ['x509', '-req', '-in', p.csr,
    '-CA', CA_CRT, '-CAkey', CA_KEY, '-CAcreateserial',
    '-out', p.crt, '-days', String(days), '-sha256',
    '-extfile', p.ext]);
  // 5. Cleanup
  try { unlinkSync(p.csr); } catch {}
  try { unlinkSync(p.ext); } catch {}
  try { chmodSync(p.key, 0o600); } catch {}
  // 6. Read fingerprint
  const fpRaw = await run('openssl', ['x509', '-in', p.crt, '-noout', '-fingerprint', '-sha256']);
  const fingerprint = fpRaw.split('=')[1] || '';
  return {
    fingerprint_sha256: fingerprint,
    cert_pem: readFileSync(p.crt, 'utf8'),
    key_pem: readFileSync(p.key, 'utf8'),
  };
}

// Compute fingerprint of an existing PEM cert on disk. Returns uppercase
// hex with colons (the same format install-ecs.sh uses and the same
// format broker.yaml stores).
export async function certFingerprint(cn) {
  const p = clientPaths(cn);
  if (!existsSync(p.crt)) throw new Error(`Cert not found: ${p.crt}`);
  const out = await run('openssl', ['x509', '-in', p.crt, '-noout', '-fingerprint', '-sha256']);
  return out.split('=')[1] || '';
}

// Read cert PEM (for bundle download).
export function readClientCertPem(cn) {
  const p = clientPaths(cn);
  if (!existsSync(p.crt)) throw new Error(`Cert not found: ${p.crt}`);
  return readFileSync(p.crt, 'utf8');
}
export function readClientKeyPem(cn) {
  const p = clientPaths(cn);
  if (!existsSync(p.key)) throw new Error(`Key not found: ${p.key}`);
  return readFileSync(p.key, 'utf8');
}

// Delete cert files for a client (used by revoke). Idempotent.
export function deleteClientCertFiles(cn) {
  const p = clientPaths(cn);
  for (const f of [p.crt, p.key]) {
    try { unlinkSync(f); } catch {}
  }
}

// Read CA cert PEM (for bundle).
export function readCaCertPem() {
  if (!existsSync(CA_CRT)) throw new Error(`CA cert not found: ${CA_CRT}`);
  return readFileSync(CA_CRT, 'utf8');
}

export const paths = { CA_KEY, CA_CRT, CLIENTS_DIR, clientPaths };
