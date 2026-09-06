// Mock HTTPS broker for VS Code SDK tests.
// Generates a fresh self-signed cert via `openssl` (assumed present on PATH).
// Tests pass `verifyTls: true` to skip CA verification.
import * as https from 'node:https';
import * as tls from 'node:tls';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';

interface MockCerts {
  certPem: string;
  keyPem: string;
  certPath: string;
  keyPath: string;
}

let cachedCerts: MockCerts | null = null;

function generateSelfSigned(): MockCerts {
  if (cachedCerts) return cachedCerts;
  // Try PATH first, then common fallbacks (Git for Windows ships its own openssl.exe).
  const candidates: string[] = [];
  const which = spawnSync(process.platform === 'win32' ? 'where' : 'which', ['openssl'], { encoding: 'utf8' });
  if ((which.status ?? 1) === 0) candidates.push('openssl');
  if (process.platform === 'win32') {
    const fallbacks = [
      'C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe',
      'C:\\Program Files (x86)\\Git\\mingw64\\bin\\openssl.exe',
      'C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe',
    ];
    for (const fb of fallbacks) if (fs.existsSync(fb)) candidates.push(fb);
  }
  if (candidates.length === 0) {
    throw new Error('openssl not found on PATH and no fallback found; cannot generate self-signed test cert');
  }
  const opensslBin = candidates[0];
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'broker-vscode-test-'));
  const certPath = path.join(tmp, 'cert.pem');
  const keyPath = path.join(tmp, 'key.pem');
  const out = spawnSync(opensslBin, [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', keyPath, '-out', certPath,
    '-days', '1', '-subj', '/CN=127.0.0.1',
    '-addext', 'subjectAltName=IP:127.0.0.1',
  ], { encoding: 'utf8' });
  if ((out.status ?? 1) !== 0) {
    throw new Error(`openssl failed: ${out.stderr}`);
  }
  cachedCerts = {
    certPem: fs.readFileSync(certPath, 'utf8'),
    keyPem: fs.readFileSync(keyPath, 'utf8'),
    certPath,
    keyPath,
  };
  return cachedCerts;
}

let server: https.Server | null = null;
let port = 0;

export function startMockBroker(): { port: number; certPath: string; keyPath: string; stop: () => void } {
  if (server) { server.close(); server = null; }
  const certs = generateSelfSigned();
  server = https.createServer(
    { cert: certs.certPem, key: certs.keyPem },
    (req, res) => {
      let body = '';
      req.on('data', (c) => (body += c.toString()));
      req.on('end', () => {
        const url = req.url || '/';
        const method = req.method || 'GET';
        if (url === '/health') {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ ok: true, version: '4.1.0' }));
        } else if (url === '/api/v1/secrets' && method === 'GET') {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify([{ name: 'github.pat', type: 'github_pat' }]));
        } else if (url === '/api/v1/secrets/resolve' && method === 'POST') {
          const parsed = JSON.parse(body || '{}');
          if (parsed.name === 'github.pat') {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ name: 'github.pat', value: 'ghp_xxxxABCDEFGHIJabcdefghij' }));
          } else {
            res.writeHead(404, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ error: 'not found' }));
          }
        } else if (url && url.startsWith('/api/v1/proxy/github/forbidden')) {
          res.writeHead(403, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'forbidden' }));
        } else {
          res.writeHead(404, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'no route' }));
        }
      });
    }
  );
  server.listen(0, '127.0.0.1', () => {
    const addr = server!.address();
    if (addr && typeof addr === 'object') port = addr.port;
  });
  // wait until listening
  const start = Date.now();
  while (port === 0 && Date.now() - start < 3000) {
    // busy-wait briefly (test only)
  }
  return {
    port,
    certPath: certs.certPath,
    keyPath: certs.keyPath,
    stop: () => {
      if (server) { server.close(); server = null; }
      port = 0;
    },
  };
}
