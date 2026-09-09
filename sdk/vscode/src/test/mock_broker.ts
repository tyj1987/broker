// Mock HTTPS broker for VS Code SDK tests.
// Generates a fresh self-signed cert via `openssl` (assumed present on PATH).
// Tests pass `insecureSkipVerify: true` to skip CA verification.
import * as https from 'node:https';
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
  const bundled = 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe';
  const openssl = process.env.OPENSSL_BIN
    || (process.platform === 'win32' && fs.existsSync(bundled) ? bundled : 'openssl');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'broker-vscode-test-'));
  const certPath = path.join(tmp, 'cert.pem');
  const keyPath = path.join(tmp, 'key.pem');
  const out = spawnSync(openssl, [
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

export async function startMockBroker(): Promise<{ port: number; certPath: string; keyPath: string; stop: () => Promise<void> }> {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  server = null;
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
        } else if (url === '/api/v2/operations' && method === 'POST') {
          const parsed = JSON.parse(body || '{}');
          res.writeHead(202, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ id: '00000000-0000-4000-8000-000000000001', provider: parsed.provider, operation_id: parsed.operation_id, status: 'waiting' }));
        } else if (url === '/api/v2/operations/00000000-0000-4000-8000-000000000001' && method === 'GET') {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ id: '00000000-0000-4000-8000-000000000001', provider: 'github', operation_id: 'repo.read', status: 'completed' }));
        } else if (url === '/api/v2/approvals' && method === 'POST') {
          const parsed = JSON.parse(body || '{}');
          res.writeHead(201, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ id: '00000000-0000-4000-8000-000000000002', requester: 'test', provider: parsed.provider, operation_id: parsed.operation_id, account_ref: parsed.account_ref, environment: parsed.environment, resource_ref: parsed.typed_parameters.resource_ref, required_approvals: 2, approvals: [], status: 'REQUESTED', created_at: '2026-09-09T00:00:00Z', expires_at: '2026-09-09T00:05:00Z' }));
        } else if (url === '/api/v2/approvals' && method === 'GET') {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ approvals: [{ id: '00000000-0000-4000-8000-000000000002', status: 'REQUESTED' }] }));
        } else if (url === '/api/v2/approvals/00000000-0000-4000-8000-000000000002/decision' && method === 'POST') {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ id: '00000000-0000-4000-8000-000000000002', status: 'APPROVED' }));
        } else if (url === '/api/v2/approvals/00000000-0000-4000-8000-000000000002/cancel' && method === 'POST') {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ id: '00000000-0000-4000-8000-000000000002', status: 'CANCELLED' }));
        } else if (url === '/api/v1/proxy/github' && method === 'POST') {
          const parsed = JSON.parse(body || '{}');
          if (parsed.path === '/forbidden') {
            res.writeHead(403, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ error: 'forbidden' }));
          } else {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ ok: true, request: parsed }));
          }
        } else {
          res.writeHead(404, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'no route' }));
        }
      });
    }
  );
  await new Promise<void>((resolve, reject) => {
    server!.once('error', reject);
    server!.listen(0, '127.0.0.1', () => {
      const addr = server!.address();
      if (addr && typeof addr === 'object') port = addr.port;
      resolve();
    });
  });
  return {
    port,
    certPath: certs.certPath,
    keyPath: certs.keyPath,
    stop: async () => {
      if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
      server = null;
      port = 0;
    },
  };
}
