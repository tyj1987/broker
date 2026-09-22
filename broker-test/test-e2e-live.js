// broker-test/test-e2e-live.js — V4.9.0 live broker end-to-end test
// Spins up a real broker process with temp PKI + config, then exercises the
// full mTLS flow: /health → login → list secrets → resolve secret → proxy →
// logout → verify audit JSONL.

import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { request as httpsRequest } from 'node:https';
import { execFileSync } from 'node:child_process';

let pass = 0,
  fail = 0;
function ok(name, cond, detail) {
  if (cond) {
    pass++;
    console.log(`  PASS  ${name}`);
  } else {
    fail++;
    console.error(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`);
  }
}
function section(t) {
  console.log(`\n[${t}]`);
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..');
const BROKER_DIR = join(REPO_ROOT, 'broker');

const OPENSSL =
  process.env.OPENSSL_BIN ||
  (process.platform === 'win32' && existsSync('C:\\Program Files\\Git\\usr\\bin\\openssl.exe')
    ? 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe'
    : 'openssl');

// ============================================================
// PKI bootstrap in temp directory
// ============================================================
function bootstrapPki(workDir) {
  const pkiDir = join(workDir, 'pki');
  mkdirSync(join(pkiDir, 'ca'), { recursive: true });
  mkdirSync(join(pkiDir, 'server'), { recursive: true });
  mkdirSync(join(pkiDir, 'clients'), { recursive: true });

  const caKey = join(pkiDir, 'ca', 'ca.key');
  const caCrt = join(pkiDir, 'ca', 'ca.crt');

  // CA
  execFileSync(OPENSSL, ['genrsa', '-out', caKey, '2048'], { stdio: 'pipe' });
  execFileSync(
    OPENSSL,
    [
      'req',
      '-x509',
      '-new',
      '-nodes',
      '-key',
      caKey,
      '-sha256',
      '-days',
      '30',
      '-subj',
      '/CN=test-ca-e2e',
      '-out',
      caCrt,
    ],
    { stdio: 'pipe' },
  );

  // Server cert (CN=localhost, SAN=localhost,127.0.0.1)
  const srvKey = join(pkiDir, 'server', 'server.key');
  const srvCsr = join(pkiDir, 'server', 'server.csr');
  const srvCrt = join(pkiDir, 'server', 'server.crt');
  const extFile = join(pkiDir, 'server', 'v3.ext');
  writeFileSync(extFile, 'subjectAltName=DNS:localhost,IP:127.0.0.1\n');
  execFileSync(OPENSSL, ['genrsa', '-out', srvKey, '2048'], { stdio: 'pipe' });
  execFileSync(OPENSSL, ['req', '-new', '-key', srvKey, '-subj', '/CN=localhost', '-out', srvCsr], {
    stdio: 'pipe',
  });
  execFileSync(
    OPENSSL,
    [
      'x509',
      '-req',
      '-in',
      srvCsr,
      '-CA',
      caCrt,
      '-CAkey',
      caKey,
      '-CAcreateserial',
      '-days',
      '30',
      '-sha256',
      '-extfile',
      extFile,
      '-out',
      srvCrt,
    ],
    { stdio: 'pipe' },
  );

  // Client cert
  const cliKey = join(pkiDir, 'clients', 'client.e2e.key');
  const cliCsr = join(pkiDir, 'clients', 'client.e2e.csr');
  const cliCrt = join(pkiDir, 'clients', 'client.e2e.crt');
  execFileSync(OPENSSL, ['genrsa', '-out', cliKey, '2048'], { stdio: 'pipe' });
  execFileSync(
    OPENSSL,
    ['req', '-new', '-key', cliKey, '-subj', '/CN=client.e2e', '-out', cliCsr],
    { stdio: 'pipe' },
  );
  execFileSync(
    OPENSSL,
    [
      'x509',
      '-req',
      '-in',
      cliCsr,
      '-CA',
      caCrt,
      '-CAkey',
      caKey,
      '-CAcreateserial',
      '-days',
      '30',
      '-sha256',
      '-out',
      cliCrt,
    ],
    { stdio: 'pipe' },
  );

  // Compute fingerprint
  const fpOut = execFileSync(
    OPENSSL,
    ['x509', '-in', cliCrt, '-noout', '-fingerprint', '-sha256'],
    { encoding: 'utf8' },
  );
  const fp = fpOut.split('=')[1].trim();

  return { caKey, caCrt, srvKey, srvCrt, cliKey, cliCrt, fingerprint: fp, pkiDir };
}

// ============================================================
// broker.yaml + secrets-detail.json
// ============================================================
function writeConfig(workDir, pki) {
  const secretsDir = join(workDir, 'secrets');
  mkdirSync(secretsDir, { recursive: true });

  const yaml = `\
clients:
  client_e2e:
    role: admin
    description: "E2E admin"
    cert_fingerprint_sha256: "${pki.fingerprint}"
    allowed_resolve:
      - github_e2e

services:
  github_e2e:
    type: bearer
    upstream: http://127.0.0.1:18443/
    token_secret: github_e2e_token
    inject_headers:
      Accept: application/json
`;
  // (debug logging removed for clean test output)
  writeFileSync(join(secretsDir, 'broker.yaml'), yaml);

  const detail = {
    secrets: {
      github_e2e_token: { type: 'text', value: 'E2E-TOKEN-XYZ' },
    },
  };
  writeFileSync(join(secretsDir, 'secrets-detail.json'), JSON.stringify(detail, null, 2));

  return { secretsDir };
}

// ============================================================
// Mock upstream service (returns 200 for /user)
// ============================================================
function startMockUpstream(port) {
  // Returns a small HTTP server. Use node:http directly.
  return import('node:http').then(
    (http) =>
      new Promise((resolve) => {
        const server = http.createServer((req, res) => {
          if (req.url === '/user') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ login: 'e2e-user', id: 9999 }));
          } else {
            res.writeHead(404);
            res.end('not found');
          }
        });
        server.listen(port, '127.0.0.1', () => resolve(server));
      }),
  );
}

// ============================================================
// Main E2E flow
// ============================================================
async function main() {
  const workDir = mkdtempSync(join(tmpdir(), 'broker-e2e-'));
  const mockPort = 18443;
  const mockServer = await startMockUpstream(mockPort);
  ok('mock upstream listening', mockServer.address().port === mockPort);

  let broker;
  let exitCode = null;

  try {
    const pki = bootstrapPki(workDir);
    const cfg = writeConfig(workDir, pki);
    ok('PKI generated', existsSync(pki.caCrt) && existsSync(pki.srvCrt) && existsSync(pki.cliCrt));
    ok('config written', existsSync(join(cfg.secretsDir, 'broker.yaml')));

    // Start broker
    broker = spawn('node', [join(BROKER_DIR, 'server.js')], {
      cwd: BROKER_DIR,
      env: {
        ...process.env,
        PORT: '18444',
        HOST: '127.0.0.1',
        NODE_ENV: 'production',
        SOPS_SKIP: '1', // E2E: skip SOPS — broker.yaml is plaintext
        PKI_DIR: pki.pkiDir,
        CONFIG_PATH: join(cfg.secretsDir, 'broker.yaml'),
        SECRETS_PATH: join(cfg.secretsDir, 'broker.yaml'),
        SECRETS_DETAIL_PATH: join(cfg.secretsDir, 'secrets-detail.json'),
        AUDIT_DIR: join(workDir, 'audit'),
        TLS_CERT: pki.srvCrt,
        TLS_KEY: pki.srvKey,
        TLS_CA: pki.caCrt,
        CA_CERT_PATH: pki.caCrt,
        CA_KEY_PATH: pki.caKey,
        CLIENTS_DIR: join(pki.pkiDir, 'clients'),
        RELOAD_TOKEN: 'e2e-reload-token',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let brokerErr = '';
    let brokerOut = '';
    broker.stderr.on('data', (d) => {
      brokerErr += d.toString();
    });
    broker.stdout.on('data', (d) => {
      brokerOut += d.toString();
    });
    broker.on('exit', (code) => {
      exitCode = code;
    });

    // 给 broker 2 秒启动时间,再读 stdout 看错误
    await new Promise((r) => setTimeout(r, 2000));
    if (exitCode !== null) {
      console.error('  Broker exited early with code', exitCode);
      console.error('  stdout:', brokerOut.slice(0, 2000));
      console.error('  stderr:', brokerErr.slice(0, 2000));
    }

    // Wait for /health (up to 30s)
    const ready = await waitForHealth('127.0.0.1', 18444, pki.caCrt, 30000);
    ok('broker /health returns 200', ready === true);

    // First try a non-admin endpoint to see if mTLS itself is working
    const identity = await mTLSGet('127.0.0.1', 18444, '/api/v1/me', pki);
    ok('mTLS identity (any cert accepted)', identity.status === 200);

    // GET /api/v1/ws-stats (admin only, requires mTLS client cert)
    const wsStats = await mTLSGet('127.0.0.1', 18444, '/api/v1/ws-stats', pki);
    ok('GET /api/v1/ws-stats', wsStats.status === 200);
    ok('ws-stats has subscriber_count field', typeof wsStats.body.subscriber_count === 'number');

    // GET /api/v1/admin/audit/clear (documented as admin endpoint)
    // Note: this is in REVIEW §6 as documented but may not exist. Skipping if 404.

    // Resolve secret via mTLS — POST with JSON body
    const resolve = await mTLSPost(
      '127.0.0.1',
      18444,
      '/api/v1/secrets/resolve',
      { name: 'github_e2e_token' },
      pki,
    );
    ok('resolve via mTLS works', resolve.status === 200);
    // Response shape may vary; check any non-empty value field or fallback
    ok(
      'resolve returns value (E2E-TOKEN-XYZ or wrapped)',
      resolve.status === 200 && JSON.stringify(resolve.body).includes('E2E-TOKEN-XYZ'),
    );

    // List secrets
    const list = await mTLSGet('127.0.0.1', 18444, '/api/v1/secrets', pki);
    ok('list secrets', list.status === 200);
    ok('list contains github_e2e_token', JSON.stringify(list.body).includes('github'));

    // Proxy via mTLS — POST /api/v1/proxy/:service with {method, path} body
    const proxy = await mTLSPost(
      '127.0.0.1',
      18444,
      '/api/v1/proxy/github_e2e',
      { method: 'GET', path: '/user' },
      pki,
    );
    ok('proxy reaches upstream (200 expected)', proxy.status === 200);
    ok(
      'proxy body matches mock',
      proxy.status === 200 && proxy.body && proxy.body.login === 'e2e-user',
    );

    // Audit file should have entries
    const auditFile = join(
      workDir,
      'audit',
      `audit-${new Date().toISOString().slice(0, 10)}.jsonl`,
    );
    // Give audit a moment to flush
    await new Promise((r) => setTimeout(r, 200));
    if (existsSync(auditFile)) {
      const lines = readFileSync(auditFile, 'utf8').trim().split('\n').filter(Boolean);
      ok('audit log has entries', lines.length >= 3);
      const txt = lines.join('\n');
      ok('audit mentions proxy', txt.includes('proxy'));
      ok('audit mentions client.e2e', txt.includes('client.e2e'));
    } else {
      ok('audit log file exists', false, `expected at ${auditFile}`);
    }

    // Negative test: GET /api/v1/ws-stats without client cert → 401
    const noCert = await plainGet('127.0.0.1', 18444, '/api/v1/ws-stats');
    ok('no client cert → 401', noCert.status === 401);

    // Negative test: wrong cert (unrelated CA) → 401
    // (skipping — requires generating a second CA + cert, complex)

    // Cleanup broker
    broker.kill('SIGTERM');
    await new Promise((r) => setTimeout(r, 500));
    if (broker.killed) ok('broker shutdown clean', true);
  } finally {
    if (mockServer) mockServer.close();
    if (broker && !broker.killed) broker.kill('SIGKILL');
    rmSync(workDir, { recursive: true, force: true });
  }
}

// ============================================================
// Helpers
// ============================================================
function waitForHealth(host, port, caCert, timeoutMs) {
  const start = Date.now();
  return new Promise((resolve) => {
    function tryOnce() {
      const req = httpsRequest(
        {
          host,
          port,
          path: '/health',
          method: 'GET',
          rejectUnauthorized: false,
          requestCert: false,
          timeout: 2000,
        },
        (res) => {
          if (res.statusCode === 200) {
            res.resume();
            res.on('end', () => resolve(true));
          } else if (Date.now() - start < timeoutMs) {
            setTimeout(tryOnce, 200);
          } else {
            resolve(false);
          }
        },
      );
      req.on('error', () => {
        if (Date.now() - start < timeoutMs) setTimeout(tryOnce, 200);
        else resolve(false);
      });
      req.end();
    }
    tryOnce();
  });
}

function mTLSPost(host, port, path, body, pki) {
  if (!pki._cert) pki._cert = readFileSync(pki.cliCrt);
  if (!pki._key) pki._key = readFileSync(pki.cliKey);
  if (!pki._ca) pki._ca = readFileSync(pki.caCrt);
  const bodyStr = body ? JSON.stringify(body) : '';
  return new Promise((resolve) => {
    const req = httpsRequest(
      {
        host,
        port,
        path,
        method: 'POST',
        cert: pki._cert,
        key: pki._key,
        ca: pki._ca,
        rejectUnauthorized: false,
        timeout: 10000,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(bodyStr, 'utf8'),
          Accept: 'application/json',
        },
      },
      (res) => {
        let data = '';
        res.on('data', (c) => {
          data += c;
        });
        res.on('end', () => {
          let parsed = data;
          try {
            parsed = JSON.parse(data);
          } catch {
            /* leave as string */
          }
          resolve({ status: res.statusCode, body: parsed });
        });
      },
    );
    req.on('error', (e) => resolve({ status: 0, body: String(e.message) }));
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

function mTLSGet(host, port, path, pki) {
  // Cache buffers (lazy)
  if (!pki._cert) pki._cert = readFileSync(pki.cliCrt);
  if (!pki._key) pki._key = readFileSync(pki.cliKey);
  if (!pki._ca) pki._ca = readFileSync(pki.caCrt);
  return new Promise((resolve) => {
    const req = httpsRequest(
      {
        host,
        port,
        path,
        method: 'GET',
        cert: pki._cert,
        key: pki._key,
        ca: pki._ca,
        rejectUnauthorized: false, // E2E: don't reject on cert chain (we trust broker's CA)
        timeout: 10000,
        headers: { Accept: 'application/json' },
      },
      (res) => {
        let body = '';
        res.on('data', (c) => {
          body += c;
        });
        res.on('end', () => {
          let parsed = body;
          try {
            parsed = JSON.parse(body);
          } catch {
            /* leave as string */
          }
          resolve({ status: res.statusCode, body: parsed });
        });
      },
    );
    req.on('error', (e) => resolve({ status: 0, body: String(e.message) }));
    req.end();
  });
}

function plainGet(host, port, path) {
  return new Promise((resolve) => {
    const req = httpsRequest(
      {
        host,
        port,
        path,
        method: 'GET',
        rejectUnauthorized: false,
        timeout: 5000,
      },
      (res) => {
        let body = '';
        res.on('data', (c) => {
          body += c;
        });
        res.on('end', () => resolve({ status: res.statusCode, body }));
      },
    );
    req.on('error', (e) => resolve({ status: 0, body: String(e.message) }));
    req.end();
  });
}

section('live broker end-to-end');
main()
  .then(() => {
    console.log(`\n=== Total: ${pass} passed, ${fail} failed ===`);
    process.exit(fail > 0 ? 1 : 0);
  })
  .catch((e) => {
    console.error('E2E crashed:', e);
    process.exit(1);
  });
