// Starts the real Broker with ephemeral PKI and strict TLS. This DEV plaintext
// fixture is NOT evidence for production SOPS or Docker/Nginx acceptance.
import assert from 'node:assert/strict';
import https from 'node:https';
import http from 'node:http';
import { spawn, execFileSync } from 'node:child_process';
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  existsSync,
  readdirSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { X509Certificate, randomBytes, createHash } from 'node:crypto';
import { once } from 'node:events';
import { hashPassword, generateSecret, computeCode } from '../broker/totp.js';
import { generateApiKey } from '../broker/api-keys.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const dir = mkdtempSync(join(tmpdir(), 'broker-real-startup-'));
const openssl =
  process.env.OPENSSL_BIN ||
  (process.platform === 'win32' && existsSync('C:\\Program Files\\Git\\usr\\bin\\openssl.exe')
    ? 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe'
    : 'openssl');
let child;
let upstream;
let checks = 0;
let logs = '';
const check = (name, condition) => {
  assert.ok(condition, name);
  checks += 1;
  console.log(`PASS ${name}`);
};
const digest = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');
const run = (...args) =>
  execFileSync(openssl, args, { stdio: 'ignore', timeout: 15000, windowsHide: true });
for (const p of ['pki/ca', 'pki/server', 'pki/clients', 'private', 'secrets', 'audit'])
  mkdirSync(join(dir, p), { recursive: true });
try {
  run(
    'req',
    '-x509',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-keyout',
    join(dir, 'pki/ca/ca.key'),
    '-out',
    join(dir, 'pki/ca/ca.crt'),
    '-days',
    '2',
    '-subj',
    '/CN=broker-startup-fixture-ca',
  );
  function issue(name, server = false, days = '2') {
    const key = join(dir, server ? 'pki/server/server.key' : `private/${name}.key`);
    const cert = join(dir, server ? 'pki/server/server.crt' : `pki/clients/${name}.crt`);
    const csr = join(dir, 'private/request.csr');
    const ext = join(dir, 'private/request.ext');
    run(
      'req',
      '-new',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-keyout',
      key,
      '-out',
      csr,
      '-subj',
      `/CN=${name}`,
    );
    writeFileSync(
      ext,
      'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=' +
        (server ? 'serverAuth' : 'clientAuth') +
        '\n' +
        (server ? 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' : ''),
    );
    run(
      'x509',
      '-req',
      '-in',
      csr,
      '-CA',
      join(dir, 'pki/ca/ca.crt'),
      '-CAkey',
      join(dir, 'pki/ca/ca.key'),
      '-set_serial',
      '0x' + randomBytes(16).toString('hex'),
      '-out',
      cert,
      '-days',
      days,
      '-sha256',
      '-extfile',
      ext,
    );
    return {
      key: readFileSync(key),
      cert: readFileSync(cert),
      x509: new X509Certificate(readFileSync(cert)),
    };
  }
  issue('localhost', true);
  const admin = issue('client.startup-admin');
  const user = issue('client.startup-user');
  const expired = issue('client.startup-expired', false, '0');
  const pw = 'Startup-' + randomBytes(24).toString('base64url');
  const seed = generateSecret();
  const now = new Date().toISOString();
  const token = 'fixture-' + randomBytes(24).toString('hex');
  upstream = http.createServer((req, res) => {
    if (req.url === '/huge') {
      res.writeHead(200, { 'Content-Length': '8192' });
      return res.end(Buffer.alloc(8192));
    }
    const body = JSON.stringify({
      ok: true,
      path: req.url,
      auth_ok: req.headers.authorization === `Bearer ${token}`,
    });
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
      'Set-Cookie': 'broker_session=evil',
      Connection: 'X-Hop',
      'X-Hop': 'private',
    });
    res.end(body);
  });
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  const clients = {};
  for (const [name, material, role] of [
    ['client.startup-admin', admin, 'admin'],
    ['client.startup-user', user, 'developer'],
    ['client.startup-expired', expired, 'developer'],
  ]) {
    clients[name] = {
      role,
      cert_fingerprint_sha256: material.x509.fingerprint256,
      cert_expires_at: new Date(material.x509.validTo).toISOString(),
      last_cert_rotation: now,
      password: hashPassword(pw),
      password_set_at: now,
      last_password_change: now,
      allow_password_login: true,
      preferred_2fa: role === 'admin' ? 'totp' : 'none',
      totp_secret: role === 'admin' ? seed : null,
      totp_recovery_codes_hash: [],
      mfa_required: role === 'admin',
      allowed_resolve: ['^VISIBLE$'],
      allowed_proxy:
        role === 'admin' ? ['.*'] : [{ service: 'echo', paths: ['^/safe/'], methods: ['GET'] }],
      rate_limit: 'unlimited',
    };
  }
  const limited = generateApiKey('limited', 'client.startup-user', { rate_limit: { minute: 2 } });
  const delegated = generateApiKey('delegated', 'client.startup-admin', {
    rate_limit: 'unlimited',
  });
  const config = {
    schema_version: 3,
    clients,
    api_keys: [limited.key_obj, delegated.key_obj],
    notifications: {},
    healthcheck: { enabled: false },
    services: {
      echo: {
        type: 'bearer',
        upstream: `http://127.0.0.1:${upstream.address().port}`,
        token_secret: 'VISIBLE',
        token_field: 'value',
        allow_paths: ['^/safe/', '^/huge$'],
        allow_methods: ['GET'],
      },
    },
  };
  const configPath = join(dir, 'secrets/broker.yaml');
  const detailPath = join(dir, 'secrets/secrets-detail.json');
  const configText = JSON.stringify(config);
  const detailText = JSON.stringify({
    version: 1,
    secrets: {
      VISIBLE: { type: 'custom', fields: { value: token }, created_at: now, updated_at: now },
    },
  });
  writeFileSync(configPath, configText);
  writeFileSync(detailPath, detailText);
  const env = {
    ...process.env,
    NODE_ENV: 'test',
    SOPS_SKIP: '1',
    PORT: '0',
    HOST: '127.0.0.1',
    BROKER_BIND: '127.0.0.1',
    PKI_DIR: join(dir, 'pki'),
    TLS_CA: join(dir, 'pki/ca/ca.crt'),
    CA_CERT_PATH: join(dir, 'pki/ca/ca.crt'),
    CA_KEY_PATH: join(dir, 'pki/ca/ca.key'),
    TLS_CERT: join(dir, 'pki/server/server.crt'),
    TLS_KEY: join(dir, 'pki/server/server.key'),
    CLIENTS_DIR: join(dir, 'pki/clients'),
    CONFIG_PATH: configPath,
    SECRETS_PATH: join(dir, 'secrets/absent.env'),
    SECRETS_DETAIL_PATH: detailPath,
    AUDIT_DIR: join(dir, 'audit'),
    OPENSSL_BIN: openssl,
    BROKER_HEALTH_DISABLE: '1',
    BROKER_MAX_UPSTREAM_RESPONSE_BYTES: '1024',
    BROKER_RETAIN_CLIENT_PRIVATE_KEYS: '0',
    RELOAD_TOKEN: 'startup-fixture-only',
  };
  for (const key of [
    'AGE_KEY_FILE',
    'SOPS_AGE_KEY_FILE',
    'NODE_OPTIONS',
    'BROKER_PUBLIC_ORIGIN',
    'BROKER_BROWSER_ORIGIN',
    'TLS_CRL',
    'CA_SERIAL_PATH',
  ])
    delete env[key];
  // Intentionally unavailable SOPS tests failure rollback only. No production
  // key/environment file is read by this process.
  env.PATH = dirname(process.execPath);
  child = spawn(process.execPath, [join(root, 'broker/server.js')], {
    cwd: dir,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  child.stdout.on('data', (data) => {
    logs = (logs + data.toString()).slice(-64000);
  });
  child.stderr.on('data', (data) => {
    logs = (logs + data.toString()).slice(-64000);
  });
  const port = await new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error('Broker startup deadline exceeded: ' + logs.slice(-1800))),
      12000,
    );
    const poll = setInterval(() => {
      const m = logs.match(/mTLS HTTPS listening on https:\/\/127\.0\.0\.1:(\d+)/);
      if (m) {
        clearTimeout(timer);
        clearInterval(poll);
        resolve(Number(m[1]));
      } else if (child.exitCode !== null) {
        clearTimeout(timer);
        clearInterval(poll);
        reject(new Error('Broker exited during startup: ' + logs.slice(-1800)));
      }
    }, 25);
    timer.unref?.();
    poll.unref?.();
  });
  check('real server boots on an ephemeral loopback port', port > 0);
  const ca = readFileSync(join(dir, 'pki/ca/ca.crt'));
  async function request(
    path,
    { method = 'GET', body, headers = {}, material, servername = 'localhost', maxVersion } = {},
  ) {
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
    return new Promise((resolve, reject) => {
      const req = https.request(
        {
          host: '127.0.0.1',
          port,
          path,
          method,
          ca,
          servername,
          rejectUnauthorized: true,
          agent: false,
          ...(maxVersion ? { maxVersion } : {}),
          ...(material ? { cert: material.cert, key: material.key } : {}),
          headers: {
            ...headers,
            ...(payload
              ? { 'content-type': 'application/json', 'content-length': payload.length }
              : {}),
          },
        },
        (res) => {
          const parts = [];
          res.on('data', (part) => parts.push(part));
          res.on('end', () => {
            const text = Buffer.concat(parts).toString();
            let json;
            try {
              json = JSON.parse(text);
            } catch {}
            resolve({ status: res.statusCode, headers: res.headers, json, text });
          });
          res.on('error', reject);
        },
      );
      req.setTimeout(5000, () => req.destroy(new Error('request timeout')));
      req.on('error', reject);
      req.end(payload);
    });
  }
  const health = await request('/health');
  check('public health is minimal', health.status === 200 && health.text === '{"status":"ok"}');
  check(
    'anonymous protected request is rejected',
    (await request('/api/v1/identity')).status === 401,
  );
  check(
    'registered real mTLS certificate works',
    (await request('/api/v1/identity', { material: user })).json?.role === 'developer',
  );
  check(
    'registered but expired real certificate is rejected',
    (await request('/api/v1/identity', { material: expired })).status === 401,
  );
  let denied = false;
  try {
    await request('/health', { servername: 'wrong.example' });
  } catch {
    denied = true;
  }
  check('hostname mismatch fails TLS verification', denied);
  denied = false;
  try {
    await request('/health', { maxVersion: 'TLSv1.2' });
  } catch {
    denied = true;
  }
  check('origin rejects legacy TLS version', denied);
  check(
    'ordinary mTLS peer cannot forge forwarding metadata',
    (
      await request('/api/v1/identity', {
        material: user,
        headers: {
          'x-ssl-client-verify': 'SUCCESS',
          'x-ssl-client-cert': encodeURIComponent(admin.cert.toString()),
        },
      })
    ).status === 401,
  );
  check(
    'invalid explicit API key cannot fall back to admin certificate',
    (
      await request('/api/v1/identity', {
        material: admin,
        headers: { authorization: 'Bearer invalid' },
      })
    ).status === 401,
  );
  for (let n = 1; n <= 3; n++) {
    const result = await request('/api/v1/identity', {
      headers: { authorization: `Bearer ${limited.secret}` },
    });
    check(
      `API-key request ${n} consumes exactly one quota unit`,
      result.status === (n <= 2 ? 200 : 401),
    );
  }
  check(
    'admin-owned API key cannot access admin routes',
    (
      await request('/api/v1/admin/clients', {
        headers: { authorization: `Bearer ${delegated.secret}` },
      })
    ).status === 403,
  );
  check(
    'delegated key cannot manage account',
    (await request('/api/v1/me', { headers: { authorization: `Bearer ${delegated.secret}` } }))
      .status === 403,
  );
  const login = await request('/api/v1/login', {
    method: 'POST',
    body: { client: 'client.startup-admin', password: pw },
  });
  check(
    'password alone returns only an MFA challenge',
    login.status === 200 &&
      login.json?.mfa_required &&
      !login.json?.token &&
      !login.headers['set-cookie'],
  );
  const mfa = await request('/api/v1/login/mfa', {
    method: 'POST',
    body: { mfa_token: login.json.mfa_token, code: computeCode(seed) },
  });
  check('valid TOTP completes real login', mfa.status === 200 && !!mfa.json?.token);
  check(
    'used MFA challenge cannot be replayed',
    (
      await request('/api/v1/login/mfa', {
        method: 'POST',
        body: { mfa_token: login.json.mfa_token, code: computeCode(seed) },
      })
    ).status === 401,
  );
  const cookie = String(mfa.headers['set-cookie']?.[0] || '').split(';')[0];
  check(
    'cookie mutation without Origin is rejected',
    (await request('/api/v1/logout', { method: 'POST', headers: { cookie }, body: {} })).status ===
      403,
  );
  check(
    'MFA-enabled step-up rejects password alone',
    (
      await request('/api/v1/me/rotate-cert', {
        method: 'POST',
        material: admin,
        body: { verify: pw },
      })
    ).status === 401,
  );
  const login2 = await request('/api/v1/login', {
    method: 'POST',
    body: { client: 'client.startup-admin', password: pw },
  });
  const parallel = await Promise.all(
    [1, 2].map(() =>
      request('/api/v1/login/mfa', {
        method: 'POST',
        body: { mfa_token: login2.json.mfa_token, code: computeCode(seed) },
      }),
    ),
  );
  check(
    'concurrent MFA challenge consumption succeeds only once',
    parallel
      .map((r) => r.status)
      .sort()
      .join(',') === '200,401',
  );
  const proxy = await request('/api/v1/proxy/echo', {
    method: 'POST',
    material: user,
    body: { path: '/safe/item', method: 'GET', headers: { Authorization: 'Bearer caller' } },
  });
  check(
    'proxy uses broker-managed credential',
    proxy.status === 200 && proxy.json?.auth_ok === true,
  );
  check(
    'proxy strips cookies and Connection-nominated headers',
    !proxy.headers['set-cookie'] && !proxy.headers['x-hop'],
  );
  check(
    'proxy response is sandboxed',
    proxy.headers['content-security-policy']?.includes('sandbox'),
  );
  check(
    'canonicalized path cannot escape owner ACL',
    (
      await request('/api/v1/proxy/echo', {
        method: 'POST',
        material: user,
        body: { path: '/safe/../admin', method: 'GET' },
      })
    ).status === 403,
  );
  check(
    'cross-origin proxy destination is rejected',
    (
      await request('/api/v1/proxy/echo', {
        method: 'POST',
        material: user,
        body: { path: 'https://never-contacted.invalid/', method: 'GET' },
      })
    ).status === 400,
  );
  check(
    'service method restriction also applies to admin',
    (
      await request('/api/v1/proxy/echo', {
        method: 'POST',
        material: admin,
        body: { path: '/safe/item', method: 'DELETE' },
      })
    ).status === 403,
  );
  check(
    'oversized real upstream response is rejected',
    (
      await request('/api/v1/proxy/echo', {
        method: 'POST',
        material: admin,
        body: { path: '/huge', method: 'GET' },
      })
    ).status === 502,
  );
  const oldCert = digest(join(dir, 'pki/clients/client.startup-user.crt'));
  const rotation = await request('/api/v1/me/rotate-cert', {
    method: 'POST',
    material: user,
    body: { verify: pw },
  });
  check('injected persistence failure rejects rotation', rotation.status === 500);
  check(
    'failed rotation restores exact original certificate',
    digest(join(dir, 'pki/clients/client.startup-user.crt')) === oldCert,
  );
  check(
    'failed rotation removes newly created private key',
    !existsSync(join(dir, 'pki/clients/client.startup-user.key')),
  );
  check(
    'old identity survives failed rotation',
    (await request('/api/v1/identity', { material: user })).status === 200,
  );
  const changed = JSON.parse(configText);
  changed.clients['client.startup-admin'].role = 'developer';
  writeFileSync(configPath, JSON.stringify(changed));
  writeFileSync(detailPath, '{corrupt');
  const reload = await request('/api/v1/reload', {
    method: 'POST',
    material: admin,
    headers: { 'x-reload-token': 'startup-fixture-only' },
    body: {},
  });
  check('corrupt reload fails closed', reload.status === 503);
  check(
    'failed reload restores previous live configuration',
    (await request('/api/v1/identity', { material: admin })).json?.role === 'admin',
  );
  check(
    'failed reload restores previous live secrets',
    (
      await request('/api/v1/proxy/echo', {
        method: 'POST',
        material: user,
        body: { path: '/safe/item', method: 'GET' },
      })
    ).json?.auth_ok === true,
  );
  check(
    'no plaintext SOPS scratch survives failures',
    !readdirSync(join(dir, 'secrets')).some((name) => name.includes('.tmp.')),
  );
  console.log(
    `startup-regressions: ${checks} passed, 0 failed (real loopback TLS; DEV fixture; Docker/SOPS success not claimed)`,
  );
} finally {
  if (child && child.exitCode === null) {
    const closed = once(child, 'close');
    child.kill();
    await closed;
  }
  if (upstream?.listening) await new Promise((resolve) => upstream.close(resolve));
  rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
}
