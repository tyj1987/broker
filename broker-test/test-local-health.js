// broker-test/test-local-health.js
import { request } from 'node:http';
import { handleHealth, buildPublicHealth, buildOpsHealth } from '../broker/routes/health.js';
import { startLocalHealthServer } from '../broker/lib/local-health.js';
import { handleStatic, STATIC_MAP } from '../broker/routes/static.js';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtempSync } from 'node:fs';

let passed = 0, failed = 0;
function assert(c, m) {
  if (c) { passed++; console.log('  OK  ', m); }
  else { failed++; console.error('  FAIL', m); }
}

function send(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

function get(port, path) {
  return new Promise((resolve, reject) => {
    const req = request({ hostname: '127.0.0.1', port, path, method: 'GET' }, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(raw); } catch { /* text */ }
        resolve({ status: res.statusCode, json, raw, headers: res.headers });
      });
    });
    req.on('error', reject);
    req.end();
  });
}

console.log('=== buildPublicHealth / buildOpsHealth ===');
{
  const pub = buildPublicHealth();
  assert(pub.status === 'ok' && Object.keys(pub).length === 1, 'public body is {status:ok}');
  const ops = buildOpsHealth({
    version: '4.1.1',
    secretCache: new Map([['a', {}]]),
    config: { services: { github: {}, cloudflare: {} } },
  });
  assert(ops.version === '4.1.1', 'ops version');
  assert(ops.sops_loaded === true, 'ops sops');
  assert(ops.services_count === 2, 'ops count');
  assert(ops.services === undefined, 'ops does not list names');
}

console.log('=== local TCP health listener ===');
{
  const server = await startLocalHealthServer({
    listen: { host: '127.0.0.1', port: 0 },
    onRequest: async (req, res) => {
      const url = new URL(req.url || '/', 'http://127.0.0.1');
      const handled = await handleHealth(req, res, { method: req.method, pathname: url.pathname }, {
        send,
        version: '4.1.1',
        secretCache: new Map([['X', {}]]),
        config: { services: { github: {} } },
        requireSops: true,
        surface: 'local',
      });
      if (!handled) send(res, 404, { error: 'not found', status: 404 });
    },
  });
  const port = server.address().port;
  try {
    const h = await get(port, '/health');
    assert(h.status === 200 && h.json.status === 'ok', 'local /health 200');
    assert(h.json.sops_loaded === true, 'local /health sops');
    assert(h.json.services_count === 1, 'local /health count');
    const r = await get(port, '/ready');
    assert(r.status === 200 && r.json.status === 'ready', 'local /ready');
    const l = await get(port, '/live');
    assert(l.status === 200 && l.json.status === 'live', 'local /live');
    const n = await get(port, '/nope');
    assert(n.status === 404, 'local unknown 404');
  } finally {
    server.close();
  }
}

console.log('=== probe error redaction ===');
{
  const res = {
    status: 0, body: null,
    writeHead(s) { this.status = s; },
    end(b) { this.body = JSON.parse(b); },
  };
  await handleHealth({}, res, { method: 'GET', pathname: '/ready' }, {
    send,
    surface: 'local',
    config: {},
    secretCache: new Map([['X', {}]]),
    runReadyProbes: async () => { throw new Error('synthetic-probe-path-canary'); },
  });
  assert(res.status === 503, 'probe failure makes readiness fail');
  assert(Array.isArray(res.body.probes) && res.body.probes.length === 0
    && !JSON.stringify(res.body).includes('synthetic-probe-path-canary'),
    `probe exception text is not exposed: ${JSON.stringify(res.body)}`);
}

console.log('=== handleStatic missing file is 500 not fall-through ===');
{
  const dir = mkdtempSync(join(tmpdir(), 'broker-dash-'));
  mkdirSync(dir, { recursive: true });
  const res = {
    status: 0, headers: {}, body: null,
    writeHead(s, h) { this.status = s; this.headers = h || {}; },
    end(b) { this.body = b; },
  };
  const handled = handleStatic({}, res, { method: 'GET', pathname: '/' }, { dashboardDir: dir });
  assert(handled === true, 'missing dashboard path is handled');
  assert(res.status === 500, '500 not 401');
  writeFileSync(join(dir, 'index.html'), '<html>ok</html>');
  const res2 = {
    status: 0, headers: {}, body: null,
    writeHead(s, h) { this.status = s; this.headers = h || {}; },
    end(b) { this.body = b; },
  };
  handleStatic({ headers: {} }, res2, { method: 'GET', pathname: '/' }, { dashboardDir: dir });
  assert(res2.status === 200 && String(res2.body).includes('ok'), 'serves when present');
  assert(res2.headers.ETag, 'etag set');
  const res3 = {
    status: 0, headers: {}, body: null,
    writeHead(s, h) { this.status = s; this.headers = h || {}; },
    end(b) { this.body = b; },
  };
  handleStatic({ headers: { 'if-none-match': res2.headers.ETag } }, res3, { method: 'GET', pathname: '/' }, { dashboardDir: dir });
  assert(res3.status === 304, '304 on etag hit');
  assert(Object.keys(STATIC_MAP).length >= 10, 'STATIC_MAP size');
  assert(STATIC_MAP['/llms.txt'] === 'llms.txt', 'llms.txt is public');
  rmSync(dir, { recursive: true, force: true });
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
