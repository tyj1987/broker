'use strict';

// Real Node app that proves the full secret pipeline:
//   encrypted file -> sops -> .env -> process.env -> pg / redis clients
//
// Endpoints:
//   GET /          -> hello
//   GET /health    -> JSON status incl. db + cache connectivity
//   GET /db/ping   -> SELECT 1 against the database
//   GET /cache/put -> SET a test key/value
//   GET /cache/get -> GET the test key/value
//   GET /whoami    -> echo the JWT secret length (proves env load)

const http = require('http');
const { Client: PgClient } = require('pg');
const { createClient: createRedisClient } = require('redis');

const port = Number(process.env.PORT) || 3000;

const DATABASE_URL = process.env.DATABASE_URL || '';
const REDIS_URL = process.env.REDIS_URL || '';
const JWT_SECRET = process.env.JWT_SECRET || '';

function log(level, msg, extra) {
  const ts = new Date().toISOString();
  const tail = extra ? ' ' + JSON.stringify(extra) : '';
  console.log(`[${ts}] ${level} ${msg}${tail}`);
}

let pg = null;
let redis = null;

async function initClients() {
  if (DATABASE_URL) {
    pg = new PgClient({ connectionString: DATABASE_URL, connectionTimeoutMillis: 3000 });
    try {
      await pg.connect();
      log('info', 'postgres connected');
    } catch (e) {
      log('error', 'postgres connect failed', { err: e.message });
      pg = null;
    }
  }
  if (REDIS_URL) {
    redis = createRedisClient({
      url: REDIS_URL,
      socket: { connectTimeout: 1500, reconnectStrategy: false },
    });
    redis.on('error', (e) => log('warn', 'redis error', { err: e.message }));
    try {
      await redis.connect();
      log('info', 'redis connected');
    } catch (e) {
      log('warn', 'redis connect failed', { err: e.message });
      try { await redis.quit(); } catch {}
      redis = null;
    }
  }
}

function json(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(body));
}

async function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');

  if (url.pathname === '/' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Hello from my-first-app! Secrets loaded from SOPS-encrypted file.\n');
    return;
  }

  if (url.pathname === '/health' && req.method === 'GET') {
    return json(res, 200, {
      status: 'ok',
      secrets_loaded: {
        database: Boolean(DATABASE_URL),
        redis: Boolean(REDIS_URL),
        jwt: JWT_SECRET.length > 0,
      },
      connectivity: {
        database: pg ? 'up' : 'down',
        redis: redis && redis.isOpen ? 'up' : 'down',
      },
      uptime_seconds: Math.round(process.uptime()),
      timestamp: new Date().toISOString(),
    });
  }

  if (url.pathname === '/whoami' && req.method === 'GET') {
    return json(res, 200, {
      jwt_secret_length: JWT_SECRET.length,
      jwt_secret_sha256_first8: JWT_SECRET
        ? require('crypto').createHash('sha256').update(JWT_SECRET).digest('hex').slice(0, 8)
        : null,
      database_url_hash: DATABASE_URL
        ? require('crypto').createHash('sha256').update(DATABASE_URL).digest('hex').slice(0, 8)
        : null,
    });
  }

  if (url.pathname === '/db/ping' && req.method === 'GET') {
    if (!pg) return json(res, 503, { error: 'database not connected' });
    try {
      const r = await pg.query('SELECT 1 AS ok, NOW() AS server_time');
      return json(res, 200, { result: r.rows[0] });
    } catch (e) {
      return json(res, 500, { error: e.message });
    }
  }

  if (url.pathname === '/cache/put' && req.method === 'POST') {
    if (!redis) return json(res, 503, { error: 'redis not connected' });
    try {
      const body = await readBody(req);
      const { key, value } = JSON.parse(body || '{}');
      if (!key || !value) return json(res, 400, { error: 'need {key, value}' });
      await redis.set(key, value, { EX: 60 });
      return json(res, 200, { ok: true, key, ttl: 60 });
    } catch (e) {
      return json(res, 500, { error: e.message });
    }
  }

  if (url.pathname === '/cache/get' && req.method === 'GET') {
    if (!redis) return json(res, 503, { error: 'redis not connected' });
    const key = url.searchParams.get('key');
    if (!key) return json(res, 400, { error: 'need ?key=' });
    const v = await redis.get(key);
    return json(res, 200, { key, value: v });
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('not found\n');
});

(async () => {
  await initClients();
  server.listen(port, () => {
    log('info', `server listening on http://localhost:${port}`);
    log('info', 'env summary', {
      DATABASE_URL: DATABASE_URL ? `${DATABASE_URL.slice(0, 20)}...` : '(empty)',
      REDIS_URL: REDIS_URL ? `${REDIS_URL.slice(0, 12)}...` : '(empty)',
      JWT_SECRET_length: JWT_SECRET.length,
    });
  });
})();

async function shutdown(signal) {
  log('info', `received ${signal}, shutting down`);
  try { server.close(); } catch {}
  try { if (pg) await pg.end(); } catch {}
  try { if (redis) await redis.quit(); } catch {}
  process.exit(0);
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
