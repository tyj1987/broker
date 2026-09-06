#!/usr/bin/env node
// Read-only production smoke test. It never sends credentials or mutating requests.
import https from 'node:https';
import net from 'node:net';

const host = process.env.BROKER_SMOKE_HOST || 'broker.52trz.com';
const originHost = process.env.BROKER_ORIGIN_HOST;
const timeoutMs = Number(process.env.BROKER_SMOKE_TIMEOUT_MS || 10000);
const failures = [];

function get(path, port = 443) {
  return new Promise((resolve, reject) => {
    const req = https.request({ host, port, path, method: 'GET', servername: host,
      rejectUnauthorized: true, timeout: timeoutMs, headers: { 'User-Agent': 'secret-broker-production-smoke/1' } }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => { if (Buffer.concat(chunks).length < 64 * 1024) chunks.push(chunk); });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end();
  });
}

function check(name, condition, detail = '') {
  if (!condition) failures.push(`${name}${detail ? `: ${detail}` : ''}`);
  console.log(`${condition ? 'PASS' : 'FAIL'} ${name}${detail ? ` (${detail})` : ''}`);
}

try {
  const response = await get('/health');
  check('443 TLS and health endpoint', [200, 401, 403].includes(response.status), `HTTP ${response.status}`);
  check('strict transport security', /max-age=/.test(String(response.headers['strict-transport-security'] || '')));
  check('no credential-shaped response', !/(ghp_|sk-[A-Za-z0-9]|AKIA[0-9A-Z]{16})/.test(response.body));
} catch (error) {
  failures.push(`443 unavailable: ${error.message}`);
  console.log(`FAIL 443 TLS and health endpoint (${error.message})`);
}

await new Promise((resolve) => {
  if (!originHost) {
    failures.push('BROKER_ORIGIN_HOST is required to verify the origin 8443 boundary (public DNS may be Cloudflare)');
    console.log('FAIL 8443 private boundary (set BROKER_ORIGIN_HOST to the origin address; edge DNS is not authoritative)');
    resolve();
    return;
  }
  const socket = net.connect({ host: originHost, port: 8443, timeout: timeoutMs });
  socket.once('connect', () => { failures.push('8443 is publicly reachable'); console.log('FAIL 8443 private boundary (TCP connection accepted)'); socket.destroy(); resolve(); });
  socket.once('timeout', () => { socket.destroy(); console.log('PASS 8443 private boundary (timeout)'); resolve(); });
  socket.once('error', () => { console.log('PASS 8443 private boundary (connection refused/unreachable)'); resolve(); });
});

if (failures.length) { console.error(`\nProduction smoke failed (${failures.length})`); process.exit(1); }
console.log('\nProduction smoke passed');
