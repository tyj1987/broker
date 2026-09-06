#!/usr/bin/env node
// cli/secret-broker.js
// Secret Broker 客户端 CLI
// Usage:
//   secret-broker health
//   secret-broker identity
//   secret-broker list
//   secret-broker get <secret-name>
//   secret-broker proxy <service> <method> <path> [--body <json>] [--query k=v]...
//   secret-broker exec --env "VAR1,VAR2" -- <command> [args...]
//   secret-broker pki issue-client --cn <name> [--role <r>] [--register]
//   secret-broker pki revoke --fingerprint <sha256>
//   secret-broker pki list
//
// Config file: ~/.broker/config.json
// {
//   "endpoint": "https://broker.example.com:8443",
//   "client_cert": "C:/Users/.../client.laptop.crt",
//   "client_key":  "C:/Users/.../client.laptop.key",
//   "ca_cert":     "C:/Users/.../ca.crt",
//   "ca_key":      "C:/Users/.../ca.key"  // only needed for pki issue/revoke
// }

import { readFileSync, existsSync, writeFileSync, statSync, copyFileSync, readdirSync } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import { request as httpsRequest } from 'node:https';
import { URL } from 'node:url';
import { homedir, platform } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

// ============================================================
// BrokerError (V4.1.1) — typed error for broker responses
//
// Parity with Python SDK exceptions.V4.1.1 + Go SDK errors.go V4.1.1.
// ============================================================
export class BrokerError extends Error {
  /**
   * @param {object} opts
   * @param {string} opts.message - human-readable message
   * @param {number} [opts.status] - HTTP status code (0 for connection errors)
   * @param {string} [opts.code] - broker-specific error code from response body
   * @param {string} [opts.requestId] - X-Request-Id response header
   * @param {number} [opts.retryAfter] - Retry-After response header (seconds)
   * @param {string} [opts.op] - logical operation, e.g. "get_secret"
   */
  constructor({ message, status = 0, code = '', requestId = '', retryAfter = 0, op = '' } = {}) {
    super(message);
    this.name = 'BrokerError';
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.retryAfter = retryAfter;
    this.op = op;
  }

  /** True if this error is worth retrying (5xx / 429 / connection). */
  get isRetryable() {
    if (this.status === 0) return true;   // connection error
    if (this.status === 429) return true;    // rate limit
    if (this.status >= 500 && this.status < 600) return true;
    return false;
  }

  /** Human-readable string with status + code + request_id + retry_after. */
  toString() {
    const meta = [];
    if (this.status) meta.push(`status=${this.status}`);
    if (this.code) meta.push(`code=${this.code}`);
    if (this.requestId) meta.push(`request_id=${this.requestId}`);
    if (this.retryAfter > 0) meta.push(`retry_after=${this.retryAfter}s`);
    const suffix = meta.length ? ` [${meta.join(' ')}]` : '';
    return `${this.name}: ${this.message}${suffix}`;
  }

  /** Structured representation for logging / audit export. Body omitted (may contain secrets). */
  toJSON() {
    return {
      error_type: this.name,
      op: this.op,
      message: this.message,
      status: this.status,
      code: this.code,
      request_id: this.requestId,
      retry_after: this.retryAfter,
      is_retryable: this.isRetryable,
    };
  }
}

/**
 * Parse a broker error response into a BrokerError.
 * @param {number} status - HTTP status code
 * @param {object} headers - response headers (lowercased keys)
 * @param {*} body - response body (parsed JSON or string)
 * @param {string} [op] - logical operation name
 * @returns {BrokerError}
 */
export function parseBrokerError(status, headers, body, op = '') {
  const requestId = (headers['x-request-id'] || '').toString();
  const retryAfter = parseInt(headers['retry-after'] || '0', 10) || 0;

  // Extract code from body if it's an object with error.code
  let code = '';
  let message = `HTTP ${status}`;
  if (body && typeof body === 'object' && body.error) {
    if (typeof body.error === 'object') {
      code = body.error.code || '';
      message = body.error.message || message;
    } else {
      message = String(body.error);
    }
  } else if (typeof body === 'string' && body) {
    message = body;
  }

  return new BrokerError({ message, status, code, requestId, retryAfter, op });
}

// ============================================================
// Config
// ============================================================
const HOME = homedir();
const DEFAULT_CONFIG = join(HOME, '.broker', 'config.json');

function loadConfig() {
  const p = process.env.BROKER_CONFIG || DEFAULT_CONFIG;
  if (!existsSync(p)) {
    die(`Config not found: ${p}\nCreate it with endpoint + client_cert + client_key + ca_cert.`);
  }
  return JSON.parse(readFileSync(p, 'utf8'));
}

// ============================================================
// HTTP client (mTLS) — V4.1.1 with retry
// ============================================================

/**
 * Sleep helper that respects abort signals.
 * @param {number} ms
 * @param {AbortSignal} [signal]
 * @returns {Promise<void>}
 */
function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new Error('aborted'));
    const t = setTimeout(resolve, ms);
    signal?.addEventListener('abort', () => { clearTimeout(t); reject(new Error('aborted')); }, { once: true });
  });
}

/**
 * mTLSRequest — V4.1.1 with optional retry on 5xx / 429 / connection errors.
 *
 * @param {object} opts
 * @param {string} [opts.method='GET']
 * @param {string} [opts.path='/']
 * @param {*} [opts.body=null]
 * @param {object} [opts.headers={}]
 * @param {number} [opts.maxRetries=0] - number of retries on transient errors (default 0 = no retry)
 * @param {number} [opts.retryBackoff=500] - initial backoff in ms (doubles each attempt)
 * @returns {Promise<{status: number, headers: object, body: *, raw: Buffer}>}
 * @throws {BrokerError} on HTTP 4xx/5xx
 * @throws {BrokerError} (status=0) on connection error
 */
async function mTLSRequest({ method = 'GET', path = '/', body = null, headers = {}, maxRetries = 0, retryBackoff = 500 } = {}) {
  let lastErr = null;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    if (attempt > 0) {
      // Exponential backoff: retryBackoff * 2^(attempt-1)
      let backoff = retryBackoff << (attempt - 1);
      // If last error had Retry-After, respect it (capped at 30s)
      if (lastErr instanceof BrokerError && lastErr.retryAfter > 0) {
        const fromHeader = lastErr.retryAfter * 1000;
        if (fromHeader < backoff && fromHeader < 30000) backoff = fromHeader;
      }
      await sleep(backoff);
    }
    try {
      const r = await mTLSRequestOnce({ method, path, body, headers });
      if (r.status >= 400) {
        const be = parseBrokerError(r.status, r.headers, r.body, `${method} ${path}`);
        lastErr = be;
        if (be.isRetryable) continue;
        throw be;
      }
      return r;
    } catch (err) {
      // Network / TLS / timeout — wrap in BrokerError (status=0)
      if (err instanceof BrokerError) {
        lastErr = err;
        if (err.isRetryable) continue;
        throw err;
      }
      const be = new BrokerError({ message: err.message || String(err), op: `${method} ${path}` });
      lastErr = be;
      if (be.isRetryable) continue;
      throw be;
    }
  }
  // Exhausted retries
  throw lastErr;
}

function mTLSRequestOnce({ method = 'GET', path = '/', body = null, headers = {} }) {
  const cfg = loadConfig();
  const url = new URL(path, cfg.endpoint);
  return new Promise((resolve, reject) => {
    // SNI: by default use the hostname from endpoint, but allow override
    // so the user can put the SSH-tunnel localhost:18443 in endpoint and
    // keep the real domain in servername without juggling hosts files.
    const sni = cfg.sni_hostname || url.hostname;

    const opts = {
      method,
      hostname: url.hostname,
      port: url.port || 8443,
      path: url.pathname + url.search,
      cert: readFileSync(cfg.client_cert),
      key:  readFileSync(cfg.client_key),
      ca:   readFileSync(cfg.ca_cert),
      servername: sni,
      rejectUnauthorized: true,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'secret-broker-cli/2.0',
        ...headers,
      },
    };
    const req = httpsRequest(opts, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const buf = Buffer.concat(chunks);
        const text = buf.toString('utf8');
        let parsed = text;
        const ct = res.headers['content-type'] || '';
        if (ct.includes('application/json')) {
          try { parsed = JSON.parse(text); } catch {}
        }
        resolve({ status: res.statusCode, headers: res.headers, body: parsed, raw: buf });
      });
    });
    req.on('error', reject);
    if (body) {
      const payload = typeof body === 'string' ? body : JSON.stringify(body);
      req.setHeader('Content-Length', Buffer.byteLength(payload));
      req.write(payload);
    }
    req.end();
  });
}

// ============================================================
// Helpers
// ============================================================
function die(msg, code = 1) { console.error('ERROR:', msg); process.exit(code); }
function info(msg) { console.log('[broker]', msg); }

function parseQuery(args, start) {
  const out = {};
  for (let i = start; i < args.length; i++) {
    if (args[i] === '--query' && i + 1 < args.length) {
      const [k, v] = args[++i].split('=');
      out[k] = v;
    }
  }
  return out;
}

// ============================================================
// Commands
// ============================================================
async function cmdHealth() {
  const r = await mTLSRequest({ method: 'GET', path: '/health' });
  if (r.status === 200) {
    console.log(JSON.stringify(r.body, null, 2));
  } else {
    die(`Health check failed: ${r.status} ${JSON.stringify(r.body)}`);
  }
}

async function cmdIdentity() {
  const r = await mTLSRequest({ method: 'GET', path: '/api/v1/identity' });
  if (r.status === 200) {
    console.log(JSON.stringify(r.body, null, 2));
  } else {
    die(`Identity failed: ${r.status} ${JSON.stringify(r.body)}`);
  }
}

async function cmdList() {
  const r = await mTLSRequest({ method: 'GET', path: '/api/v1/secrets' });
  if (r.status === 200) {
    // Always emit JSON so scripts can parse it
    process.stdout.write(JSON.stringify(r.body) + '\n');
  } else {
    die(`List failed: ${r.status} ${JSON.stringify(r.body)}`);
  }
}

async function cmdGet(name) {
  if (!name) die('Usage: secret-broker get <name>');
  const r = await mTLSRequest({ method: 'POST', path: '/api/v1/secrets/resolve', body: { name } });
  if (r.status === 200) {
    process.stdout.write(r.body.value);
    if (!process.stdout.isTTY) process.stdout.write('\n');
  } else {
    die(`Resolve failed: ${r.status} ${JSON.stringify(r.body)}`);
  }
}

async function cmdProxy(args) {
  if (args.length < 3) die('Usage: secret-broker proxy <service> <METHOD> <path> [--body <json>] [--query k=v ...] [--header K:V]');
  const [service, method, ...rest] = args;
  let path = '';
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === '--body')        { i++; continue; }
    if (rest[i] === '--query')       { i++; continue; }
    if (rest[i] === '--header')      { i++; continue; }
    path = rest.slice(i).join(' ');
    break;
  }
  if (!path) path = '/';

  let body = null;
  let query = {};
  let headers = {};
  for (let i = 3; i < rest.length; i++) {
    if (rest[i] === '--body' && i + 1 < rest.length) {
      try { body = JSON.parse(rest[++i]); }
      catch { body = rest[++i]; }
    } else if (rest[i] === '--query' && i + 1 < rest.length) {
      const [k, v] = rest[++i].split('=');
      query[k] = v;
    } else if (rest[i] === '--header' && i + 1 < rest.length) {
      const [k, v] = rest[++i].split(':');
      headers[k.trim()] = v.trim();
    }
  }

  const r = await mTLSRequest({
    method: 'POST',
    path: `/api/v1/proxy/${service}`,
    body: { method, path, query, headers, body },
  });
  if (r.status === 200) {
    process.stdout.write(r.raw);
  } else {
    process.stderr.write(`Proxy failed: ${r.status} ${r.raw.toString('utf8')}\n`);
    process.exit(1);
  }
}

async function cmdExec(args) {
  // secret-broker exec --env "VAR1,VAR2" -- <cmd> [args...]
  let envVars = [];
  let i = 0;
  while (i < args.length) {
    if (args[i] === '--env' && i + 1 < args.length) {
      envVars = args[++i].split(',').map(s => s.trim()).filter(Boolean);
      i++;
    } else if (args[i] === '--') {
      i++;
      break;
    } else {
      die(`Unknown exec arg: ${args[i]}`);
    }
  }
  if (i >= args.length) die('Usage: secret-broker exec --env "VAR1,VAR2" -- <cmd> [args...]');
  const cmd = args[i];
  const cmdArgs = args.slice(i + 1);

  // Resolve each requested secret and map to env var
  const env = { ...process.env };
  for (const v of envVars) {
    const r = await mTLSRequest({ method: 'POST', path: '/api/v1/secrets/resolve', body: { name: v } });
    if (r.status === 200) {
      env[v] = r.body.value;
      // Also support secret-broker.ssh.KEY style: if v is "GH_TOKEN" and there's "github.pat", use direct
    } else {
      die(`Cannot resolve ${v}: ${r.status} ${JSON.stringify(r.body)}`);
    }
  }

  info(`Spawning: ${cmd} ${cmdArgs.join(' ')} with ${envVars.length} env vars injected`);
  const child = spawn(cmd, cmdArgs, { env, stdio: 'inherit' });
  child.on('exit', (code) => process.exit(code || 0));
  child.on('error', (e) => die(`Spawn failed: ${e.message}`));
}

// ============================================================
// SSH subcommands (V4.1 任务 12)
// ============================================================
async function cmdSshExec(args) {
  // secret-broker ssh-exec --target user@host[:port] --command "cmd" [--secret <name>] [--timeout <ms>]
  let target = null, command = null, secretName = 'ssh.connection', timeoutMs = null;
  let i = 0;
  while (i < args.length) {
    if (args[i] === '--target' && i + 1 < args.length) { target = args[++i]; i++; }
    else if (args[i] === '--command' && i + 1 < args.length) { command = args[++i]; i++; }
    else if (args[i] === '--secret' && i + 1 < args.length) { secretName = args[++i]; i++; }
    else if (args[i] === '--timeout' && i + 1 < args.length) { timeoutMs = parseInt(args[++i], 10); i++; }
    else die(`Unknown ssh-exec arg: ${args[i]}`);
  }
  if (!target || !command) {
    die('Usage: secret-broker ssh-exec --target user@host[:port] --command "cmd" [--secret <name>] [--timeout <ms>]');
  }
  const r = await mTLSRequest({
    method: 'POST',
    path: '/api/v1/ssh/exec',
    body: { target, command, secret_name: secretName, timeout_ms: timeoutMs },
  });
  if (r.status !== 200) die(`ssh-exec failed: ${r.status} ${JSON.stringify(r.body)}`);
  if (r.body.stdout) process.stdout.write(r.body.stdout);
  if (r.body.stderr) process.stderr.write(r.body.stderr);
  process.exit(r.body.exitCode || 0);
}

async function cmdSshTunnel(args) {
  // secret-broker ssh-tunnel --target user@host[:port] --local-port N --remote-host H --remote-port N [--secret <name>]
  let target = null, localPort = null, remoteHost = null, remotePort = null, secretName = 'ssh.connection';
  let i = 0;
  while (i < args.length) {
    if (args[i] === '--target' && i + 1 < args.length) { target = args[++i]; i++; }
    else if (args[i] === '--local-port' && i + 1 < args.length) { localPort = parseInt(args[++i], 10); i++; }
    else if (args[i] === '--remote-host' && i + 1 < args.length) { remoteHost = args[++i]; i++; }
    else if (args[i] === '--remote-port' && i + 1 < args.length) { remotePort = parseInt(args[++i], 10); i++; }
    else if (args[i] === '--secret' && i + 1 < args.length) { secretName = args[++i]; i++; }
    else die(`Unknown ssh-tunnel arg: ${args[i]}`);
  }
  if (!target || !localPort || !remoteHost || !remotePort) {
    die('Usage: secret-broker ssh-tunnel --target user@host[:port] --local-port N --remote-host H --remote-port N [--secret <name>]');
  }
  const r = await mTLSRequest({
    method: 'POST',
    path: '/api/v1/ssh/tunnel',
    body: { target, local_port: localPort, remote_host: remoteHost, remote_port: remotePort, secret_name: secretName },
  });
  if (r.status !== 200) die(`ssh-tunnel failed: ${r.status} ${JSON.stringify(r.body)}`);
  info(`Tunnel ${r.body.id} open: localhost:${r.body.localPort} -> ${r.body.remote} via ${r.body.target}`);
  // 保持客户端活着直到 SIGINT
  process.on('SIGINT', async () => {
    info(`\nClosing tunnel ${r.body.id}...`);
    await mTLSRequest({ method: 'POST', path: '/api/v1/ssh/tunnel/stop', body: { id: r.body.id } });
    process.exit(0);
  });
  // 阻塞
  await new Promise(() => {});
}

// ============================================================
// PKI subcommands
// ============================================================
function cmdPKI(args) {
  const sub = args[0];
  const subArgs = args.slice(1);

  function findOpt(name) {
    const i = subArgs.indexOf(`--${name}`);
    if (i >= 0 && i + 1 < subArgs.length) return subArgs[i + 1];
    return null;
  }
  function hasFlag(name) {
    return subArgs.includes(`--${name}`);
  }

  if (sub === 'issue-client') {
    const cn = findOpt('cn');
    if (!cn) die('Usage: secret-broker pki issue-client --cn <name> [--role <r>] [--register]');
    const role = findOpt('role') || 'developer';
    const ps1 = join(process.cwd(), 'scripts', 'broker', 'issue-client-cert.ps1');
    if (!existsSync(ps1)) die(`PKI script not found: ${ps1}. Run from the broker repo root.`);
    const psArgs = [
      '-NoProfile', '-ExecutionPolicy', 'Bypass',
      '-File', ps1, '-CN', cn, '-Role', role,
    ];
    if (hasFlag('register')) psArgs.push('-RegisterToConfig');
    const r = spawnSync('powershell', psArgs, { stdio: 'inherit' });
    process.exit(r.status || 0);
  }

  if (sub === 'revoke') {
    const fp = findOpt('fingerprint');
    if (!fp) die('Usage: secret-broker pki revoke --fingerprint <sha256>');
    const ps1 = join(process.cwd(), 'scripts', 'broker', 'revoke-cert.ps1');
    if (!existsSync(ps1)) die(`PKI script not found: ${ps1}. Run from the broker repo root.`);
    const r = spawnSync('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ps1, '-Fingerprint', fp], { stdio: 'inherit' });
    process.exit(r.status || 0);
  }

  if (sub === 'list') {
    const dir = join(process.cwd(), 'pki', 'clients');
    if (!existsSync(dir)) {
      console.log('(no clients directory)');
      return;
    }
    for (const f of readdirSync(dir).filter(f => f.endsWith('.crt'))) {
      const full = join(dir, f);
      const out = spawnSync('openssl', ['x509', '-in', full, '-noout', '-subject', '-fingerprint', '-sha256', '-dates'], { encoding: 'utf8' });
      console.log(`\n${f}`);
      console.log(out.stdout.trim());
    }
    return;
  }

  if (sub === 'show-ca') {
    const cfg = loadConfig();
    const out = spawnSync('openssl', ['x509', '-in', cfg.ca_cert, '-noout', '-subject', '-issuer', '-fingerprint', '-sha256', '-dates'], { encoding: 'utf8' });
    console.log(out.stdout);
    return;
  }

  die(`Unknown pki subcommand: ${sub}\nKnown: issue-client, revoke, list, show-ca`);
}

// ============================================================
// Main
// ============================================================
function main() {
  const args = process.argv.slice(2);
  const cmd = args[0];
  const rest = args.slice(1);

  const handlers = {
    health:    cmdHealth,
    identity:  cmdIdentity,
    list:      cmdList,
    ls:        cmdList,
    get:       () => cmdGet(rest[0]),
    proxy:     () => cmdProxy(rest),
    exec:      () => cmdExec(rest),
    pki:       () => cmdPKI(rest),
    'ssh-exec':   () => cmdSshExec(rest),
    'ssh-tunnel': () => cmdSshTunnel(rest),
    help:      () => printHelp(),
    '--help':  () => printHelp(),
    '-h':      () => printHelp(),
  };

  if (!cmd || !handlers[cmd]) {
    printHelp();
    process.exit(cmd ? 1 : 0);
  }
  Promise.resolve(handlers[cmd]()).catch(err => die(err.message || String(err)));
}

function printHelp() {
  console.log(`Secret Broker CLI v2.0

Usage:
  secret-broker <command> [args]

Commands:
  health                              Check broker health
  identity                            Show current client cert identity
  list                                List secrets visible to this client
  get <name>                          Resolve a secret to plaintext (audited)
  proxy <service> <METHOD> <path>     Proxy-mode: AI calls external API
                                      [--body '<json>'] [--query k=v] [--header K:V]
  exec --env "VAR1,VAR2" -- <cmd>     Inject secrets as env vars, run child process
  pki issue-client --cn <name>        Issue a new client cert
       [--role developer|ci|admin]    Role determines default ACL
       [--register]                    Auto-append to broker.yaml
  pki revoke --fingerprint <sha256>   Revoke a client cert
  pki list                            List all client certs
  pki show-ca                         Show root CA cert details
  help                                Show this help

Config: ~/.broker/config.json
  {
    "endpoint": "https://broker.example.com:8443",
    "client_cert": "C:/Users/.../client.laptop.crt",
    "client_key":  "C:/Users/.../client.laptop.key",
    "ca_cert":     "C:/Users/.../ca.crt",
    "sni_hostname": "broker.example.com"
  }

Examples:
  secret-broker health
  secret-broker proxy github GET /repos/tyj1987/sops-age-template
  secret-broker exec --env "GH_TOKEN" -- git push origin main
`);
}

// Run main() only when this file is executed as a CLI, not when imported.
// When imported (e.g. for testing), main() is a no-op so the exports work.
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
