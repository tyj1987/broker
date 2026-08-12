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
// HTTP client (mTLS)
// ============================================================
function mTLSRequest({ method = 'GET', path = '/', body = null, headers = {} }) {
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

main();
