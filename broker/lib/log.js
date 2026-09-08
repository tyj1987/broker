// broker/lib/log.js — structured JSON logs with pluggable sinks (no deps).
//
// Built-in sinks:
//   - stdout       (default; JSON line on stdout/stderr)
//   - file:<path>  (append JSON line to file; rotates at 50MB)
//   - http:<url>   (POST JSON line to URL; fire-and-forget; useful for Loki/HTTP OTLP)
//   - syslog       (RFC 5424 over UDP; one JSON line per datagram — best effort)
//
// Configure via env: BROKER_LOG_SINKS=stdout,file:/var/log/broker/broker.log,http://loki:3100/loki/api/v1/push
// Level via BROKER_LOG_LEVEL (debug|info|warn|error).
//
// All sinks are best-effort; a sink failure never blocks the broker.

import { appendFileSync, existsSync, mkdirSync, renameSync, statSync, unlinkSync } from 'node:fs';
import { dirname } from 'node:path';
import { createHmac } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { createSocket } from 'node:dgram';

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };

function currentLevel() {
  const n = (process.env.BROKER_LOG_LEVEL || 'info').toLowerCase();
  return LEVELS[n] ?? LEVELS.info;
}

// ─────────────────────────────────────────────────────────────────────
// Sink interface:
//   { name, write(level, msg, fields, line): void }
// ─────────────────────────────────────────────────────────────────────

class StdoutSink {
  name = 'stdout';
  write(level, msg, fields, line) {
    if (level === 'error') console.error(line);
    else console.log(line);
  }
}

class FileSink {
  constructor(path) {
    this.name = `file:${path}`;
    this.path = path;
    this.bytes = 0;
    this.dir = dirname(path);
    if (!existsSync(this.dir)) mkdirSync(this.dir, { recursive: true });
  }
  write(level, msg, fields, line) {
    try {
      const stat = existsSync(this.path) ? statSync(this.path) : { size: 0 };
      this.bytes = stat.size;
      appendFileSync(this.path, line + '\n');
      this.bytes += Buffer.byteLength(line, 'utf8') + 1;
      if (this.bytes > 50 * 1024 * 1024) {
        const rotated = this.path + '.1';
        if (existsSync(rotated)) unlinkSync(rotated);
        renameSync(this.path, rotated);
        this.bytes = 0;
      }
    } catch (err) {
      console.error(`[log-sink ${this.name}] write failed:`, err.message);
    }
  }
}

class HttpSink {
  constructor(url, opts = {}) {
    this.name = `http:${url}`;
    this.url = url;
    this.headers = opts.headers || {};
    this.timeoutMs = opts.timeoutMs || 2000;
  }
  write(level, msg, fields, line) {
    // Use global fetch (Node 18+) or http module (Node < 18)
    const body = JSON.stringify({ ts: new Date().toISOString(), level, msg, ...fields });
    const doPost = (url) => {
      try {
        const u = new URL(url);
        const isHttps = u.protocol === 'https:';
        const request = isHttps ? httpsRequest : httpRequest;
        const req = request({
          hostname: u.hostname,
          port: u.port || (isHttps ? 443 : 80),
          path: u.pathname + u.search,
          method: 'POST',
          headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body), ...this.headers },
          timeout: this.timeoutMs,
        }, (res) => res.on('data', () => {}).on('end', () => {}));
        req.on('error', () => {});
        req.on('timeout', () => req.destroy());
        req.write(body);
        req.end();
      } catch { /* swallow */ }
    };
    doPost(this.url);
  }
}

class SyslogSink {
  constructor(opts = {}) {
    this.name = 'syslog';
    this.host = opts.host || '127.0.0.1';
    this.port = opts.port || 514;
    this.facility = opts.facility || 16; // local0
  }
  write(level, msg, fields, line) {
    try {
      const severity = { debug: 7, info: 6, warn: 4, error: 3 }[level] ?? 6;
      const pri = (this.facility << 3) | severity;
      const hostname = process.env.HOSTNAME || 'broker';
      const tag = 'secret-broker';
      // RFC 5424 format
      const syslogLine = `<${pri}>1 ${new Date().toISOString()} ${hostname} ${tag} - - - ${line}`;
      const client = createSocket('udp4');
      client.send(Buffer.from(syslogLine), this.port, this.host, (err) => {
        client.close();
      });
    } catch { /* swallow */ }
  }
}

function parseSinks(spec) {
  if (!spec) return [new StdoutSink()];
  const sinks = [];
  for (const part of spec.split(',').map(s => s.trim()).filter(Boolean)) {
    if (part === 'stdout') sinks.push(new StdoutSink());
    else if (part.startsWith('file:')) sinks.push(new FileSink(part.slice(5)));
    else if (part.startsWith('http:') || part.startsWith('https:')) sinks.push(new HttpSink(part));
    else if (part === 'syslog') sinks.push(new SyslogSink());
    else console.error(`[log] unknown sink: ${part}`);
  }
  return sinks.length ? sinks : [new StdoutSink()];
}

// ─────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────

let _sinks = null;
function getSinks() {
  if (!_sinks) _sinks = parseSinks(process.env.BROKER_LOG_SINKS);
  return _sinks;
}

// For tests: reset + inject
export function _setSinks(sinks) {
  _sinks = sinks;
}

function emit(level, msg, fields = {}) {
  if ((LEVELS[level] ?? 99) < currentLevel()) return;
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    msg,
    ...fields,
  });
  for (const sink of getSinks()) {
    try { sink.write(level, msg, fields, line); } catch { /* never throw */ }
  }
}

export const log = {
  debug: (msg, fields) => emit('debug', msg, fields),
  info: (msg, fields) => emit('info', msg, fields),
  warn: (msg, fields) => emit('warn', msg, fields),
  error: (msg, fields) => emit('error', msg, fields),
};

// HMAC helper for log integrity (V4.1.1)
export function signLine(line, secret) {
  return createHmac('sha256', secret).update(line).digest('hex');
}

export { StdoutSink, FileSink, HttpSink, SyslogSink, parseSinks };
export default log;
