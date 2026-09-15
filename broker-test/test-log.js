// broker-test/test-log.js — V4.1.1 tests for broker/lib/log.js (pluggable sinks)

import {
  StdoutSink,
  FileSink,
  HttpSink,
  SyslogSink,
  parseSinks,
  log,
  _setSinks,
  signLine,
} from '../broker/lib/log.js';
import { mkdtempSync, rmSync, readFileSync, existsSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

let pass = 0, fail = 0;
function ok(name, cond, detail) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`); }
}

if (process.platform !== 'win32') {
  const WORK = mkdtempSync(join(tmpdir(), 'broker-log-link-'));
  try {
    const target = join(WORK, 'target.log');
    const link = join(WORK, 'broker.log');
    writeFileSync(target, 'original\n', { mode: 0o600 });
    symlinkSync(target, link);
    const originalError = console.error;
    console.error = () => {};
    new FileSink(link).write('info', 'blocked', {}, '{"msg":"blocked"}');
    console.error = originalError;
    ok('file sink refuses symbolic links', readFileSync(target, 'utf8') === 'original\n');
  } finally {
    rmSync(WORK, { recursive: true, force: true });
  }
}
function section(t) { console.log(`\n[${t}]`); }

// ---------- tests ----------

section('1. StdoutSink');

{
  const orig = console.log;
  const captured = [];
  console.log = (l) => captured.push(l);
  const s = new StdoutSink();
  s.write('info', 'test', { foo: 'bar' }, JSON.stringify({ ts: 'x', level: 'info', msg: 'test', foo: 'bar' }));
  console.log = orig;
  ok('captured one line', captured.length === 1);
  ok('line is the JSON', captured[0]?.includes('"msg":"test"'));
}

section('2. FileSink writes + persists');

{
  const WORK = mkdtempSync(join(tmpdir(), 'broker-log-'));
  try {
    const f = join(WORK, 'broker.log');
    const s = new FileSink(f);
    s.write('info', 'hello', { n: 1 }, JSON.stringify({ ts: 't', level: 'info', msg: 'hello', n: 1 }));
    s.write('warn', 'careful', {}, JSON.stringify({ ts: 't', level: 'warn', msg: 'careful' }));
    ok('file exists', existsSync(f));
    const content = readFileSync(f, 'utf8');
    ok('contains hello', content.includes('"msg":"hello"'));
    ok('contains careful', content.includes('"msg":"careful"'));
  } finally {
    rmSync(WORK, { recursive: true, force: true });
  }
}

section('3. HttpSink does not throw (best-effort)');

{
  const s = new HttpSink('http://127.0.0.1:1/never-listens'); // connection refused
  let threw = false;
  try { s.write('info', 'test', {}, '{}'); }
  catch (e) { threw = true; }
  ok('does not throw', !threw);
}

section('4. SyslogSink does not throw');

{
  const s = new SyslogSink({ host: '127.0.0.1', port: 1 }); // no syslog server
  let threw = false;
  try { s.write('info', 'test', {}, '{}'); }
  catch (e) { threw = true; }
  ok('does not throw', !threw);
}

section('5. parseSinks');

{
  // Force a fresh parse by clearing the cache
  const sinks1 = parseSinks('stdout');
  ok('stdout sink', sinks1.length === 1 && sinks1[0] instanceof StdoutSink);
  const sinks2 = parseSinks('stdout,file:/tmp/test.log');
  ok('stdout + file', sinks2.length === 2 && sinks2[1] instanceof FileSink);
  const sinks3 = parseSinks('syslog');
  ok('syslog', sinks3.length === 1 && sinks3[0] instanceof SyslogSink);
  const sinks4 = parseSinks('http://example.com/log');
  ok('http', sinks4.length === 1 && sinks4[0] instanceof HttpSink);
  const sinks5 = parseSinks('unknown-sink-type');
  ok('unknown → fallback to stdout', sinks5.length === 1 && sinks5[0] instanceof StdoutSink);
  const sinks6 = parseSinks('');
  ok('empty → stdout', sinks6.length === 1 && sinks6[0] instanceof StdoutSink);
}

section('6. log() honors BROKER_LOG_LEVEL');

{
  const captured = [];
  _setSinks([{ name: 'test', write: (l, m, f, line) => captured.push(line) }]);
  const orig = process.env.BROKER_LOG_LEVEL;
  process.env.BROKER_LOG_LEVEL = 'warn';
  log.debug('should be filtered');
  log.info('also filtered');
  log.warn('kept');
  log.error('also kept');
  if (orig === undefined) delete process.env.BROKER_LOG_LEVEL;
  else process.env.BROKER_LOG_LEVEL = orig;
  ok('debug filtered', !captured.some(l => l.includes('"level":"debug"')));
  ok('info filtered', !captured.some(l => l.includes('"level":"info"')));
  ok('warn kept', captured.some(l => l.includes('"level":"warn"')));
  ok('error kept', captured.some(l => l.includes('"level":"error"')));
}

section('7. log() sink failure does not propagate');

{
  _setSinks([{ name: 'broken', write: () => { throw new Error('boom'); } }]);
  let threw = false;
  try { log.info('test'); }
  catch (e) { threw = true; }
  ok('sink failure does not throw', !threw);
  _setSinks(null); // reset
}

section('8. signLine produces deterministic HMAC');

{
  const sig1 = signLine('hello world', 'secret-key');
  const sig2 = signLine('hello world', 'secret-key');
  const sig3 = signLine('hello world', 'different-key');
  ok('same input + key → same sig', sig1 === sig2);
  ok('different key → different sig', sig1 !== sig3);
  ok('64 hex chars', /^[a-f0-9]{64}$/.test(sig1));
}

section('9. log() output is valid JSON');

{
  const captured = [];
  _setSinks([{ name: 'test', write: (l, m, f, line) => captured.push(line) }]);
  log.info('json-test', { foo: 'bar', n: 42 });
  ok('one line', captured.length === 1);
  let parsed;
  try { parsed = JSON.parse(captured[0]); } catch (e) { ok('parses as JSON', false, e.message); }
  ok('parses as JSON', !!parsed);
  ok('has ts', typeof parsed?.ts === 'string');
  ok('has level=info', parsed?.level === 'info');
  ok('has msg=json-test', parsed?.msg === 'json-test');
  ok('has foo=bar', parsed?.foo === 'bar');
  _setSinks(null);
}

section('10. public logger redacts before sink fan-out');

// All values below are synthetic canaries. No provider requests or real keys.
const LOG_CANARY = 'synthetic-log-canary';
const OAUTH_CANARY = 'gho_' + 'Z'.repeat(36);
function captureLog(message, fields, level = 'info') {
  const captured = [];
  let threw = false;
  _setSinks([{ name: 'capture', write: (l, m, f, line) => captured.push({ level: l, msg: m, fields: f, line }) }]);
  try { log[level](message, fields); } catch { threw = true; }
  finally { _setSinks(null); }
  return { captured, threw };
}
function restoreEnv(name, value) {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}
{
  const beforeLevel = process.env.BROKER_LOG_LEVEL;
  process.env.BROKER_LOG_LEVEL = 'debug';
  try {
    for (const level of ['debug', 'info', 'warn', 'error']) {
      const input = { password: LOG_CANARY, nested: { Authorization: LOG_CANARY }, note: OAUTH_CANARY, public: 'ok' };
      const original = JSON.stringify(input);
      const { captured, threw } = captureLog(`password=${LOG_CANARY}`, input, level);
      ok(`${level} emits one safe record`, !threw && captured.length === 1);
      const record = captured[0];
      ok(`${level} message argument redacted`, record?.msg === 'password=***');
      ok(`${level} field arguments redacted`, record?.fields.password === '[REDACTED]' && record?.fields.nested.Authorization === '[REDACTED]');
      ok(`${level} no raw canary in any sink argument`, !JSON.stringify(record).includes(LOG_CANARY) && !JSON.stringify(record).includes(OAUTH_CANARY));
      ok(`${level} public values retained`, record?.fields.public === 'ok' && record?.fields.note === 'gho_***');
      ok(`${level} input not mutated`, JSON.stringify(input) === original);
    }
  } finally { restoreEnv('BROKER_LOG_LEVEL', beforeLevel); }
}
{
  const record = captureLog('actual-message', { ts: 'forged-time', level: 'debug', msg: 'forged-message', status: 200 }).captured[0];
  const parsed = JSON.parse(record.line);
  ok('caller cannot overwrite severity', parsed.level === 'info' && record.level === 'info');
  ok('caller cannot overwrite message', parsed.msg === 'actual-message' && record.msg === 'actual-message');
  ok('caller cannot overwrite timestamp', Number.isFinite(Date.parse(parsed.ts)) && parsed.ts !== 'forged-time');
  ok('reserved metadata excluded from fields', !Object.hasOwn(record.fields, 'ts') && !Object.hasOwn(record.fields, 'level') && !Object.hasOwn(record.fields, 'msg'));
}

section('11. serialization failures never disclose raw input');
{
  const cases = [
    ['BigInt field', { count: 1n }],
    ['throwing field getter', { get value() { throw new Error(LOG_CANARY); } }],
    ['throwing toJSON', { toJSON() { throw new Error(LOG_CANARY); } }],
    ['toJSON returning BigInt', { toJSON() { return 1n; } }],
  ];
  for (const [name, fields] of cases) {
    const { captured, threw } = captureLog(`password=${LOG_CANARY}`, fields);
    ok(`${name} does not throw`, !threw);
    ok(`${name} emits fixed fallback`, captured.length === 1 && JSON.parse(captured[0].line).msg === '[log record unavailable]');
    ok(`${name} does not expose input or error`, !JSON.stringify(captured).includes(LOG_CANARY));
  }
  const cycle = { password: LOG_CANARY };
  cycle.self = cycle;
  const cyclic = captureLog('cycle', cycle);
  ok('circular fields do not throw', !cyclic.threw && cyclic.captured.length === 1);
  ok('circular fields are redacted', cyclic.captured[0]?.fields.password === '[REDACTED]' && cyclic.captured[0]?.fields.self === '[CIRCULAR]');
  const rawJSON = { toJSON() { return { password: LOG_CANARY, note: OAUTH_CANARY, public: 'ok' }; } };
  const custom = captureLog(rawJSON, { nested: rawJSON }).captured[0];
  ok('toJSON message output is redacted after conversion', custom?.msg.password === '[REDACTED]' && custom?.msg.note === 'gho_***');
  ok('nested toJSON field output is redacted after conversion', custom?.fields.nested.password === '[REDACTED]' && custom?.fields.nested.public === 'ok');
  ok('custom serialization never bypasses redaction', !JSON.stringify(custom).includes(LOG_CANARY) && !JSON.stringify(custom).includes(OAUTH_CANARY));
  const top = captureLog('safe', rawJSON).captured[0];
  ok('top-level field toJSON cannot replace the envelope', top?.msg === 'safe' && JSON.parse(top.line).level === 'info' && top.fields.password === '[REDACTED]');
  for (const fields of [null, undefined, 42, false, 'public', ['public']]) {
    const item = captureLog('safe', fields);
    ok('non-object fields remain safe', !item.threw && item.captured.length === 1 && item.captured[0].msg === 'safe');
  }
  const undefinedMessage = captureLog(undefined, {});
  ok('undefined message remains valid JSON', !undefinedMessage.threw && JSON.parse(undefinedMessage.captured[0].line).level === 'info');
}

section('12. sink isolation and lazy evaluation');
{
  const input = { nested: { public: 'original' } };
  const message = { public: 'original' };
  const captured = [];
  _setSinks([
    { name: 'mutating', write: (_l, m, f) => { f.nested.public = LOG_CANARY; m.public = LOG_CANARY; throw new Error(LOG_CANARY); } },
    { name: 'later', write: (_l, m, f, line) => captured.push({ m, f, line }) },
  ]);
  try { log.info(message, input); } finally { _setSinks(null); }
  ok('later sink receives an independent snapshot', captured[0]?.f.nested.public === 'original' && captured[0]?.m.public === 'original');
  ok('sink mutations cannot affect caller values', input.nested.public === 'original' && message.public === 'original');
  ok('broken earlier sink cannot suppress later sinks', captured.length === 1);
  const beforeLevel = process.env.BROKER_LOG_LEVEL;
  let read = false;
  process.env.BROKER_LOG_LEVEL = 'error';
  try { log.info('filtered', { get field() { read = true; throw new Error(LOG_CANARY); } }); }
  finally { restoreEnv('BROKER_LOG_LEVEL', beforeLevel); }
  ok('filtered records never evaluate input getters', !read);
}

section('13. sink diagnostics and initialization fail safely');
{
  const work = mkdtempSync(join(tmpdir(), 'broker-log-diagnostics-'));
  const captured = [];
  const originalError = console.error;
  try {
    console.error = (...parts) => captured.push(parts.join(' '));
    parseSinks(`password=${LOG_CANARY}`);
    new FileSink(join(work, `password=${LOG_CANARY}`, '..')).write('info', 'safe', {}, '{}');
  } finally { console.error = originalError; rmSync(work, { recursive: true, force: true }); }
  ok('sink diagnostics do not contain raw configuration', captured.length >= 2 && captured.every(line => !line.includes(LOG_CANARY)));
  const temp = mkdtempSync(join(tmpdir(), 'broker-log-init-'));
  const beforeSinks = process.env.BROKER_LOG_SINKS;
  let threw = false;
  try {
    writeFileSync(join(temp, 'file'), 'not a directory');
    process.env.BROKER_LOG_SINKS = `file:${join(temp, 'file', 'child', 'log')}`;
    _setSinks(null);
    try { log.info(`password=${LOG_CANARY}`); } catch { threw = true; }
  } finally { restoreEnv('BROKER_LOG_SINKS', beforeSinks); _setSinks(null); rmSync(temp, { recursive: true, force: true }); }
  ok('sink initialization failure does not escape logger', !threw);
}

section('14. stdout and file receive identical redacted records');
{
  const work = mkdtempSync(join(tmpdir(), 'broker-log-fanout-'));
  const stdout = [];
  const stderr = [];
  const originalLog = console.log;
  const originalError = console.error;
  try {
    _setSinks([new StdoutSink(), new FileSink(join(work, 'broker.log'))]);
    console.log = line => stdout.push(line);
    console.error = line => stderr.push(line);
    log.info(`password=${LOG_CANARY}`, { token: LOG_CANARY, public: '测试' });
    log.error(`password=${LOG_CANARY}`, { token: LOG_CANARY });
  } finally { console.log = originalLog; console.error = originalError; _setSinks(null); }
  try {
    const lines = readFileSync(join(work, 'broker.log'), 'utf8').trim().split('\n');
    ok('stdout/file serialize the same informational record', stdout.length === 1 && stdout[0] === lines[0]);
    ok('stderr/file serialize the same error record', stderr.length === 1 && stderr[0] === lines[1]);
    ok('file never contains synthetic raw credential', !lines.join('\n').includes(LOG_CANARY));
    ok('non-ASCII public text remains intact', JSON.parse(lines[0]).public === '测试');
  } finally { rmSync(work, { recursive: true, force: true }); }
}

section('15. HTTP and UDP loopback transport parity');
{
  const { createServer } = await import('node:http');
  const { createSocket } = await import('node:dgram');
  const { once } = await import('node:events');
  const server = createServer();
  const udp = createSocket('udp4');
  const captured = [];
  let timer;
  try {
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    udp.bind(0, '127.0.0.1');
    await once(udp, 'listening');
    const httpReceived = new Promise((resolve) => {
      server.once('request', (req, res) => {
        const chunks = [];
        req.on('data', chunk => chunks.push(chunk));
        req.on('end', () => { const body = Buffer.concat(chunks); res.end('ok'); resolve({ body: body.toString('utf8'), declared: req.headers['content-length'], actual: body.length }); });
      });
    });
    const udpReceived = once(udp, 'message').then(([data]) => data.toString('utf8'));
    const deadline = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('local transport timeout')), 3000); });
    _setSinks([
      { name: 'capture', write: (_l, _m, _f, line) => captured.push(line) },
      new HttpSink(`http://127.0.0.1:${server.address().port}/logs`),
      new SyslogSink({ host: '127.0.0.1', port: udp.address().port }),
    ]);
    log.info(`password=${LOG_CANARY}`, { authorization: LOG_CANARY, public: '日志✓' });
    const [http, datagram] = await Promise.race([Promise.all([httpReceived, udpReceived]), deadline]);
    ok('HTTP sends the exact canonical log record', http.body === captured[0]);
    ok('HTTP content-length counts UTF-8 bytes', Number(http.declared) === http.actual);
    ok('UDP transports the same record after syslog header', datagram.endsWith(captured[0]));
    ok('transport bodies contain no raw synthetic credential', !http.body.includes(LOG_CANARY) && !datagram.includes(LOG_CANARY));
  } catch {
    ok('loopback transport verification completes', false);
  } finally {
    clearTimeout(timer);
    _setSinks(null);
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    udp.close();
  }
}

section('16. file rotation and transport guards');
{
  const { truncateSync } = await import('node:fs');
  const work = mkdtempSync(join(tmpdir(), 'broker-log-rotation-'));
  try {
    for (const previous of [false, true]) {
      const file = join(work, previous ? 'with-old.log' : 'without-old.log');
      writeFileSync(file, '');
      truncateSync(file, 50 * 1024 * 1024);
      if (previous) writeFileSync(file + '.1', 'old rotation');
      const sink = new FileSink(file);
      sink.write('info', 'safe', {}, '{"msg":"safe"}');
      ok('file rotation creates replacement without stale target', existsSync(file + '.1') && !existsSync(file) && sink.bytes === 0);
    }
    const originalError = console.error;
    const messages = [];
    console.error = (...args) => messages.push(args.join(' '));
    try {
      if (process.platform !== 'win32') new FileSink('/dev/null').write('info', 'safe', {}, '{}');
    } finally { console.error = originalError; }
    if (process.platform !== 'win32') ok('non-regular file descriptors fail closed', messages.length === 1 && messages[0] === '[log-sink file] write failed');
    let threw = false;
    try {
      new HttpSink('not-a-url').write('info', 'safe', {}, '{}');
      new HttpSink('http://127.0.0.1:1').write('info', 'safe', {});
    } catch { threw = true; }
    ok('HTTP invalid URL and absent record do not throw', !threw);
  } finally { rmSync(work, { recursive: true, force: true }); }
}

// ---------- summary ----------

console.log(`\n=== ${pass} pass / ${fail} fail ===`);
process.exit(fail === 0 ? 0 : 1);
