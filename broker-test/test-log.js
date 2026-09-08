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
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

let pass = 0, fail = 0;
function ok(name, cond, detail) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`); }
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
  process.env.BROKER_LOG_LEVEL = orig;
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

// ---------- summary ----------

console.log(`\n=== ${pass} pass / ${fail} fail ===`);
process.exit(fail === 0 ? 0 : 1);
