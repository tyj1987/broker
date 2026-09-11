// broker-test/test-http.js — V4.7.0 lib/http.js 单元测试
// 覆盖 send / readBody / jsonError

import { Readable } from 'node:stream';
import { send, readBody, jsonError } from '../broker/lib/http.js';

let pass = 0, fail = 0;
function ok(name, cond, detail) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`); }
}
function section(t) { console.log(`\n[${t}]`); }

function mockRes() {
  const headers = {};
  return {
    statusCode: 0,
    body: null,
    headers,
    setHeader(k, v) { headers[k.toLowerCase()] = v; },
    writeHead(code, hdrs) {
      this.statusCode = code;
      Object.entries(hdrs).forEach(([k, v]) => { headers[k.toLowerCase()] = v; });
    },
    end(payload) { this.body = payload; },
  };
}

// ============================================================
// send
// ============================================================
section('send');
{
  const res = mockRes();
  send(res, 200, { ok: true });
  ok('status 200', res.statusCode === 200);
  ok('body JSON serialized', res.body === '{"ok":true}');
  ok('content-type json', res.headers['content-type'] === 'application/json; charset=utf-8');
  // Node's http module accepts both string and number for Content-Length;
  // mockRes stores the raw value. Verify the numeric value matches.
  ok('content-length matches body size', Number(res.headers['content-length']) === Buffer.byteLength('{"ok":true}', 'utf8'));
  ok('security headers merged (CSP)', res.headers['content-security-policy'] !== undefined);
  ok('security headers merged (X-Frame-Options)', res.headers['x-frame-options'] === 'DENY');
}
{
  const res = mockRes();
  send(res, 200, 'plain text');
  ok('text body', res.body === 'plain text');
  ok('content-type text', res.headers['content-type'] === 'text/plain; charset=utf-8');
}
{
  // noSecurityHeaders flag
  const res = mockRes();
  send(res, 200, { ok: true }, { noSecurityHeaders: true });
  ok('no security headers when opted out', res.headers['x-frame-options'] === undefined);
}
{
  // X-Broker-Version only when exposeVersion=true
  const res1 = mockRes();
  send(res1, 200, {});
  ok('no X-Broker-Version by default', res1.headers['x-broker-version'] === undefined);
  const res2 = mockRes();
  send(res2, 200, {}, { exposeVersion: true });
  ok('X-Broker-Version when exposeVersion=true', res2.headers['x-broker-version'] !== undefined);
}
{
  // extra headers merged
  const res = mockRes();
  send(res, 200, {}, { 'X-Custom': 'val' });
  ok('extra header merged', res.headers['x-custom'] === 'val');
}
{
  // _kind hint switches CSP profile
  const resJson = mockRes();
  send(resJson, 200, {}, { _kind: 'json' });
  const resHtml = mockRes();
  send(resHtml, 200, {}, { _kind: 'html' });
  // Both should have CSP, possibly different
  ok('_kind=json adds CSP', resJson.headers['content-security-policy'] !== undefined);
  ok('_kind=html adds CSP', resHtml.headers['content-security-policy'] !== undefined);
}
{
  // 404 + error body
  const res = mockRes();
  send(res, 404, { error: 'not found' });
  ok('404 status', res.statusCode === 404);
  ok('404 body', res.body === '{"error":"not found"}');
}

// ============================================================
// readBody
// ============================================================
section('readBody');
{
  // JSON body
  const req = Readable.from([Buffer.from('{"a":1,"b":2}')]);
  const body = await readBody(req);
  ok('parses JSON body', body && body.a === 1 && body.b === 2);
}
{
  // non-JSON body → _raw
  const req = Readable.from([Buffer.from('plain=text')]);
  const body = await readBody(req);
  ok('non-JSON → _raw', body && body._raw === 'plain=text');
}
{
  // empty body → null
  const req = Readable.from([]);
  const body = await readBody(req);
  ok('empty body → null', body === null);
}
{
  // body > 1MB → rejects
  const big = 'x'.repeat(1024 * 1024 + 1);
  const req = Readable.from([Buffer.from(big)]);
  let threw = false;
  try { await readBody(req); } catch (e) { threw = /too large/.test(e.message); }
  ok('body > 1MB rejected', threw);
}
{
  // malformed JSON → _raw
  const req = Readable.from([Buffer.from('{not json}')]);
  const body = await readBody(req);
  ok('malformed JSON → _raw', body && body._raw === '{not json}');
}

// ============================================================
// jsonError
// ============================================================
section('jsonError');
{
  const res = mockRes();
  jsonError(res, 403, 'Admin only');
  ok('status 403', res.statusCode === 403);
  ok('body has error field', res.body.includes('"error":"Admin only"'));
  ok('body has status field', res.body.includes('"status":403'));
}
{
  const res = mockRes();
  jsonError(res, 500, 'oops');
  ok('500 status', res.statusCode === 500);
}

console.log(`\n=== Total: ${pass} passed, ${fail} failed ===`);
process.exit(fail > 0 ? 1 : 0);
