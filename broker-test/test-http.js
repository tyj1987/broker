// broker-test/test-http.js — V4.7.0 lib/http.js 单元测试
// 覆盖 send / readBody / jsonError

import { readFileSync } from 'node:fs';
import { Readable } from 'node:stream';
import {
  send,
  sendBuffer,
  readBody,
  jsonError,
  wrapAsyncRequestHandler,
  RequestBodyTooLargeError,
} from '../broker/lib/http.js';

let pass = 0,
  fail = 0;
function ok(name, cond, detail) {
  if (cond) {
    pass++;
    console.log(`  PASS  ${name}`);
  } else {
    fail++;
    console.error(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`);
  }
}
function section(t) {
  console.log(`\n[${t}]`);
}

function mockRes() {
  const headers = {};
  return {
    statusCode: 0,
    body: null,
    headers,
    setHeader(k, v) {
      headers[k.toLowerCase()] = v;
    },
    writeHead(code, hdrs) {
      this.statusCode = code;
      Object.entries(hdrs).forEach(([k, v]) => {
        headers[k.toLowerCase()] = v;
      });
    },
    end(payload) {
      this.body = payload;
    },
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
  ok(
    'content-length matches body size',
    Number(res.headers['content-length']) === Buffer.byteLength('{"ok":true}', 'utf8'),
  );
  ok('security headers merged (CSP)', res.headers['content-security-policy'] !== undefined);
  ok('security headers merged (X-Frame-Options)', res.headers['x-frame-options'] === 'DENY');
  ok('JSON responses are non-cacheable', res.headers['cache-control'] === 'no-store');
  ok('JSON responses include legacy no-cache directive', res.headers.pragma === 'no-cache');
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
  // extra headers merged and may intentionally override defaults.
  const res = mockRes();
  send(res, 200, {}, { 'X-Custom': 'val', 'Cache-Control': 'private, max-age=60' });
  ok('extra header merged', res.headers['x-custom'] === 'val');
  ok(
    'explicit cache policy overrides default',
    res.headers['cache-control'] === 'private, max-age=60',
  );
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
{
  // Never overwrite a response that another route already completed.
  const res = mockRes();
  res.headersSent = true;
  send(res, 500, { error: 'late write' });
  ok('already-sent response is not overwritten', res.statusCode === 0 && res.body === null);
}

// ============================================================
// sendBuffer
// ============================================================
section('sendBuffer');
{
  const res = mockRes();
  const payload = Buffer.from([0, 1, 2, 255]);
  sendBuffer(res, 200, payload, 'application/zip', {
    'Content-Disposition': 'attachment; filename="bundle.zip"',
    exposeVersion: true,
  });
  ok('binary status 200', res.statusCode === 200);
  ok('binary payload is preserved', Buffer.isBuffer(res.body) && res.body.equals(payload));
  ok('binary content type is explicit', res.headers['content-type'] === 'application/zip');
  ok('binary content length is exact', Number(res.headers['content-length']) === payload.length);
  ok('binary response is non-cacheable', res.headers['cache-control'] === 'no-store');
  ok('binary response includes security headers', res.headers['x-frame-options'] === 'DENY');
  ok('binary response exposes version only when requested', !!res.headers['x-broker-version']);
  ok(
    'binary content disposition is preserved',
    res.headers['content-disposition'] === 'attachment; filename="bundle.zip"',
  );
}
{
  const res = mockRes();
  res.writableEnded = true;
  sendBuffer(res, 200, Buffer.from('late'));
  ok('binary helper does not write after response end', res.statusCode === 0 && res.body === null);
}
{
  // The main HTTPS server must delegate to the same hardened response helper.
  const serverSource = readFileSync(new URL('../broker/server.js', import.meta.url), 'utf8');
  ok('server imports shared hardened send helper', serverSource.includes('send as sendSafe'));
  ok(
    'server delegates ordinary API responses to hardened send helper',
    /return sendSafe\(res, status, body, \{/.test(serverSource),
  );
  ok(
    'plain HTTP local-health listener explicitly opts out of HTTPS-only headers',
    /sendSafe\(response, status, body, \{ \.\.\.extraHeaders, noSecurityHeaders: true \}\)/.test(
      serverSource,
    ),
  );
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
  try {
    await readBody(req);
  } catch (e) {
    threw = /too large/.test(e.message);
  }
  ok('body > 1MB rejected', threw);
}
{
  // malformed JSON → _raw
  const req = Readable.from([Buffer.from('{not json}')]);
  const body = await readBody(req);
  ok('malformed JSON → _raw', body && body._raw === '{not json}');
}
{
  // Reject from Content-Length before buffering the body.
  const req = Readable.from([Buffer.from('{}')]);
  req.headers = { 'content-length': String(2 * 1024 * 1024) };
  let err = null;
  try {
    await readBody(req);
  } catch (e) {
    err = e;
  }
  ok(
    'oversized Content-Length rejected',
    err instanceof RequestBodyTooLargeError && err.statusCode === 413,
  );
}

// ============================================================
// async request listener safety
// ============================================================
section('wrapAsyncRequestHandler');
{
  const res = mockRes();
  const listener = wrapAsyncRequestHandler(async () => {
    throw new RequestBodyTooLargeError();
  });
  listener({}, res);
  await new Promise((resolve) => setImmediate(resolve));
  ok('body-limit rejection becomes 413', res.statusCode === 413);
  ok('413 response hides internal detail', res.body.includes('Request body too large'));
  ok('413 disables keep-alive', res.shouldKeepAlive === false);
  ok('413 explicitly closes the connection', res.headers.connection === 'close');
}
{
  const res = mockRes();
  const listener = wrapAsyncRequestHandler(async () => {
    throw new Error('sensitive internal detail');
  });
  listener({}, res);
  await new Promise((resolve) => setImmediate(resolve));
  ok('unexpected async rejection becomes 500', res.statusCode === 500);
  ok(
    '500 response does not leak exception detail',
    !res.body.includes('sensitive internal detail'),
  );
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
