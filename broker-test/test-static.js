// broker-test/test-static.js — V4.1.1 tests for broker/routes/static.js
//
// Verifies:
//   1. Returns 200 with body for first GET
//   2. Returns 304 when If-None-Match matches the ETag
//   3. Returns 304 when If-None-Match is "*"
//   4. Returns 304 when If-None-Match has multiple ETags including ours
//   5. Returns 200 when If-None-Match is stale
//   6. Body is cached on second read (no re-stat)
//   7. Security headers applied to all responses (200 and 304)
//   8. 500 for missing dashboard file
//   9. Falls through (returns false) for non-GET or unknown paths

import {
  handleStatic,
  STATIC_MAP,
  _internals,
} from '../broker/routes/static.js';
import { mkdtempSync, writeFileSync, rmSync, existsSync, statSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

let pass = 0, fail = 0;
function ok(name, cond, detail) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`); }
}
function section(t) { console.log(`\n[${t}]`); }

// ---------- setup ----------

const WORK = mkdtempSync(join(tmpdir(), 'broker-static-test-'));
const dashboardDir = join(WORK, 'dashboard');
mkdirSync(dashboardDir, { recursive: true });
writeFileSync(join(dashboardDir, 'app.js'), 'console.log("hi");');
writeFileSync(join(dashboardDir, 'style.css'), 'body { color: red; }');
writeFileSync(join(dashboardDir, 'index.html'), '<html><body>hi</body></html>');

// ---------- helpers ----------

function fakeReq(headers = {}) {
  return { headers, method: 'GET', url: '/' };
}
function fakeRes() {
  const res = {
    statusCode: 0,
    headers: {},
    body: null,
    ended: false,
  };
  res.writeHead = (status, headers) => { res.statusCode = status; res.headers = headers; return res; };
  res.end = (body) => { res.ended = true; if (body !== undefined) res.body = body; return res; };
  return res;
}

const deps = { dashboardDir };

// ---------- tests ----------

section('1. First GET returns 200 with body');

{
  const res = fakeRes();
  const handled = handleStatic(fakeReq(), res, { method: 'GET', pathname: '/app.js' }, deps);
  ok('handled', handled === true);
  ok('status 200', res.statusCode === 200);
  ok('body matches', res.body.toString() === 'console.log("hi");');
  ok('ETag header set', typeof res.headers['ETag'] === 'string' && res.headers['ETag'].startsWith('"'));
  ok('Cache-Control set', /max-age=300/.test(res.headers['Cache-Control']));
  ok('Content-Type: js', res.headers['Content-Type'] === 'application/javascript; charset=utf-8');
  ok('X-Frame-Options: DENY', res.headers['X-Frame-Options'] === 'DENY');
  ok('X-Content-Type-Options: nosniff', res.headers['X-Content-Type-Options'] === 'nosniff');
  ok('CSP applied', typeof res.headers['Content-Security-Policy'] === 'string');

  // Save ETag for next tests
  globalThis._etag = res.headers['ETag'];
}

section('2. If-None-Match matches → 304');

{
  const res = fakeRes();
  const req = fakeReq({ 'if-none-match': globalThis._etag });
  const handled = handleStatic(req, res, { method: 'GET', pathname: '/app.js' }, deps);
  ok('handled', handled === true);
  ok('status 304', res.statusCode === 304);
  ok('ETag still set on 304', res.headers['ETag'] === globalThis._etag);
  ok('no body on 304', res.body === null);
  ok('Cache-Control on 304', /max-age=300/.test(res.headers['Cache-Control']));
}

section('3. If-None-Match: *  → 304');

{
  const res = fakeRes();
  const req = fakeReq({ 'if-none-match': '*' });
  const handled = handleStatic(req, res, { method: 'GET', pathname: '/app.js' }, deps);
  ok('handled', handled === true);
  ok('status 304', res.statusCode === 304);
}

section('4. If-None-Match has multiple ETags including ours → 304');

{
  const res = fakeRes();
  const req = fakeReq({ 'if-none-match': '"some-other-etag", ' + globalThis._etag + ', "another"' });
  const handled = handleStatic(req, res, { method: 'GET', pathname: '/app.js' }, deps);
  ok('handled', handled === true);
  ok('status 304 (matched in list)', res.statusCode === 304);
}

section('5. If-None-Match is stale → 200');

{
  const res = fakeRes();
  const req = fakeReq({ 'if-none-match': '"old-etag-not-matching-anything"' });
  const handled = handleStatic(req, res, { method: 'GET', pathname: '/app.js' }, deps);
  ok('handled', handled === true);
  ok('status 200 (stale)', res.statusCode === 200);
  ok('body returned', res.body && res.body.toString() === 'console.log("hi");');
}

section('6. Different file → different ETag');

{
  const res1 = fakeRes();
  handleStatic(fakeReq(), res1, { method: 'GET', pathname: '/style.css' }, deps);
  ok('css served', res1.statusCode === 200);
  ok('css ETag differs from app.js', res1.headers['ETag'] !== globalThis._etag);
  ok('Content-Type: css', res1.headers['Content-Type'] === 'text/css; charset=utf-8');
}

section('7. HTML file → no-cache + html CSP');

{
  const res = fakeRes();
  handleStatic(fakeReq(), res, { method: 'GET', pathname: '/' }, deps);
  ok('served', res.statusCode === 200);
  ok('Cache-Control no-cache', /no-cache/.test(res.headers['Cache-Control']));
  ok('CSP has script-src (html)', /script-src/.test(res.headers['Content-Security-Policy']));
}

section('8. 500 for missing dashboard file');

{
  // Map points to a path that doesn't exist
  const res = fakeRes();
  // Simulate by manually constructing a missing-file path: STATIC_MAP exists but file is absent.
  // We'll just remove the file and re-request.
  rmSync(join(dashboardDir, 'app.js'));
  const handled = handleStatic(fakeReq(), res, { method: 'GET', pathname: '/app.js' }, deps);
  ok('handled', handled === true);
  ok('status 500', res.statusCode === 500);
  ok('Cache-Control no-store', res.headers['Cache-Control'] === 'no-store');
  ok('security headers applied', res.headers['X-Frame-Options'] === 'DENY');
  // restore
  writeFileSync(join(dashboardDir, 'app.js'), 'console.log("hi");');
  // invalidate cache
  _internals.metaCache.clear();
}

section('9. Non-GET falls through (returns false)');

{
  const res = fakeRes();
  const handled = handleStatic(fakeReq(), res, { method: 'POST', pathname: '/app.js' }, deps);
  ok('not handled', handled === false);
}

section('10. Unknown path falls through');

{
  const res = fakeRes();
  const handled = handleStatic(fakeReq(), res, { method: 'GET', pathname: '/something-random' }, deps);
  ok('not handled', handled === false);
}

section('11. Body cache works');

{
  // Trigger a 200 response so loadBody() runs and caches the body
  const res = fakeRes();
  handleStatic(fakeReq(), res, { method: 'GET', pathname: '/app.js' }, deps);
  const meta = _internals.fileMeta(join(dashboardDir, 'app.js'));
  ok('body cached after first load', meta.body !== null);
  ok('body length matches', meta.body.length === 18); // 'console.log("hi");' = 18 chars
}

// ---------- summary ----------

console.log(`\n=== ${pass} pass / ${fail} fail ===`);
rmSync(WORK, { recursive: true, force: true });
process.exit(fail === 0 ? 0 : 1);
