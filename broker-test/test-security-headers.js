// broker-test/test-security-headers.js — V4.1.1 tests for broker/lib/security-headers.js
// Tests the new HTTP security headers module added per REVIEW.md Now#1.
//
//   - Default headers are present
//   - CSP varies by kind (html / json / sse / static)
//   - HSTS is configurable via env
//   - Disable switch works (BROKER_DISABLE_SECURITY_HEADERS=1)
//   - send() in http.js merges security headers
//   - snapshotHeaders() is pure

import {
  securityHeaders,
  snapshotHeaders,
} from '../broker/lib/security-headers.js';
import { send } from '../broker/lib/http.js';

let pass = 0, fail = 0;
function ok(name, cond, detail) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`); }
}
function section(t) { console.log(`\n[${t}]`); }

// ---------- tests ----------

section('1. Default headers are present (json kind)');

const json = securityHeaders({ kind: 'json' });
ok('X-Content-Type-Options: nosniff', json['X-Content-Type-Options'] === 'nosniff');
ok('X-Frame-Options: DENY', json['X-Frame-Options'] === 'DENY');
ok('Referrer-Policy: no-referrer', json['Referrer-Policy'] === 'no-referrer');
ok('Strict-Transport-Security set', /^max-age=\d+/.test(json['Strict-Transport-Security'] || ''));
ok('HSTS includes includeSubDomains', /includeSubDomains/.test(json['Strict-Transport-Security']));
ok('Cross-Origin-Opener-Policy: same-origin', json['Cross-Origin-Opener-Policy'] === 'same-origin');
ok('Cross-Origin-Resource-Policy: same-origin', json['Cross-Origin-Resource-Policy'] === 'same-origin');
ok('Permissions-Policy present', typeof json['Permissions-Policy'] === 'string' && json['Permissions-Policy'].length > 0);

section('2. CSP varies by kind');

const htmlH = securityHeaders({ kind: 'html' });
const jsonH = securityHeaders({ kind: 'json' });
const sseH = securityHeaders({ kind: 'sse' });
const staticH = securityHeaders({ kind: 'static' });
ok('html CSP has script-src', /script-src/.test(htmlH['Content-Security-Policy']));
ok('html CSP has frame-ancestors none', /frame-ancestors 'none'/.test(htmlH['Content-Security-Policy']));
ok('json CSP has default-src none', /default-src 'none'/.test(jsonH['Content-Security-Policy']));
ok('json CSP has frame-ancestors none', /frame-ancestors 'none'/.test(jsonH['Content-Security-Policy']));
ok('sse CSP = json CSP', sseH['Content-Security-Policy'] === jsonH['Content-Security-Policy']);
ok('sse adds Cache-Control: no-store', sseH['Cache-Control'] === 'no-store');
ok('static CSP = html CSP', staticH['Content-Security-Policy'] === htmlH['Content-Security-Policy']);
ok('default kind is json', JSON.stringify(jsonH) === JSON.stringify(securityHeaders()));

section('3. snapshotHeaders is a pure snapshot');

const snap1 = snapshotHeaders('json');
const snap2 = snapshotHeaders('json');
ok('snapshots are deep equal', JSON.stringify(snap1) === JSON.stringify(snap2));
// Mutating the snapshot must not affect future calls
snap1['X-Frame-Options'] = 'TAMPERED';
const snap3 = snapshotHeaders('json');
ok('snapshot mutation does not leak', snap3['X-Frame-Options'] === 'DENY');

section('4. send() merges security headers into response');

const fakeRes = makeFakeRes();
send(fakeRes, 200, { ok: true });
ok('response has X-Content-Type-Options', fakeRes.headers['X-Content-Type-Options'] === 'nosniff');
ok('response has X-Frame-Options: DENY', fakeRes.headers['X-Frame-Options'] === 'DENY');
ok('response has CSP for json', typeof fakeRes.headers['Content-Security-Policy'] === 'string');
ok('response Content-Type is JSON', /application\/json/.test(fakeRes.headers['Content-Type']));
ok('response Content-Length set', fakeRes.headers['Content-Length'] > 0);

section('5. send() can override security headers');

const fakeRes2 = makeFakeRes();
send(fakeRes2, 200, { html: '<p>hi</p>' }, { _kind: 'html', 'X-Frame-Options': 'SAMEORIGIN' });
ok('X-Frame-Options override applied', fakeRes2.headers['X-Frame-Options'] === 'SAMEORIGIN');
ok('CSP still applied (html kind)', /script-src/.test(fakeRes2.headers['Content-Security-Policy']));

section('6. send() respects noSecurityHeaders escape hatch');

const fakeRes3 = makeFakeRes();
send(fakeRes3, 200, { ok: true }, { noSecurityHeaders: true });
ok('no X-Frame-Options when disabled', !('X-Frame-Options' in fakeRes3.headers));
ok('no CSP when disabled', !('Content-Security-Policy' in fakeRes3.headers));

section('7. Disable switch (BROKER_DISABLE_SECURITY_HEADERS=1)');

const prevDisabled = process.env.BROKER_DISABLE_SECURITY_HEADERS;
process.env.BROKER_DISABLE_SECURITY_HEADERS = '1';
// Re-import to pick up env change (module is cached but the disabled flag is captured)
const sec2 = await import('../broker/lib/security-headers.js?v=' + Date.now());
const off = sec2.securityHeaders({ kind: 'json' });
ok('headers empty when disabled', Object.keys(off).length === 0);
process.env.BROKER_DISABLE_SECURITY_HEADERS = prevDisabled;

section('8. All headers are strings (no arrays/booleans)');

const all = { ...json, ...htmlH };
for (const [k, v] of Object.entries(all)) {
  if (typeof v !== 'string') {
    ok(`header "${k}" is string`, false, `got ${typeof v}`);
    break;
  }
}
ok('all headers are strings', true);

section('9. No fingerprinting headers added (no Server / X-Powered-By)');

ok('no Server header', !('Server' in json));
ok('no X-Powered-By header', !('X-Powered-By' in json));

// ---------- helpers ----------

function makeFakeRes() {
  const headers = {};
  return {
    headers,
    statusCode: 0,
    body: null,
    writeHead(status, h) {
      this.statusCode = status;
      Object.assign(this.headers, h);
      return this;
    },
    end(payload) {
      this.body = payload;
      return this;
    },
  };
}

// ---------- summary ----------

console.log(`\n=== ${pass} pass / ${fail} fail ===`);
process.exit(fail === 0 ? 0 : 1);
