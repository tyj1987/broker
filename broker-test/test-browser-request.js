// Browser cookie-session origin boundary tests.

import { readFileSync } from 'node:fs';
import {
  checkTrustedBrowserMutation,
  expectedBrowserOrigin,
  isBrowserRequest,
  isCookieSessionRequest,
} from '../broker/lib/browser-request.js';

let passed = 0;
let failed = 0;

function ok(name, condition) {
  if (condition) {
    passed += 1;
    console.log(`  PASS  ${name}`);
  } else {
    failed += 1;
    console.error(`  FAIL  ${name}`);
  }
}

function request({ method = 'POST', headers = {}, encrypted = true } = {}) {
  return {
    method,
    headers: Object.fromEntries(
      Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value]),
    ),
    socket: { encrypted },
  };
}

console.log('[expected origin]');
{
  const req = request({ headers: { Host: 'broker.52trz.com' } });
  ok(
    'HTTPS host becomes exact expected origin',
    expectedBrowserOrigin(req, {}) === 'https://broker.52trz.com',
  );
  ok(
    'explicit public origin wins',
    expectedBrowserOrigin(req, { BROKER_PUBLIC_ORIGIN: 'https://admin.example.com/' }) ===
      'https://admin.example.com',
  );
  ok(
    'unsafe configured HTTP origin is rejected',
    expectedBrowserOrigin(req, { BROKER_PUBLIC_ORIGIN: 'http://admin.example.com' }) === null,
  );
  ok(
    'loopback HTTP origin is permitted for development',
    expectedBrowserOrigin(req, { BROKER_PUBLIC_ORIGIN: 'http://127.0.0.1:8443' }) ===
      'http://127.0.0.1:8443',
  );
}

console.log('\n[mutation origin checks]');
{
  const sameOrigin = request({
    headers: {
      Host: 'broker.52trz.com',
      Origin: 'https://broker.52trz.com',
      'Sec-Fetch-Site': 'same-origin',
    },
  });
  ok(
    'same-origin browser POST allowed',
    checkTrustedBrowserMutation(sameOrigin, { requireOrigin: true }).ok,
  );

  const crossOrigin = request({
    headers: {
      Host: 'broker.52trz.com',
      Origin: 'https://evil.52trz.com',
      'Sec-Fetch-Site': 'same-site',
    },
  });
  const cross = checkTrustedBrowserMutation(crossOrigin, { requireOrigin: true });
  ok('same-site subdomain mutation denied', !cross.ok);
  ok('same-site denial uses fetch-metadata reason', cross.reason === 'cross_origin_fetch_metadata');

  const mismatchedOrigin = request({
    headers: { Host: 'broker.52trz.com', Origin: 'https://evil.example' },
  });
  ok(
    'mismatched Origin denied without fetch metadata',
    checkTrustedBrowserMutation(mismatchedOrigin, { requireOrigin: true }).reason ===
      'origin_mismatch',
  );

  const missing = request({ headers: { Host: 'broker.52trz.com' } });
  ok(
    'cookie mutation requires Origin',
    checkTrustedBrowserMutation(missing, { requireOrigin: true }).reason === 'origin_required',
  );
  ok(
    'non-browser login client remains compatible',
    checkTrustedBrowserMutation(missing, { requireOrigin: false }).ok,
  );
  ok(
    'safe GET never requires Origin',
    checkTrustedBrowserMutation(request({ method: 'GET' }), { requireOrigin: true }).ok,
  );
  ok(
    'opaque Origin is denied',
    checkTrustedBrowserMutation(
      request({ headers: { Host: 'broker.52trz.com', Origin: 'null' } }),
      { requireOrigin: true },
    ).reason === 'invalid_origin',
  );
}

console.log('\n[cookie and browser detection]');
{
  const cookieReq = request({ headers: { Cookie: 'a=1; broker_session=session-id; b=2' } });
  ok('host-only broker session cookie is detected', isCookieSessionRequest(cookieReq));
  const headerReq = request({
    headers: { Cookie: 'broker_session=session-id', 'X-Auth-Token': 'explicit-token' },
  });
  ok(
    'explicit session header is not treated as cookie authentication',
    !isCookieSessionRequest(headerReq),
  );
  ok(
    'Origin identifies a browser request',
    isBrowserRequest(request({ headers: { Origin: 'https://broker.52trz.com' } })),
  );
  ok('plain CLI request is not identified as browser', !isBrowserRequest(request()));
}

console.log('\n[server wiring]');
{
  const source = readFileSync(new URL('../broker/server.js', import.meta.url), 'utf8');
  ok('server imports browser mutation boundary', source.includes('checkTrustedBrowserMutation'));
  ok('cookie sessions are origin-gated', source.includes("rejectBrowserMutation('session_origin'"));
  ok('logout is origin-gated', source.includes("rejectBrowserMutation('logout_origin'"));
  ok('password login is origin-checked', source.includes("rejectBrowserMutation('login_origin'"));
  ok('MFA login is origin-checked', source.includes("rejectBrowserMutation('login_mfa_origin'"));
  ok(
    'browser login response does not expose the session token',
    source.split('...(isBrowserRequest(req) ? {} : { token })').length - 1 === 2,
  );
}

console.log(`\n=== Total: ${passed} passed, ${failed} failed ===`);
process.exit(failed > 0 ? 1 : 0);
