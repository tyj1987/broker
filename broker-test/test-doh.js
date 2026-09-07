import {
  isIpLiteral, shouldSkipDoH, pickARecord, clearDoHCache,
  resolveHostnameDoH, dohConnect,
} from '../broker/lib/doh.js';
import {
  defaultServiceTest, matchServiceTemplate, describeUpstreamStatus,
} from '../broker/lib/service-test.js';
import { SERVICE_TEMPLATES } from '../broker/service-templates.js';

let passed = 0, failed = 0;
function assert(c, m) {
  if (c) { passed++; console.log('  OK  ', m); }
  else { failed++; console.error('  FAIL', m); }
}

console.log('=== doh helpers ===');
assert(isIpLiteral('1.2.3.4'), 'ipv4 literal');
assert(isIpLiteral('::1'), 'ipv6 literal');
assert(!isIpLiteral('api.cloudflare.com'), 'hostname is not literal');
assert(shouldSkipDoH('127.0.0.1'), 'skip loopback ip');
assert(shouldSkipDoH('localhost'), 'skip localhost');
assert(shouldSkipDoH('foo.local'), 'skip .local');
assert(!shouldSkipDoH('api.cloudflare.com'), 'do not skip public host');
assert(pickARecord({ Answer: [{ type: 5, data: 'cname.' }, { type: 1, data: '104.16.1.1' }] }) === '104.16.1.1', 'pick A');
assert(pickARecord({ Answer: [] }) === null, 'empty answer');
assert(pickARecord(null) === null, 'null json');

console.log('=== resolveHostnameDoH (injected) ===');
{
  clearDoHCache();
  const ip = await resolveHostnameDoH('api.cloudflare.com', {
    request: async () => JSON.stringify({ Answer: [{ type: 1, data: '104.16.0.1' }] }),
  });
  assert(ip === '104.16.0.1', 'injected A record');
  const cached = await resolveHostnameDoH('api.cloudflare.com', {
    request: async () => { throw new Error('should use cache'); },
  });
  assert(cached === '104.16.0.1', 'cache hit');
  assert((await resolveHostnameDoH('127.0.0.1')) === '127.0.0.1', 'skip ip');
  assert((await resolveHostnameDoH('localhost')) === 'localhost', 'skip localhost');
  clearDoHCache();
  let threw = false;
  try {
    await resolveHostnameDoH('no.such.host.invalid', {
      endpoints: [{ url: 'https://x/dns-query', ip: '1.1.1.1', host: 'x' }],
      request: async () => { throw new Error('fail'); },
    });
  } catch (e) {
    threw = /DoH resolve failed for no.such.host.invalid/.test(e.message);
  }
  assert(threw, 'all endpoints fail → DoH resolve failed');
  const conn = await dohConnect('api.example', {
    request: async () => JSON.stringify({ Answer: [{ type: 1, data: '9.9.9.9' }] }),
  });
  assert(conn.hostname === '9.9.9.9' && conn.servername === 'api.example', 'dohConnect SNI stays on name');
  const skipped = await dohConnect('api.example', { skip: true });
  assert(skipped.hostname === 'api.example' && skipped.servername === 'api.example', 'dohConnect skip');
  clearDoHCache();
}

console.log('=== defaultServiceTest ===');
{
  const cfTpl = defaultServiceTest({ name: 'cloudflare', upstream: 'https://api.cloudflare.com/client/v4' });
  assert(cfTpl.path === '/user/tokens/verify', 'cf by name → verify');
  assert(cfTpl.method === 'GET', 'cf method GET');

  const cfHost = defaultServiceTest({ name: 'prod_cf', upstream: 'https://api.cloudflare.com/client/v4' });
  assert(cfHost.path === '/user/tokens/verify', 'cf by upstream host → verify');
  assert(matchServiceTemplate({ upstream: 'https://api.cloudflare.com/client/v4' })?.id === 'cloudflare', 'match host');

  const explicit = defaultServiceTest({
    name: 'cloudflare',
    upstream: 'https://api.cloudflare.com/client/v4',
    dashboard_actions: [{ method: 'GET', path: '/zones' }],
  });
  assert(explicit.path === '/zones', 'service action wins over template');

  const slashOnly = defaultServiceTest({
    name: 'cloudflare',
    dashboard_actions: [{ method: 'GET', path: '/' }],
    upstream: 'https://api.cloudflare.com/client/v4',
  });
  assert(slashOnly.path === '/user/tokens/verify', 'GET / is not useful → template');

  const unknown = defaultServiceTest({ name: 'custom', upstream: 'https://example.invalid/api' });
  assert(unknown.path === '/' && unknown.method === 'GET', 'unknown → GET /');

  const gh = defaultServiceTest({ name: 'github', upstream: SERVICE_TEMPLATES.github.upstream });
  assert(gh.path && gh.path !== '/', 'github has a real action');
}

console.log('=== describeUpstreamStatus ===');
{
  assert(describeUpstreamStatus(200).ok === true, '200 ok');
  const r301 = describeUpstreamStatus(301, { path: '/', hostname: 'api.cloudflare.com' });
  assert(r301.ok === false && /redirected \(301\)/.test(r301.error), '301 not ok');
  assert(/tokens\/verify/.test(r301.error), '301 hint names verify');
  const r403 = describeUpstreamStatus(403);
  assert(r403.ok === false && !r403.error, '4xx ok=false without redirect error');
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
