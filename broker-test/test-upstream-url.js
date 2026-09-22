// broker-test/test-upstream-url.js — credential proxy origin confinement

import { resolveUpstreamUrl, validateConfiguredUpstream } from '../broker/lib/upstream-url.js';

let pass = 0;
let fail = 0;

function ok(name, cond) {
  if (cond) {
    pass++;
    console.log(`  PASS  ${name}`);
  } else {
    fail++;
    console.error(`  FAIL  ${name}`);
  }
}

function rejects(name, upstream, path) {
  let threw = false;
  try {
    resolveUpstreamUrl(upstream, path);
  } catch {
    threw = true;
  }
  ok(name, threw);
}

console.log('[upstream URL confinement]');

{
  const u = resolveUpstreamUrl('https://api.example.com/v1/', '/users?id=1');
  ok('same-origin absolute path allowed', u.href === 'https://api.example.com/users?id=1');
}
{
  const u = resolveUpstreamUrl('https://api.example.com/v1/', 'items');
  ok('same-origin relative path allowed', u.href === 'https://api.example.com/v1/items');
}
{
  const u = resolveUpstreamUrl('https://api.example.com/', 'https://api.example.com/safe');
  ok('same-origin absolute URL remains confined', u.href === 'https://api.example.com/safe');
}

rejects(
  'absolute cross-origin URL rejected',
  'https://api.example.com/',
  'https://attacker.example/collect',
);
rejects(
  'scheme-relative cross-origin URL rejected',
  'https://api.example.com/',
  '//attacker.example/collect',
);
rejects(
  'different port is different origin and rejected',
  'https://api.example.com/',
  'https://api.example.com:8443/collect',
);
rejects('javascript protocol rejected', 'https://api.example.com/', 'javascript:alert(1)');
rejects('non-http configured upstream rejected', 'file:///tmp/', '/secret');
rejects('public plain HTTP upstream rejected by default', 'http://api.example.com/', '/secret');
{
  const u = resolveUpstreamUrl('http://127.0.0.1:8080/', '/health');
  ok('loopback HTTP upstream allowed', u.href === 'http://127.0.0.1:8080/health');
}
{
  const u = resolveUpstreamUrl('http://api.example.com/', '/health', { allowInsecureHttp: true });
  ok('explicit insecure HTTP override works', u.href === 'http://api.example.com/health');
}
{
  let threw = false;
  try {
    validateConfiguredUpstream('https://user:pass@api.example.com/');
  } catch {
    threw = true;
  }
  ok('embedded upstream credentials rejected', threw);
}

console.log(`\n=== Total: ${pass} passed, ${fail} failed ===`);
process.exit(fail > 0 ? 1 : 0);
