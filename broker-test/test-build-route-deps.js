// broker-test/test-build-route-deps.js
import { buildRouteDeps, useModularRoutes } from '../broker/lib/build-route-deps.js';
import { PUBLIC_HANDLERS, API_HANDLERS, ALL_HANDLERS, dispatch } from '../broker/routes/index.js';

let passed = 0, failed = 0;
function assert(c, m) {
  if (c) { passed++; console.log('  OK  ', m); }
  else { failed++; console.error('  FAIL', m); }
}

console.log('=== buildRouteDeps ===');
{
  const d = buildRouteDeps({ send: 1, config: { a: 1 }, version: '3.4.0' });
  assert(d.send === 1 && d.config.a === 1 && d.version === '3.4.0', 'fields');
  assert(typeof d.audit === 'function', 'default audit');
  assert(d.canAccessSecret() === true, 'default canAccess');
}

console.log('=== useModularRoutes ===');
{
  const prev = process.env.USE_MODULAR_ROUTES;
  delete process.env.USE_MODULAR_ROUTES;
  assert(useModularRoutes() === false, 'default off');
  process.env.USE_MODULAR_ROUTES = '1';
  assert(useModularRoutes() === true, 'on');
  process.env.USE_MODULAR_ROUTES = 'true';
  assert(useModularRoutes() === true, 'true');
  if (prev === undefined) delete process.env.USE_MODULAR_ROUTES;
  else process.env.USE_MODULAR_ROUTES = prev;
}

console.log('=== handler registries ===');
{
  assert(PUBLIC_HANDLERS.length === 2, 'public');
  assert(API_HANDLERS.length === 6, 'api');
  assert(ALL_HANDLERS.length === 8, 'all');
  assert(typeof dispatch === 'function', 'dispatch');
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
