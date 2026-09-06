import { prepareReadOnlyServiceTest } from '../broker/lib/service-test-policy.js';

let passed = 0;
function ok(name, condition) { if (!condition) throw new Error(`FAIL: ${name}`); passed++; console.log(`  PASS  ${name}`); }
function rejects(name, fn, status) { let error; try { fn(); } catch (e) { error = e; } ok(name, error?.statusCode === status); }

const service = { environment: 'production', operations: {
  probe: { method: 'GET', path: '/v1/status' },
  mutate: { method: 'POST', path: '/v1/items', allow_body: true },
}};
const context = { client: { role: 'admin', allowed_operations: [
  { service: 'example', operations: ['probe'], environments: ['production'] },
] }};

const result = prepareReadOnlyServiceTest({ serviceName: 'example', service, body: { operation_id: 'probe', parameters: {} }, context });
ok('registered authorized GET operation accepted', result.operationId === 'probe' && result.request.path === '/v1/status');
rejects('caller-selected path cannot replace operation', () => prepareReadOnlyServiceTest({ serviceName: 'example', service, body: { operation_id: 'missing', path: 'https://evil.example' }, context }), 400);
rejects('mutating operation denied even when registered', () => prepareReadOnlyServiceTest({ serviceName: 'example', service, body: { operation_id: 'mutate' }, context: { client: { allowed_operations: [{ service: 'example', operations: ['mutate'] }] } } }), 403);
rejects('admin without explicit operation grant denied', () => prepareReadOnlyServiceTest({ serviceName: 'example', service, body: { operation_id: 'probe' }, context: { client: { role: 'admin' } } }), 403);
rejects('wrong environment denied', () => prepareReadOnlyServiceTest({ serviceName: 'example', service, body: { operation_id: 'probe' }, context: { client: { allowed_operations: [{ service: 'example', operations: ['probe'], environments: ['development'] }] } } }), 403);

console.log(`\n${passed} passed, 0 failed`);
