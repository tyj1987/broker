import { securityProfile, permits, resolveOperation, normalizeOperations, tlsAuthorizationPolicy } from '../broker/lib/security-profile.js';

let passed = 0;
function ok(name, value) { if (!value) throw new Error(`FAIL: ${name}`); passed++; console.log(`  PASS  ${name}`); }
function rejects(name, fn) { let hit = false; try { fn(); } catch { hit = true; } ok(name, hit); }

ok('strict is the default', securityProfile({}) === 'strict');
ok('invalid profile fails to strict', securityProfile({ security_profile: 'unsafe' }) === 'strict');
ok('strict permits typed operations', permits({}, 'typed_operations'));
ok('strict blocks API keys', !permits({}, 'api_key'));
ok('strict blocks plaintext resolution', !permits({}, 'secret_resolve'));
ok('strict blocks free-form proxy', !permits({}, 'legacy_proxy'));
ok('strict TLS rejects unauthorized peers', tlsAuthorizationPolicy({}).rejectUnauthorized === true);
ok('strict TLS requires TLS 1.3 client certificates', tlsAuthorizationPolicy({}).requestCert === true && tlsAuthorizationPolicy({}).minVersion === 'TLSv1.3');
ok('controlled TLS rejects unauthorized peers', tlsAuthorizationPolicy({ security_profile: 'controlled' }).rejectUnauthorized === true);
ok('compatibility TLS leaves application-layer auth available', tlsAuthorizationPolicy({ security_profile: 'compatibility' }).rejectUnauthorized === false);
ok('controlled permits API keys', permits({ security_profile: 'controlled' }, 'api_key'));
ok('controlled still blocks plaintext', !permits({ security_profile: 'controlled' }, 'secret_resolve'));
ok('compatibility permits plaintext', permits({ security_profile: 'compatibility' }, 'secret_resolve'));

const service = { operations: { list: { method: 'GET', path: '/items', allowed_parameters: ['page'], required_parameters: ['page'] } } };
const operation = resolveOperation(service, 'list', { page: 2 });
ok('typed operation resolves fixed method and path', operation.method === 'GET' && operation.path === '/items');
ok('typed operation accepts allowlisted parameter', operation.query.page === 2);
rejects('unknown operation denied', () => resolveOperation(service, 'delete_all', {}));
rejects('unknown parameter denied', () => resolveOperation(service, 'list', { page: 1, url: 'https://evil.example' }));
rejects('required parameter enforced', () => resolveOperation(service, 'list', {}));
rejects('nested parameter value denied', () => resolveOperation(service, 'list', { page: { url: 'https://evil.example' } }));
rejects('array parameters denied', () => resolveOperation(service, 'list', []));
rejects('null parameters denied', () => resolveOperation(service, 'list', null));
rejects('infinite numeric parameter denied', () => resolveOperation(service, 'list', { page: Infinity }));
rejects('oversize string parameter denied', () => resolveOperation(service, 'list', { page: 'x'.repeat(2049) }));
rejects('runtime unsupported method denied', () => resolveOperation({ operations: { bad: { method: 'TRACE', path: '/' } } }, 'bad', {}));
rejects('runtime unsafe path denied', () => resolveOperation({ operations: { bad: { path: '//evil.example' } } }, 'bad', {}));
rejects('runtime unsafe body limit denied', () => resolveOperation({ operations: { bad: { path: '/', max_body_bytes: -1 } } }, 'bad', {}));

const normalized = normalizeOperations({
  list: { method: 'get', path: '/items', allowed_parameters: ['page'], required_parameters: ['page'] },
});
ok('operation catalog normalized', normalized.list.method === 'GET' && normalized.list.path === '/items');
ok('unknown operation fields dropped', normalized.list.upstream === undefined && normalized.list.headers === undefined);
rejects('absolute operation URL denied', () => normalizeOperations({ list: { path: 'https://evil.example/' } }));
rejects('network-path operation URL denied', () => normalizeOperations({ list: { path: '//evil.example/' } }));
rejects('query embedded in operation path denied', () => normalizeOperations({ list: { path: '/items?next=evil' } }));
rejects('unsupported method denied', () => normalizeOperations({ list: { method: 'CONNECT', path: '/' } }));
rejects('required parameter must be allowed', () => normalizeOperations({ list: { path: '/', required_parameters: ['id'] } }));
rejects('oversize operation body policy denied', () => normalizeOperations({ list: { path: '/', max_body_bytes: 2 * 1024 * 1024 } }));
rejects('resource parameter must be allowlisted', () => normalizeOperations({ list: { path: '/', resource_parameter: 'repo' } }));
rejects('operations array denied', () => normalizeOperations([]));
rejects('empty operations denied', () => normalizeOperations({}));
rejects('invalid operation id denied', () => normalizeOperations({ 'Bad Op': { path: '/' } }));
rejects('non-object operation denied', () => normalizeOperations({ list: 'GET /' }));
rejects('invalid allowed parameter list denied', () => normalizeOperations({ list: { path: '/', allowed_parameters: 'id' } }));
rejects('invalid parameter name denied', () => normalizeOperations({ list: { path: '/', allowed_parameters: ['bad name'] } }));
rejects('backslash path denied', () => normalizeOperations({ list: { path: '/safe\\evil' } }));
rejects('fragment path denied', () => normalizeOperations({ list: { path: '/safe#evil' } }));
rejects('invalid environment denied', () => normalizeOperations({ list: { path: '/', environment: 'PROD!' } }));
rejects('empty resource denied', () => normalizeOperations({ list: { path: '/', resource: '' } }));
const resourceOp = normalizeOperations({ get: { path: '/repos', allowed_parameters: ['repo'], resource_parameter: 'repo', environment: 'production' } });
const resourceResolved = resolveOperation({ operations: resourceOp }, 'get', { repo: 'org/repo' });
ok('resource and environment resolve into policy attributes', resourceResolved.resource === 'org/repo' && resourceResolved.environment === 'production');

console.log(`\n${passed} passed, 0 failed`);
