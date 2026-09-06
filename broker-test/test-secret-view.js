import { renderSecretFields } from '../broker/lib/secret-view.js';

let passed = 0, failed = 0;
function ok(name, value) { if (value) { passed++; console.log('  PASS ', name); } else { failed++; console.error('  FAIL ', name); } }

const source = { token: 'canary-secret', user: 'alice' };
const strict = renderSecretFields(source, 'strict');
ok('strict redacts every field', strict.token === '[REDACTED]' && strict.user === '[REDACTED]');
ok('strict output has no canary', !JSON.stringify(strict).includes('canary-secret'));
const controlled = renderSecretFields(source, 'controlled');
ok('controlled compatibility view preserved', controlled.token === 'canary-secret');
controlled.token = 'changed';
ok('returned object does not mutate source', source.token === 'canary-secret');

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
