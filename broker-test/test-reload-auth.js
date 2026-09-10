import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { isReloadTokenValid } from '../broker/lib/reload-auth.js';

const expected = 'reload-control-token-01';
assert.equal(isReloadTokenValid({ 'x-reload-token': expected }, expected), true);
assert.equal(isReloadTokenValid({ 'x-reload-token': 'reload-control-token-02' }, expected), false);
assert.equal(isReloadTokenValid({}, expected), false);
assert.equal(isReloadTokenValid({ 'x-reload-token': [expected] }, expected), false);
assert.equal(isReloadTokenValid({ 'x-reload-token': '' }, expected), false);
assert.equal(isReloadTokenValid({ 'x-reload-token': expected }, ''), false);
assert.equal(isReloadTokenValid({ 'x-reload-token': '令牌' }, '令牌'), true);
assert.equal(isReloadTokenValid({ 'x-reload-token': '令牌' }, '令牌一'), false);

const server = readFileSync(resolve(import.meta.dirname, '../broker/server.js'), 'utf8');
const handler = server.slice(server.indexOf("if (m === 'POST' && p === '/api/v1/reload')"), server.indexOf('// ----- POST /api/v1/rotate/:name'));
assert.ok(handler.length > 0, 'reload handler is present');
assert.ok(!handler.includes('searchParams'), 'reload token is never accepted from the URL');
assert.ok(!handler.includes('err.message'), 'reload failure details are not returned or audited');
assert.match(handler, /error: 'reload_failed'/);
assert.match(handler, /jsonError\(res, 500, 'Reload failed'\)/);

console.log('reload authentication: header-only constant-time verification and safe failures passed');
