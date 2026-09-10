import assert from 'node:assert/strict';
import { requireTrustedBrowserMutation } from '../broker/lib/browser-request.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const expectCode = (code) => (error) => error instanceof V2Error && error.code === code;
const identity = { via: 'session', authFactors: ['webauthn'] };
const trusted = 'https://broker.example.com';

assert.doesNotThrow(() => requireTrustedBrowserMutation({
  headers: { origin: trusted, 'sec-fetch-site': 'same-origin' },
}, identity, trusted));
assert.doesNotThrow(() => requireTrustedBrowserMutation({ headers: { origin: trusted } }, identity, trusted));
assert.doesNotThrow(() => requireTrustedBrowserMutation({ headers: { origin: trusted } }, identity, `${trusted}/`));
assert.throws(() => requireTrustedBrowserMutation({ headers: { origin: trusted } }, {
  via: 'api_key', authFactors: ['webauthn'],
}, trusted), expectCode('step_up_required'));
assert.throws(() => requireTrustedBrowserMutation({ headers: { origin: trusted } }, {
  via: 'session', authFactors: [],
}, trusted), expectCode('step_up_required'));
assert.throws(() => requireTrustedBrowserMutation({ headers: {} }, identity, trusted), expectCode('origin_denied'));
assert.throws(() => requireTrustedBrowserMutation({
  headers: { origin: 'https://attacker.example', 'sec-fetch-site': 'cross-site' },
}, identity, trusted), expectCode('origin_denied'));
assert.throws(() => requireTrustedBrowserMutation({
  headers: { origin: trusted, 'sec-fetch-site': 'cross-site' },
}, identity, trusted), expectCode('origin_denied'));
assert.throws(() => requireTrustedBrowserMutation({ headers: { origin: trusted } }, identity, 'http://broker.example.com'), expectCode('browser_origin_unavailable'));
assert.throws(() => requireTrustedBrowserMutation({ headers: { origin: trusted } }, identity, 'not-a-url'), expectCode('browser_origin_unavailable'));
assert.throws(() => requireTrustedBrowserMutation({ headers: { origin: trusted } }, identity, `${trusted}/admin`), expectCode('browser_origin_unavailable'));

console.log('browser mutation boundary: WebAuthn session and exact same-origin checks passed');
