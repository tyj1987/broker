import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const manifest = JSON.parse(readFileSync(new URL('../manifest.json', import.meta.url)));
assert.equal(manifest.manifest_version, 3);
assert.deepEqual(manifest.permissions.sort(), ['activeTab', 'nativeMessaging', 'scripting']);
assert.equal(manifest.host_permissions.some((value) => value.includes('<all_urls>') || value.includes('*://*')), false);
assert.equal(manifest.permissions.includes('cookies'), false);
assert.match(manifest.key, /^[A-Za-z0-9+/=]+$/);
const host = JSON.parse(readFileSync(new URL('../native-host/com.secretbroker.browser.json', import.meta.url)));
assert.deepEqual(host.allowed_origins, ['chrome-extension://fcllkkhicfhknnbapgheklkaccjdbeln/']);
const worker = readFileSync(new URL('../service-worker.js', import.meta.url), 'utf8');
assert.match(worker, /account_ref/);
assert.match(worker, /complete-approved-otp/);
assert.doesNotMatch(worker, /cookies|debugger|clipboard/);
console.log('browser extension manifest: least-privilege checks passed');
