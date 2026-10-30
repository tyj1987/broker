// broker-test/test-api-key-route-policy.js — delegated API-key HTTP surface

import { isApiKeyRouteAllowed } from '../broker/lib/api-key-route-policy.js';

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

console.log('[delegated API-key route policy]');
ok('identity remains available', isApiKeyRouteAllowed('GET', '/api/v1/identity'));
ok('services remains available', isApiKeyRouteAllowed('GET', '/api/v1/services'));
ok('secrets remains available', isApiKeyRouteAllowed('GET', '/api/v1/secrets'));
ok('secret resolve remains available', isApiKeyRouteAllowed('POST', '/api/v1/secrets/resolve'));
ok('proxy remains available', isApiKeyRouteAllowed('POST', '/api/v1/proxy/github'));
ok(
  'health status remains available (filtered elsewhere)',
  isApiKeyRouteAllowed('GET', '/api/v1/healthcheck/status'),
);
ok('self audit allowed', isApiKeyRouteAllowed('GET', '/api/v1/me/audit'));
ok('self audit wrong method denied', !isApiKeyRouteAllowed('POST', '/api/v1/me/audit'));
ok('profile denied', !isApiKeyRouteAllowed('GET', '/api/v1/me'));
ok('password change denied', !isApiKeyRouteAllowed('POST', '/api/v1/me/change-password'));
ok('cert rotation denied', !isApiKeyRouteAllowed('POST', '/api/v1/me/rotate-cert'));
ok('TOTP management denied', !isApiKeyRouteAllowed('POST', '/api/v1/me/totp/disable'));
ok('key list denied', !isApiKeyRouteAllowed('GET', '/api/v1/api-keys'));
ok('sibling key read denied', !isApiKeyRouteAllowed('GET', '/api/v1/api-keys/0123456789abcdef'));
ok('key revoke denied', !isApiKeyRouteAllowed('DELETE', '/api/v1/api-keys/0123456789abcdef'));
ok('master child issuance allowed', isApiKeyRouteAllowed('POST', '/api/v1/api-keys/issue-child'));
ok(
  'master child issuance wrong method denied',
  !isApiKeyRouteAllowed('GET', '/api/v1/api-keys/issue-child'),
);

console.log(`\n=== Total: ${pass} passed, ${fail} failed ===`);
process.exit(fail > 0 ? 1 : 0);
