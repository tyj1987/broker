import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
  ALIYUN_CALLER_AUTHORITY_CONTRACT,
  createAliyunCallerAuthorityProvider,
} from '../broker/adapters/aliyun-caller-authority.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const NOW = Date.parse('2026-09-13T00:00:00Z');
const CREDENTIAL_BINDING = 'b'.repeat(43);
const EXECUTION_ID = '12345678-1234-4123-8123-123456789abc';
const REQUEST_BINDING = 'a'.repeat(43);
const input = {
  account_ref: 'aliyun-isolated',
  environment: 'staging',
  tool: 'aliyun.ecs.instances.list@1.0.0',
  target: 'ecs-inventory-isolated',
  execution_environment: 'staging',
  resource_ref: 'ecs-inventory-isolated',
  region_id: 'cn-hangzhou',
  execution_id: EXECUTION_ID,
  request_binding: REQUEST_BINDING,
  signal: new AbortController().signal,
};
const body = {
  IdentityType: 'AssumedRoleUser',
  AccountId: '1234567890123456',
  PrincipalId: '1234567890123456:broker-contract',
  Arn: 'acs:ram::1234567890123456:role/broker-contract',
  RequestId: 'must-not-project',
};
const signed = (request) => ({
  account_ref: request.account_ref,
  environment: request.environment,
  resource_ref: request.resource_ref,
  region_id: request.region_id,
  execution_id: request.execution_id,
  request_binding: request.request_binding,
  credential_binding: CREDENTIAL_BINDING,
  headers: {
    Authorization: `ACS3-HMAC-SHA256 Credential=STS.TEST,SignedHeaders=host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-security-token;x-acs-signature-nonce;x-acs-version,Signature=${'a'.repeat(64)}`,
    host: 'sts.aliyuncs.com',
    'x-acs-action': 'GetCallerIdentity',
    'x-acs-content-sha256': createHash('sha256').update('').digest('hex'),
    'x-acs-date': '2026-09-13T00:00:00Z',
    'x-acs-security-token': 'temporary-security-token',
    'x-acs-signature-nonce': 'nonce-12345678',
    'x-acs-version': '2015-04-01',
  },
});
const sha = (value) => createHash('sha256').update(value).digest('hex');
const calls = [];
const provider = createAliyunCallerAuthorityProvider({
  now: () => NOW,
  signRequest: async (request) => {
    calls.push({ sign: request });
    return signed(request);
  },
  request: async (request) => {
    calls.push({ request });
    return { status: 200, body };
  },
});
const evidence = await provider(input);
assert.deepEqual(evidence.authority, {
  identity_type: 'AssumedRoleUser',
  account_id_sha256: sha(body.AccountId),
  principal_id_sha256: sha(body.PrincipalId),
  arn_sha256: sha(body.Arn),
});
assert.equal(evidence.credential_binding, CREDENTIAL_BINDING);
assert.equal(JSON.stringify(evidence.authority).includes(body.AccountId), false);
assert.equal(JSON.stringify(evidence.authority).includes(body.Arn), false);
assert.equal(calls[0].sign.operation_id, 'sts.caller-identity.read');
assert.equal(calls[0].sign.execution_id, EXECUTION_ID);
assert.equal(calls[0].sign.request_binding, REQUEST_BINDING);
assert.deepEqual(calls[0].sign.query, {});
assert.equal(calls[1].request.origin, 'https://sts.aliyuncs.com');
assert.equal(calls[1].request.path, '/');
assert.equal(calls[1].request.redirect, 'manual');
assert.equal(Object.hasOwn(calls[1].request.headers, 'host'), false);

const expectCode = (code) => (error) => error instanceof V2Error && error.code === code;
const withResponse = (value, sign = signed) =>
  createAliyunCallerAuthorityProvider({
    now: () => NOW,
    signRequest: async (request) => sign(request),
    request: async () => value,
  });
for (const [value, code] of [
  [{ status: 307, body: {} }, 'aliyun_authority_redirect_denied'],
  [{ status: 401, body: {} }, 'aliyun_authority_credential_rejected'],
  [{ status: 403, body: {} }, 'aliyun_authority_forbidden'],
  [{ status: 429, body: {} }, 'aliyun_authority_rate_limited'],
  [{ status: 500, body: { AccessKeySecret: 'canary' } }, 'aliyun_authority_upstream_error'],
  [{ status: 200, body: Buffer.from('{') }, 'aliyun_authority_invalid_response'],
  [{ status: 200, body: { ...body, IdentityType: 'Root' } }, 'aliyun_authority_invalid_response'],
  [{ status: 200, body: Buffer.alloc(256 * 1024 + 1) }, 'aliyun_authority_response_too_large'],
])
  await assert.rejects(withResponse(value)(input), expectCode(code));
await assert.rejects(
  withResponse({ status: 200, body }, (request) => ({ ...signed(request), account_ref: 'other' }))(
    input,
  ),
  expectCode('aliyun_authority_signer_response_invalid'),
);
await assert.rejects(
  provider({ ...input, target: 'other' }),
  expectCode('aliyun_authority_execution_binding_mismatch'),
);
await assert.rejects(
  provider({ ...input, execution_id: 'wrong' }),
  expectCode('aliyun_authority_execution_binding_mismatch'),
);
await assert.rejects(
  provider({ ...input, request_binding: 'wrong' }),
  expectCode('aliyun_authority_execution_binding_mismatch'),
);
await assert.rejects(
  createAliyunCallerAuthorityProvider({
    request: async () => ({ status: 200, body }),
    signRequest: async () => {
      throw new Error('must-not-leak-signer-detail');
    },
  })(input),
  expectCode('aliyun_authority_signer_unavailable'),
);
await assert.rejects(
  createAliyunCallerAuthorityProvider({
    now: () => NOW,
    signRequest: async (request) => signed(request),
    request: async () => {
      throw new Error('must-not-leak-transport-detail');
    },
  })(input),
  expectCode('aliyun_authority_unavailable'),
);
assert.throws(() => createAliyunCallerAuthorityProvider(), TypeError);
assert.throws(() => createAliyunCallerAuthorityProvider({ request: async () => ({}) }), TypeError);
assert.throws(
  () =>
    createAliyunCallerAuthorityProvider({
      request: async () => ({}),
      signRequest: async () => ({}),
      now: null,
    }),
  TypeError,
);
assert.equal(ALIYUN_CALLER_AUTHORITY_CONTRACT.output_contains_identifiers, false);

console.log(
  'aliyun authority: fixed STS probe, hashed projection and fail-closed responses passed',
);
