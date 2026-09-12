import { createHash } from 'node:crypto';

import { V2Error } from '../lib/operations-v2.js';
import { BROKER_VERSION } from '../version.js';

const OPERATION_ID = 'sts.caller-identity.read';
const ORIGIN = 'https://sts.aliyuncs.com';
const ACTION = 'GetCallerIdentity';
const VERSION = '2015-04-01';
const EMPTY_PAYLOAD_HASH = createHash('sha256').update('').digest('hex');
const MAX_RESPONSE_BYTES = 256 * 1024;
const SAFE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,511}$/;
const EXECUTION_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const REQUEST_BINDING_RE = /^[A-Za-z0-9_-]{43}$/;
const ARN_RE =
  /^acs:ram::[0-9]{6,32}:(?:root|user\/[A-Za-z0-9+=,.@_/-]+|role\/[A-Za-z0-9+=,.@_/-]+)$/;
const SIGNED_HEADERS_RE =
  /^ACS3-HMAC-SHA256 Credential=[^,\s]+,SignedHeaders=host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-security-token;x-acs-signature-nonce;x-acs-version,Signature=[0-9a-f]{64}$/;

function fail(code, message, status = 400) {
  throw new V2Error(code, message, status);
}

function digest(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function parseBody(body) {
  if (body && typeof body === 'object' && !Buffer.isBuffer(body)) return body;
  const text = Buffer.isBuffer(body) ? body.toString('utf8') : String(body || '');
  if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES)
    fail(
      'aliyun_authority_response_too_large',
      'Alibaba Cloud authority response exceeded the limit',
      502,
    );
  try {
    return JSON.parse(text);
  } catch {
    fail(
      'aliyun_authority_invalid_response',
      'Alibaba Cloud returned an invalid authority response',
      502,
    );
  }
}

function validateHeaders(result, expected, now) {
  const headers = result?.headers;
  const date = Date.parse(headers?.['x-acs-date']);
  if (
    result?.account_ref !== expected.account_ref ||
    result?.environment !== expected.environment ||
    result?.resource_ref !== expected.resource_ref ||
    result?.region_id !== expected.region_id ||
    result?.execution_id !== expected.execution_id ||
    result?.request_binding !== expected.request_binding ||
    !headers ||
    typeof headers !== 'object' ||
    Array.isArray(headers) ||
    Object.keys(headers).some(
      (key) =>
        ![
          'Authorization',
          'host',
          'x-acs-action',
          'x-acs-content-sha256',
          'x-acs-date',
          'x-acs-security-token',
          'x-acs-signature-nonce',
          'x-acs-version',
        ].includes(key),
    ) ||
    headers.host !== 'sts.aliyuncs.com' ||
    headers['x-acs-action'] !== ACTION ||
    headers['x-acs-version'] !== VERSION ||
    headers['x-acs-content-sha256'] !== EMPTY_PAYLOAD_HASH ||
    typeof headers['x-acs-security-token'] !== 'string' ||
    headers['x-acs-security-token'].length < 8 ||
    headers['x-acs-security-token'].length > 4096 ||
    !/^[A-Za-z0-9-]{8,128}$/.test(headers['x-acs-signature-nonce'] || '') ||
    !SIGNED_HEADERS_RE.test(headers.Authorization || '') ||
    !Number.isFinite(date) ||
    Math.abs(now - date) > 5 * 60_000
  )
    fail(
      'aliyun_authority_signer_response_invalid',
      'Alibaba Cloud signer returned invalid authority headers',
      503,
    );
  if (!/^[A-Za-z0-9_-]{43}$/.test(result.credential_binding || ''))
    fail(
      'aliyun_authority_signer_response_invalid',
      'Alibaba Cloud signer returned invalid authority headers',
      503,
    );
  return { headers, credentialBinding: result.credential_binding };
}

function projectAuthority(body) {
  if (
    !['Account', 'RAMUser', 'AssumedRoleUser'].includes(body?.IdentityType) ||
    !/^[0-9]{6,32}$/.test(body?.AccountId || '') ||
    !SAFE_ID_RE.test(body?.PrincipalId || '') ||
    !ARN_RE.test(body?.Arn || '')
  )
    fail(
      'aliyun_authority_invalid_response',
      'Alibaba Cloud returned an invalid authority projection',
      502,
    );
  return Object.freeze({
    identity_type: body.IdentityType,
    account_id_sha256: digest(body.AccountId),
    principal_id_sha256: digest(body.PrincipalId),
    arn_sha256: digest(body.Arn),
  });
}

export function createAliyunCallerAuthorityProvider({ request, signRequest, now = Date.now } = {}) {
  if (typeof request !== 'function')
    throw new TypeError('Alibaba Cloud authority provider requires transport');
  if (typeof signRequest !== 'function')
    throw new TypeError('Alibaba Cloud authority provider requires signer');
  if (typeof now !== 'function')
    throw new TypeError('Alibaba Cloud authority provider requires clock');
  return async function readCallerAuthority(input) {
    if (
      input?.tool !== 'aliyun.ecs.instances.list@1.0.0' ||
      input?.target !== input?.resource_ref ||
      input?.execution_environment !== input?.environment ||
      !EXECUTION_ID_RE.test(input?.execution_id || '') ||
      !REQUEST_BINDING_RE.test(input?.request_binding || '')
    )
      fail(
        'aliyun_authority_execution_binding_mismatch',
        'Alibaba Cloud authority execution binding does not match',
        403,
      );
    const signingInput = {
      operation_id: OPERATION_ID,
      account_ref: input.account_ref,
      environment: input.environment,
      resource_ref: input.resource_ref,
      region_id: input.region_id,
      execution_id: input.execution_id,
      request_binding: input.request_binding,
      method: 'POST',
      path: '/',
      query: {},
      signal: input.signal,
    };
    let signed;
    try {
      signed = validateHeaders(await signRequest(signingInput), signingInput, now());
    } catch (error) {
      if (error instanceof V2Error) throw error;
      fail(
        'aliyun_authority_signer_unavailable',
        'Alibaba Cloud authority signer is unavailable',
        503,
      );
    }
    const outboundHeaders = { ...signed.headers };
    delete outboundHeaders.host;
    let response;
    try {
      response = await request({
        origin: ORIGIN,
        method: 'POST',
        path: '/',
        headers: {
          ...outboundHeaders,
          Accept: 'application/json',
          'User-Agent': `secret-broker/${BROKER_VERSION}`,
        },
        body: '',
        max_response_bytes: MAX_RESPONSE_BYTES,
        redirect: 'manual',
        signal: input.signal,
      });
    } catch (error) {
      if (error instanceof V2Error) throw error;
      fail('aliyun_authority_unavailable', 'Alibaba Cloud authority request failed', 502);
    }
    if ([301, 302, 303, 307, 308].includes(response?.status))
      fail('aliyun_authority_redirect_denied', 'Alibaba Cloud authority redirect was denied', 502);
    if (response?.status === 401)
      fail('aliyun_authority_credential_rejected', 'Alibaba Cloud credential was rejected', 502);
    if (response?.status === 403)
      fail('aliyun_authority_forbidden', 'Alibaba Cloud caller identity was denied', 403);
    if (response?.status === 429)
      fail('aliyun_authority_rate_limited', 'Alibaba Cloud authority rate limit was reached', 429);
    if (response?.status !== 200)
      fail('aliyun_authority_upstream_error', 'Alibaba Cloud authority request failed', 502);
    return Object.freeze({
      authority: projectAuthority(parseBody(response.body)),
      credential_binding: signed.credentialBinding,
    });
  };
}

export const ALIYUN_CALLER_AUTHORITY_CONTRACT = Object.freeze({
  operation_id: OPERATION_ID,
  origin: ORIGIN,
  action: ACTION,
  api_version: VERSION,
  method: 'POST',
  maximum_response_bytes: MAX_RESPONSE_BYTES,
  output_contains_identifiers: false,
});
