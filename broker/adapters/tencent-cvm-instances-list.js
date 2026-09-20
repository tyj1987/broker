import { createHash } from 'node:crypto';

import { V2Error } from '../lib/operations-v2.js';
import { BROKER_VERSION } from '../version.js';

const TOOL = 'tencent.cvm.instances.list@1.0.0';
const ORIGIN = 'https://cvm.tencentcloudapi.com';
const OPERATION_ID = 'cvm.instances.list';
const API_ACTION = 'DescribeInstances';
const API_VERSION = '2017-03-12';
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const REGION_RE = /^[a-z0-9]+(?:-[a-z0-9]+){1,4}$/;
const RESOURCE_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const INSTANCE_ID_RE = /^ins-[a-z0-9]{8,64}$/;
const SAFE_TEXT_RE = /^[^\u0000-\u001f\u007f]{0,256}$/;
const STATE_RE = /^[A-Z][A-Z0-9_]{0,63}$/;
const EXECUTION_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const REQUEST_BINDING_RE = /^[A-Za-z0-9_-]{43}$/;
const AUTHORIZATION_RE =
  /^TC3-HMAC-SHA256 Credential=[^,\s]+\/\d{4}-\d{2}-\d{2}\/cvm\/tc3_request, SignedHeaders=content-type;host, Signature=[0-9a-f]{64}$/;

function fail(code, message, status = 400) {
  throw new V2Error(code, message, status);
}

function boundedInteger(value, fallback, minimum, maximum) {
  const normalized = value === undefined ? fallback : value;
  if (!Number.isSafeInteger(normalized) || normalized < minimum || normalized > maximum) {
    fail('tencent_invalid_pagination', 'Tencent Cloud pagination is invalid');
  }
  return normalized;
}

function validateParameters(parameters) {
  if (!parameters || typeof parameters !== 'object' || Array.isArray(parameters)) {
    fail('tencent_invalid_request', 'Tencent Cloud CVM request is invalid');
  }
  const allowed = new Set(['resource_ref', 'region', 'offset', 'limit']);
  if (Object.keys(parameters).some((key) => !allowed.has(key))) {
    fail('tencent_invalid_request', 'Tencent Cloud CVM request contains unsupported parameters');
  }
  if (!RESOURCE_RE.test(parameters.resource_ref || '')) {
    fail('tencent_invalid_resource', 'Tencent Cloud CVM resource binding is invalid');
  }
  if (!REGION_RE.test(parameters.region || '')) {
    fail('tencent_invalid_region', 'Tencent Cloud region is invalid');
  }
  return {
    resourceRef: parameters.resource_ref,
    region: parameters.region,
    offset: boundedInteger(parameters.offset, 0, 0, 10_000),
    limit: boundedInteger(parameters.limit, 20, 1, 100),
  };
}

function parseBody(body) {
  if (body && typeof body === 'object' && !Buffer.isBuffer(body)) return body;
  const text = Buffer.isBuffer(body) ? body.toString('utf8') : String(body || '');
  if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES) {
    fail('tencent_response_too_large', 'Tencent Cloud response exceeded the configured limit', 502);
  }
  try {
    return JSON.parse(text);
  } catch {
    fail('tencent_invalid_response', 'Tencent Cloud returned an invalid response', 502);
  }
}

function validateSignedHeaders(result, expected, payloadHash, now) {
  if (
    !result ||
    typeof result !== 'object' ||
    result.account_ref !== expected.account_ref ||
    result.environment !== expected.environment ||
    result.resource_ref !== expected.resource_ref ||
    result.region !== expected.region ||
    result.execution_id !== expected.execution_id ||
    result.request_binding !== expected.request_binding ||
    result.payload_sha256 !== payloadHash
  ) {
    fail('tencent_signer_scope_mismatch', 'Tencent Cloud signing scope does not match', 503);
  }
  const headers = result.headers;
  const timestamp = Number(headers?.['x-tc-timestamp']);
  if (
    !headers ||
    typeof headers !== 'object' ||
    Array.isArray(headers) ||
    Object.keys(headers).some(
      (key) =>
        ![
          'Authorization',
          'content-type',
          'host',
          'x-tc-action',
          'x-tc-region',
          'x-tc-timestamp',
          'x-tc-token',
          'x-tc-version',
        ].includes(key),
    ) ||
    headers.host !== 'cvm.tencentcloudapi.com' ||
    headers['content-type'] !== 'application/json; charset=utf-8' ||
    headers['x-tc-action'] !== API_ACTION ||
    headers['x-tc-version'] !== API_VERSION ||
    headers['x-tc-region'] !== expected.region ||
    typeof headers['x-tc-token'] !== 'string' ||
    headers['x-tc-token'].length < 8 ||
    headers['x-tc-token'].length > 4096 ||
    !AUTHORIZATION_RE.test(headers.Authorization || '') ||
    !Number.isSafeInteger(timestamp) ||
    Math.abs(now - timestamp * 1000) > 5 * 60_000
  ) {
    fail('tencent_signer_response_invalid', 'Tencent Cloud signer returned invalid headers', 503);
  }
  return headers;
}

function projectResponse(body, expected) {
  const response = body?.Response;
  if (response?.Error) {
    fail('tencent_upstream_error', 'Tencent Cloud CVM inventory request failed', 502);
  }
  if (
    !Array.isArray(response?.InstanceSet) ||
    !Number.isSafeInteger(response.TotalCount) ||
    response.TotalCount < response.InstanceSet.length ||
    response.InstanceSet.length > expected.limit
  ) {
    fail('tencent_invalid_response', 'Tencent Cloud returned invalid pagination data', 502);
  }
  const instances = response.InstanceSet.map((instance) => {
    const zone = instance?.Placement?.Zone;
    if (
      !INSTANCE_ID_RE.test(instance?.InstanceId || '') ||
      !SAFE_TEXT_RE.test(instance.InstanceName || '') ||
      !STATE_RE.test(instance.InstanceState || '') ||
      !SAFE_TEXT_RE.test(instance.InstanceType || '') ||
      !REGION_RE.test(zone || '') ||
      !zone.startsWith(`${expected.region}-`)
    ) {
      fail('tencent_invalid_response', 'Tencent Cloud returned invalid CVM metadata', 502);
    }
    return {
      instance_id: instance.InstanceId,
      instance_name: instance.InstanceName,
      state: instance.InstanceState,
      instance_type: instance.InstanceType,
      region: expected.region,
      zone,
    };
  });
  return {
    instances,
    total_count: response.TotalCount,
    offset: expected.offset,
    limit: expected.limit,
  };
}

export function createTencentCvmInstancesListAdapter({
  request,
  signRequest,
  now = Date.now,
} = {}) {
  if (typeof request !== 'function')
    throw new TypeError('Tencent Cloud adapter requires a pinned request transport');
  if (typeof signRequest !== 'function')
    throw new TypeError('Tencent Cloud adapter requires an isolated signing capability');
  if (typeof now !== 'function') throw new TypeError('Tencent Cloud adapter requires a clock');

  return async function tencentCvmInstancesList(parameters, context = {}) {
    const validated = validateParameters(parameters);
    if (
      context.execution?.tool !== TOOL ||
      context.execution?.target !== validated.resourceRef ||
      context.execution?.environment !== context.environment ||
      !EXECUTION_ID_RE.test(context.execution?.execution_id || '') ||
      !REQUEST_BINDING_RE.test(context.execution?.request_binding || '')
    ) {
      fail(
        'tencent_execution_binding_mismatch',
        'Execution capability is not bound to this Tencent Cloud inventory',
        403,
      );
    }
    if (typeof context.accountRef !== 'string' || !context.accountRef) {
      fail('tencent_account_unavailable', 'Tencent Cloud account binding is unavailable', 503);
    }
    const payload = JSON.stringify({ Limit: validated.limit, Offset: validated.offset });
    const payloadHash = createHash('sha256').update(payload).digest('hex');
    const signingInput = {
      operation_id: OPERATION_ID,
      account_ref: context.accountRef,
      environment: context.environment,
      resource_ref: validated.resourceRef,
      region: validated.region,
      execution_id: context.execution.execution_id,
      request_binding: context.execution.request_binding,
      method: 'POST',
      path: '/',
      payload,
      payload_sha256: payloadHash,
      signal: context.signal,
    };
    let signed;
    try {
      signed = validateSignedHeaders(
        await signRequest(signingInput),
        signingInput,
        payloadHash,
        now(),
      );
    } catch (error) {
      if (error instanceof V2Error) throw error;
      fail('tencent_signer_unavailable', 'Tencent Cloud signer is unavailable', 503);
    }
    let response;
    try {
      const outboundHeaders = { ...signed };
      delete outboundHeaders.host;
      response = await request({
        origin: ORIGIN,
        method: 'POST',
        path: '/',
        headers: {
          ...outboundHeaders,
          Accept: 'application/json',
          'User-Agent': `secret-broker/${BROKER_VERSION}`,
        },
        body: payload,
        max_response_bytes: MAX_RESPONSE_BYTES,
        redirect: 'manual',
        signal: context.signal,
      });
    } catch (error) {
      if (error instanceof V2Error) throw error;
      fail('tencent_unavailable', 'Tencent Cloud request failed', 502);
    }
    if ([301, 302, 303, 307, 308].includes(response?.status))
      fail('tencent_redirect_denied', 'Tencent Cloud redirect was denied', 502);
    if (response?.status === 401)
      fail('tencent_credential_rejected', 'Tencent Cloud credential was rejected', 502);
    if (response?.status === 403)
      fail('tencent_forbidden', 'Tencent Cloud role lacks CVM inventory access', 403);
    if (response?.status === 429)
      fail('tencent_rate_limited', 'Tencent Cloud rate limit was reached', 429);
    if (response?.status !== 200)
      fail('tencent_upstream_error', 'Tencent Cloud CVM inventory request failed', 502);
    return projectResponse(parseBody(response.body), validated);
  };
}

export const TENCENT_CVM_INSTANCES_LIST_CONTRACT = Object.freeze({
  tool: TOOL,
  operation_id: OPERATION_ID,
  origin: ORIGIN,
  method: 'POST',
  path: '/',
  api_action: API_ACTION,
  api_version: API_VERSION,
  required_permission: 'cvm:DescribeInstances',
  maximum_response_bytes: MAX_RESPONSE_BYTES,
  maximum_page_size: 100,
  releases_network_addresses: false,
  arbitrary_url: false,
  credential_export: false,
  requires_isolated_signer: true,
});
