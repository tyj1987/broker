import { createHash } from 'node:crypto';

import { V2Error } from '../lib/operations-v2.js';
import { BROKER_VERSION } from '../version.js';

const TOOL = 'aliyun.ecs.instances.list@1.0.0';
const OPERATION_ID = 'ecs.instances.list';
const METHOD = 'POST';
const PATH = '/';
const API_ACTION = 'DescribeInstances';
const API_VERSION = '2014-05-26';
const EMPTY_PAYLOAD_HASH = createHash('sha256').update('').digest('hex');
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const REGION_RE = /^[a-z0-9]+(?:-[a-z0-9]+){1,4}$/;
const RESOURCE_RE = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const INSTANCE_ID_RE = /^i-[a-zA-Z0-9]{6,64}$/;
const SAFE_TEXT_RE = /^[^\u0000-\u001f\u007f]{0,256}$/;
const STATUS_RE = /^[A-Za-z][A-Za-z0-9_-]{0,31}$/;
const NEXT_TOKEN_RE = /^[A-Za-z0-9._~-]{1,2048}$/;
const EXECUTION_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const REQUEST_BINDING_RE = /^[A-Za-z0-9_-]{43}$/;
const SIGNED_HEADERS_RE =
  /^ACS3-HMAC-SHA256 Credential=[^,\s]+,SignedHeaders=host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-security-token;x-acs-signature-nonce;x-acs-version,Signature=[0-9a-f]{64}$/;

function fail(code, message, status = 400) {
  throw new V2Error(code, message, status);
}

function pageValue(value, fallback, maximum) {
  const normalized = value === undefined ? fallback : value;
  if (!Number.isSafeInteger(normalized) || normalized < 1 || normalized > maximum) {
    fail('aliyun_invalid_pagination', 'Alibaba Cloud pagination is invalid');
  }
  return normalized;
}

export function validateAliyunEcsInstancesListParameters(parameters) {
  if (!parameters || typeof parameters !== 'object' || Array.isArray(parameters)) {
    fail('aliyun_invalid_request', 'Alibaba Cloud ECS request is invalid');
  }
  const allowed = new Set(['resource_ref', 'region_id', 'next_token', 'max_results']);
  if (Object.keys(parameters).some((key) => !allowed.has(key))) {
    fail('aliyun_invalid_request', 'Alibaba Cloud ECS request contains unsupported parameters');
  }
  if (!RESOURCE_RE.test(parameters.resource_ref || '')) {
    fail('aliyun_invalid_resource', 'Alibaba Cloud ECS resource binding is invalid');
  }
  if (!REGION_RE.test(parameters.region_id || '')) {
    fail('aliyun_invalid_region', 'Alibaba Cloud region is invalid');
  }
  if (parameters.next_token !== undefined && !NEXT_TOKEN_RE.test(parameters.next_token)) {
    fail('aliyun_invalid_next_token', 'Alibaba Cloud continuation token is invalid');
  }
  return {
    resourceRef: parameters.resource_ref,
    regionId: parameters.region_id,
    nextToken: parameters.next_token,
    maxResults: pageValue(parameters.max_results, 20, 100),
  };
}

function parseBody(body) {
  if (body && typeof body === 'object' && !Buffer.isBuffer(body)) return body;
  const text = Buffer.isBuffer(body) ? body.toString('utf8') : String(body || '');
  if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES) {
    fail('aliyun_response_too_large', 'Alibaba Cloud response exceeded the configured limit', 502);
  }
  try {
    return JSON.parse(text);
  } catch {
    fail('aliyun_invalid_response', 'Alibaba Cloud returned an invalid response', 502);
  }
}

function validateSignedHeaders(result, expected, now) {
  if (
    !result ||
    typeof result !== 'object' ||
    result.account_ref !== expected.account_ref ||
    result.environment !== expected.environment ||
    result.resource_ref !== expected.resource_ref ||
    result.region_id !== expected.region_id ||
    result.execution_id !== expected.execution_id ||
    result.request_binding !== expected.request_binding
  ) {
    fail('aliyun_signer_scope_mismatch', 'Alibaba Cloud signing scope does not match', 503);
  }
  const headers = result.headers;
  const date = Date.parse(headers?.['x-acs-date']);
  if (
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
    headers.host !== `ecs.${expected.region_id}.aliyuncs.com` ||
    headers['x-acs-action'] !== API_ACTION ||
    headers['x-acs-version'] !== API_VERSION ||
    headers['x-acs-content-sha256'] !== EMPTY_PAYLOAD_HASH ||
    typeof headers['x-acs-security-token'] !== 'string' ||
    headers['x-acs-security-token'].length < 8 ||
    headers['x-acs-security-token'].length > 4096 ||
    typeof headers['x-acs-signature-nonce'] !== 'string' ||
    !/^[A-Za-z0-9-]{8,128}$/.test(headers['x-acs-signature-nonce']) ||
    !SIGNED_HEADERS_RE.test(headers.Authorization || '') ||
    !Number.isFinite(date) ||
    Math.abs(now - date) > 5 * 60_000
  ) {
    fail('aliyun_signer_response_invalid', 'Alibaba Cloud signer returned invalid headers', 503);
  }
  if (!/^[A-Za-z0-9_-]{43}$/.test(result.credential_binding || '')) {
    fail('aliyun_signer_response_invalid', 'Alibaba Cloud signer returned invalid headers', 503);
  }
  return { headers, credentialBinding: result.credential_binding };
}

function projectResponse(body, expected) {
  const instances = body?.Instances?.Instance;
  if (
    !Array.isArray(instances) ||
    !Number.isSafeInteger(body.TotalCount) ||
    body.TotalCount < instances.length ||
    instances.length > expected.maxResults
  ) {
    fail('aliyun_invalid_response', 'Alibaba Cloud returned invalid pagination data', 502);
  }
  const projected = instances.map((instance) => {
    if (
      !INSTANCE_ID_RE.test(instance?.InstanceId || '') ||
      !SAFE_TEXT_RE.test(instance.InstanceName || '') ||
      !STATUS_RE.test(instance.Status || '') ||
      !REGION_RE.test(instance.RegionId || '') ||
      instance.RegionId !== expected.regionId ||
      !SAFE_TEXT_RE.test(instance.ZoneId || '') ||
      !SAFE_TEXT_RE.test(instance.InstanceType || '')
    ) {
      fail('aliyun_scope_mismatch', 'Alibaba Cloud result escaped the requested region', 502);
    }
    return {
      instance_id: instance.InstanceId,
      instance_name: instance.InstanceName,
      status: instance.Status,
      region_id: instance.RegionId,
      zone_id: instance.ZoneId,
      instance_type: instance.InstanceType,
    };
  });
  const output = { instances: projected, total_count: body.TotalCount };
  if (body.NextToken !== undefined) {
    if (typeof body.NextToken !== 'string' || !NEXT_TOKEN_RE.test(body.NextToken)) {
      fail('aliyun_invalid_response', 'Alibaba Cloud returned an invalid continuation token', 502);
    }
    output.next_token = body.NextToken;
  }
  return output;
}

export function createAliyunEcsInstancesListAdapter({ request, signRequest, now = Date.now } = {}) {
  if (typeof request !== 'function')
    throw new TypeError('Alibaba Cloud adapter requires a pinned request transport');
  if (typeof signRequest !== 'function')
    throw new TypeError('Alibaba Cloud adapter requires an isolated signing capability');
  if (typeof now !== 'function') throw new TypeError('Alibaba Cloud adapter requires a clock');

  return async function aliyunEcsInstancesList(parameters, context = {}) {
    const validated = validateAliyunEcsInstancesListParameters(parameters);
    if (
      context.execution?.tool !== TOOL ||
      context.execution?.target !== validated.resourceRef ||
      context.execution?.environment !== context.environment ||
      !EXECUTION_ID_RE.test(context.execution?.execution_id || '') ||
      !REQUEST_BINDING_RE.test(context.execution?.request_binding || '')
    ) {
      fail(
        'aliyun_execution_binding_mismatch',
        'Execution capability is not bound to this Alibaba Cloud inventory',
        403,
      );
    }
    if (typeof context.accountRef !== 'string' || !context.accountRef) {
      fail('aliyun_account_unavailable', 'Alibaba Cloud account binding is unavailable', 503);
    }
    const query = {
      MaxResults: validated.maxResults,
      RegionId: validated.regionId,
    };
    if (validated.nextToken !== undefined) query.NextToken = validated.nextToken;
    const signingInput = {
      operation_id: OPERATION_ID,
      account_ref: context.accountRef,
      environment: context.environment,
      resource_ref: validated.resourceRef,
      region_id: validated.regionId,
      execution_id: context.execution.execution_id,
      request_binding: context.execution.request_binding,
      method: METHOD,
      path: PATH,
      query,
      signal: context.signal,
    };
    let signed;
    try {
      signed = validateSignedHeaders(await signRequest(signingInput), signingInput, now());
    } catch (error) {
      if (error instanceof V2Error) throw error;
      fail('aliyun_signer_unavailable', 'Alibaba Cloud signer is unavailable', 503);
    }

    if (
      context.providerCredentialBinding !== undefined &&
      context.providerCredentialBinding !== signed.credentialBinding
    ) {
      fail(
        'aliyun_credential_binding_mismatch',
        'Alibaba Cloud credential changed during the bound operation',
        503,
      );
    }
    let response;
    try {
      const outboundHeaders = { ...signed.headers };
      delete outboundHeaders.host;
      response = await request({
        origin: `https://ecs.${validated.regionId}.aliyuncs.com`,
        method: METHOD,
        path: `/?${new URLSearchParams(query)}`,
        headers: {
          ...outboundHeaders,
          Accept: 'application/json',
          'User-Agent': `secret-broker/${BROKER_VERSION}`,
        },
        body: '',
        max_response_bytes: MAX_RESPONSE_BYTES,
        redirect: 'manual',
        signal: context.signal,
      });
    } catch (error) {
      if (error instanceof V2Error) throw error;
      fail('aliyun_unavailable', 'Alibaba Cloud request failed', 502);
    }
    if ([301, 302, 303, 307, 308].includes(response?.status))
      fail('aliyun_redirect_denied', 'Alibaba Cloud redirect was denied', 502);
    if (response?.status === 401)
      fail('aliyun_credential_rejected', 'Alibaba Cloud credential was rejected', 502);
    if (response?.status === 403)
      fail('aliyun_forbidden', 'Alibaba Cloud role lacks ECS inventory access', 403);
    if (response?.status === 429)
      fail('aliyun_rate_limited', 'Alibaba Cloud rate limit was reached', 429);
    if (response?.status !== 200)
      fail('aliyun_upstream_error', 'Alibaba Cloud ECS inventory request failed', 502);
    return projectResponse(parseBody(response.body), validated);
  };
}

export const ALIYUN_ECS_INSTANCES_LIST_CONTRACT = Object.freeze({
  tool: TOOL,
  operation_id: OPERATION_ID,
  endpoint_template: 'https://ecs.{region_id}.aliyuncs.com',
  method: METHOD,
  path: PATH,
  api_action: API_ACTION,
  api_version: API_VERSION,
  required_permission: 'ecs:DescribeInstances',
  maximum_response_bytes: MAX_RESPONSE_BYTES,
  maximum_page_size: 100,
  arbitrary_url: false,
  credential_export: false,
  requires_isolated_signer: true,
});
