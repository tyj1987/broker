import { V2Error } from '../lib/operations-v2.js';
import { BROKER_VERSION } from '../version.js';

const TOOL = 'cloudflare.zones.list@1.0.0';
const ORIGIN = 'https://api.cloudflare.com';
const PATH = '/client/v4/zones';
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const ACCOUNT_ID_RE = /^[a-f0-9]{32}$/;
const EXECUTION_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const REQUEST_BINDING_RE = /^[A-Za-z0-9_-]{43}$/;
const ZONE_NAME_RE =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const ZONE_STATUSES = new Set(['initializing', 'pending', 'active', 'moved']);
const ZONE_TYPES = new Set(['full', 'partial', 'secondary', 'internal']);

function fail(code, message, status = 400) {
  throw new V2Error(code, message, status);
}

function positiveInteger(value, fallback, maximum = Number.MAX_SAFE_INTEGER) {
  const result = value === undefined ? fallback : value;
  if (!Number.isSafeInteger(result) || result < 1 || result > maximum) {
    fail('cloudflare_invalid_pagination', 'Cloudflare pagination is invalid');
  }
  return result;
}

function parseBody(body) {
  if (body && typeof body === 'object' && !Buffer.isBuffer(body)) return body;
  const text = Buffer.isBuffer(body) ? body.toString('utf8') : String(body || '');
  if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES) {
    fail('cloudflare_response_too_large', 'Cloudflare response exceeded the configured limit', 502);
  }
  try {
    return JSON.parse(text);
  } catch {
    fail('cloudflare_invalid_response', 'Cloudflare returned an invalid response', 502);
  }
}

function validateCredential(lease, accountId) {
  if (
    !lease ||
    typeof lease !== 'object' ||
    typeof lease.token !== 'string' ||
    lease.token.length < 1 ||
    lease.token.length > 4096
  ) {
    fail('cloudflare_credential_unavailable', 'Cloudflare credential is unavailable', 503);
  }
  if (typeof lease.account_id !== 'string' || lease.account_id.toLowerCase() !== accountId) {
    fail(
      'cloudflare_credential_scope_mismatch',
      'Cloudflare credential is not account scoped',
      403,
    );
  }
  return lease.token;
}

function projectResponse(body, accountId, expectedPage, expectedPerPage) {
  if (body?.success !== true || !Array.isArray(body.result) || !body.result_info) {
    fail('cloudflare_invalid_response', 'Cloudflare returned an invalid zones response', 502);
  }
  const zones = body.result.map((zone) => {
    if (
      !ACCOUNT_ID_RE.test(zone?.id || '') ||
      zone.account?.id?.toLowerCase() !== accountId ||
      !ZONE_NAME_RE.test(zone.name || '') ||
      !ZONE_STATUSES.has(zone.status) ||
      !ZONE_TYPES.has(zone.type) ||
      typeof zone.paused !== 'boolean'
    ) {
      fail(
        'cloudflare_scope_mismatch',
        'Cloudflare zone result escaped the requested account',
        502,
      );
    }
    return {
      id: zone.id,
      name: zone.name,
      status: zone.status,
      type: zone.type,
      paused: zone.paused,
    };
  });
  const info = body.result_info;
  for (const field of ['count', 'total_count', 'total_pages']) {
    if (!Number.isSafeInteger(info[field]) || info[field] < 0) {
      fail('cloudflare_invalid_response', 'Cloudflare returned invalid pagination metadata', 502);
    }
  }
  if (
    info.page !== expectedPage ||
    info.per_page !== expectedPerPage ||
    info.count !== zones.length ||
    info.total_count < info.count ||
    zones.length > expectedPerPage
  ) {
    fail(
      'cloudflare_invalid_response',
      'Cloudflare returned inconsistent pagination metadata',
      502,
    );
  }
  return {
    zones,
    result_info: {
      page: info.page,
      per_page: info.per_page,
      count: info.count,
      total_count: info.total_count,
      total_pages: info.total_pages,
    },
  };
}

export function createCloudflareZonesListAdapter({ request, tokenProvider } = {}) {
  if (typeof request !== 'function')
    throw new TypeError('Cloudflare adapter requires a pinned request transport');
  if (typeof tokenProvider !== 'function')
    throw new TypeError('Cloudflare adapter requires a scoped token provider');

  return async function cloudflareZonesList(parameters, context = {}) {
    const accountId =
      typeof parameters?.resource_ref === 'string' ? parameters.resource_ref.toLowerCase() : '';
    if (!ACCOUNT_ID_RE.test(accountId || ''))
      fail('cloudflare_invalid_account', 'Cloudflare account identity is invalid');
    const name = parameters?.name;
    if (name !== undefined && (typeof name !== 'string' || !ZONE_NAME_RE.test(name))) {
      fail('cloudflare_invalid_zone_name', 'Cloudflare zone name is invalid');
    }
    const page = positiveInteger(parameters?.page, 1);
    const perPage = positiveInteger(parameters?.per_page, 20, 50);
    if (perPage < 5) fail('cloudflare_invalid_pagination', 'Cloudflare pagination is invalid');
    if (
      context.execution?.tool !== TOOL ||
      typeof context.execution?.target !== 'string' ||
      context.execution.target.toLowerCase() !== accountId ||
      context.execution?.environment !== context.environment ||
      !EXECUTION_ID_RE.test(context.execution?.execution_id || '') ||
      !REQUEST_BINDING_RE.test(context.execution?.request_binding || '')
    ) {
      fail(
        'cloudflare_execution_binding_mismatch',
        'Execution capability is not bound to this Cloudflare account',
        403,
      );
    }
    if (typeof context.accountRef !== 'string' || !context.accountRef) {
      fail('cloudflare_account_unavailable', 'Cloudflare account binding is unavailable', 503);
    }

    let lease;
    try {
      lease = await tokenProvider({
        account_ref: context.accountRef,
        environment: context.environment,
        account_id: accountId,
        execution_id: context.execution.execution_id,
        request_binding: context.execution.request_binding,
        signal: context.signal,
      });
    } catch {
      fail('cloudflare_credential_unavailable', 'Cloudflare credential is unavailable', 503);
    }
    const token = validateCredential(lease, accountId);
    const query = new URLSearchParams({
      'account.id': accountId,
      page: String(page),
      per_page: String(perPage),
    });
    if (name !== undefined) query.set('name', name);

    let response;
    try {
      response = await request({
        origin: ORIGIN,
        method: 'GET',
        path: `${PATH}?${query}`,
        headers: {
          Accept: 'application/json',
          Authorization: `Bearer ${token}`,
          'User-Agent': `secret-broker/${BROKER_VERSION}`,
        },
        max_response_bytes: MAX_RESPONSE_BYTES,
        redirect: 'manual',
        signal: context.signal,
      });
    } catch (error) {
      if (error instanceof V2Error) throw error;
      fail('cloudflare_unavailable', 'Cloudflare request failed', 502);
    }
    if ([301, 302, 303, 307, 308].includes(response?.status)) {
      fail('cloudflare_redirect_denied', 'Cloudflare redirect was denied', 502);
    }
    if (response?.status === 401)
      fail('cloudflare_credential_rejected', 'Cloudflare credential was rejected', 502);
    if (response?.status === 403)
      fail('cloudflare_forbidden', 'Cloudflare token lacks Zone Read access', 403);
    if (response?.status === 429)
      fail('cloudflare_rate_limited', 'Cloudflare rate limit was reached', 429);
    if (response?.status !== 200)
      fail('cloudflare_upstream_error', 'Cloudflare zones request failed', 502);
    return projectResponse(parseBody(response.body), accountId, page, perPage);
  };
}

export const CLOUDFLARE_ZONES_LIST_CONTRACT = Object.freeze({
  tool: TOOL,
  origin: ORIGIN,
  method: 'GET',
  path: PATH,
  maximum_response_bytes: MAX_RESPONSE_BYTES,
  required_permission: 'Zone Zone Read',
  pagination: Object.freeze({ minimum_per_page: 5, maximum_per_page: 50 }),
});
