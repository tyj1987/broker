import { V2Error } from '../lib/operations-v2.js';
import { BROKER_VERSION } from '../version.js';

const TOOL = 'cloudflare.dns.records.list@1.0.0';
const ORIGIN = 'https://api.cloudflare.com';
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const ZONE_ID_RE = /^[a-f0-9]{32}$/;
const EXECUTION_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const REQUEST_BINDING_RE = /^[A-Za-z0-9_-]{43}$/;
const DNS_NAME_RE =
  /^(?=.{1,253}$)(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const RECORD_TYPES = new Set([
  'A',
  'AAAA',
  'CAA',
  'CERT',
  'CNAME',
  'DNSKEY',
  'DS',
  'HTTPS',
  'LOC',
  'MX',
  'NAPTR',
  'NS',
  'OPENPGPKEY',
  'PTR',
  'SMIMEA',
  'SRV',
  'SSHFP',
  'SVCB',
  'TLSA',
  'TXT',
  'URI',
]);

function fail(code, message, status = 400) {
  throw new V2Error(code, message, status);
}

function boundedInteger(value, fallback, maximum) {
  const normalized = value === undefined ? fallback : value;
  if (!Number.isSafeInteger(normalized) || normalized < 1 || normalized > maximum) {
    fail('cloudflare_dns_invalid_pagination', 'Cloudflare DNS pagination is invalid');
  }
  return normalized;
}

function parseBody(body) {
  const text = Buffer.isBuffer(body)
    ? body.toString('utf8')
    : typeof body === 'string'
      ? body
      : body === undefined
        ? ''
        : JSON.stringify(body);
  if (Buffer.byteLength(text || '', 'utf8') > MAX_RESPONSE_BYTES) {
    fail('cloudflare_dns_response_too_large', 'Cloudflare DNS response exceeded the limit', 502);
  }
  try {
    return JSON.parse(text);
  } catch {
    fail('cloudflare_dns_invalid_response', 'Cloudflare returned an invalid DNS response', 502);
  }
}

function projectResponse(body, page, perPage) {
  if (body?.success !== true || !Array.isArray(body.result) || !body.result_info) {
    fail('cloudflare_dns_invalid_response', 'Cloudflare returned an invalid DNS response', 502);
  }
  const records = body.result.map((record) => {
    const name = typeof record?.name === 'string' ? record.name.toLowerCase() : '';
    if (
      !ZONE_ID_RE.test(record?.id || '') ||
      !RECORD_TYPES.has(record?.type) ||
      !DNS_NAME_RE.test(name) ||
      !Number.isSafeInteger(record?.ttl) ||
      record.ttl < 1 ||
      typeof record?.proxied !== 'boolean'
    ) {
      fail('cloudflare_dns_invalid_response', 'Cloudflare returned invalid DNS metadata', 502);
    }
    return { id: record.id, type: record.type, name, ttl: record.ttl, proxied: record.proxied };
  });
  const info = body.result_info;
  for (const field of ['count', 'total_count', 'total_pages']) {
    if (!Number.isSafeInteger(info[field]) || info[field] < 0) {
      fail(
        'cloudflare_dns_invalid_response',
        'Cloudflare returned invalid pagination metadata',
        502,
      );
    }
  }
  if (
    info.page !== page ||
    info.per_page !== perPage ||
    info.count !== records.length ||
    info.total_count < info.count ||
    records.length > perPage
  ) {
    fail(
      'cloudflare_dns_invalid_response',
      'Cloudflare returned inconsistent pagination metadata',
      502,
    );
  }
  return {
    records,
    result_info: {
      page: info.page,
      per_page: info.per_page,
      count: info.count,
      total_count: info.total_count,
      total_pages: info.total_pages,
    },
  };
}

export function createCloudflareDnsRecordsListAdapter({ request, tokenProvider } = {}) {
  if (typeof request !== 'function')
    throw new TypeError('Cloudflare DNS adapter requires a pinned request transport');
  if (typeof tokenProvider !== 'function')
    throw new TypeError('Cloudflare DNS adapter requires a scoped token provider');

  return async function cloudflareDnsRecordsList(parameters, context = {}) {
    const zoneId = typeof parameters?.zone_id === 'string' ? parameters.zone_id.toLowerCase() : '';
    if (!ZONE_ID_RE.test(zoneId) || parameters?.resource_ref !== zoneId) {
      fail('cloudflare_dns_zone_binding_mismatch', 'Cloudflare DNS zone binding is invalid', 403);
    }
    const type = parameters.type;
    if (type !== undefined && !RECORD_TYPES.has(type)) {
      fail('cloudflare_dns_invalid_filter', 'Cloudflare DNS record type is invalid');
    }
    const name = parameters.name === undefined ? undefined : String(parameters.name).toLowerCase();
    if (name !== undefined && !DNS_NAME_RE.test(name)) {
      fail('cloudflare_dns_invalid_filter', 'Cloudflare DNS name filter is invalid');
    }
    if (parameters.proxied !== undefined && typeof parameters.proxied !== 'boolean') {
      fail('cloudflare_dns_invalid_filter', 'Cloudflare DNS proxied filter is invalid');
    }
    const page = boundedInteger(parameters.page, 1, 10_000);
    const perPage = boundedInteger(parameters.per_page, 50, 100);
    if (
      context.execution?.tool !== TOOL ||
      context.execution?.target !== zoneId ||
      context.execution?.environment !== context.environment ||
      !EXECUTION_ID_RE.test(context.execution?.execution_id || '') ||
      !REQUEST_BINDING_RE.test(context.execution?.request_binding || '')
    ) {
      fail(
        'cloudflare_dns_execution_binding_mismatch',
        'Execution capability is not bound to this Cloudflare zone',
        403,
      );
    }
    if (typeof context.accountRef !== 'string' || !context.accountRef) {
      fail(
        'cloudflare_dns_account_unavailable',
        'Cloudflare DNS account binding is unavailable',
        503,
      );
    }
    let lease;
    try {
      lease = await tokenProvider({
        account_ref: context.accountRef,
        environment: context.environment,
        zone_id: zoneId,
        execution_id: context.execution.execution_id,
        request_binding: context.execution.request_binding,
        signal: context.signal,
      });
    } catch {
      fail(
        'cloudflare_dns_credential_unavailable',
        'Cloudflare DNS credential is unavailable',
        503,
      );
    }
    if (
      !lease ||
      typeof lease.token !== 'string' ||
      lease.token.length < 8 ||
      lease.zone_id !== zoneId
    ) {
      fail(
        'cloudflare_dns_credential_unavailable',
        'Cloudflare DNS credential is unavailable',
        503,
      );
    }
    const query = new URLSearchParams({ page: String(page), per_page: String(perPage) });
    if (type !== undefined) query.set('type', type);
    if (name !== undefined) query.set('name.exact', name);
    if (parameters.proxied !== undefined) query.set('proxied', String(parameters.proxied));
    let response;
    try {
      response = await request({
        origin: ORIGIN,
        method: 'GET',
        path: `/client/v4/zones/${zoneId}/dns_records?${query}`,
        headers: {
          Accept: 'application/json',
          Authorization: `Bearer ${lease.token}`,
          'User-Agent': `secret-broker/${BROKER_VERSION}`,
        },
        max_response_bytes: MAX_RESPONSE_BYTES,
        redirect: 'manual',
        signal: context.signal,
      });
    } catch (error) {
      if (error instanceof V2Error) throw error;
      fail('cloudflare_dns_unavailable', 'Cloudflare DNS request failed', 502);
    }
    if ([301, 302, 303, 307, 308].includes(response?.status)) {
      fail('cloudflare_dns_redirect_denied', 'Cloudflare DNS redirect was denied', 502);
    }
    if (response?.status === 401)
      fail('cloudflare_dns_credential_rejected', 'Cloudflare DNS credential was rejected', 502);
    if (response?.status === 403)
      fail('cloudflare_dns_forbidden', 'Cloudflare token lacks DNS Read access', 403);
    if (response?.status === 429)
      fail('cloudflare_dns_rate_limited', 'Cloudflare DNS rate limit was reached', 429);
    if (response?.status !== 200)
      fail('cloudflare_dns_upstream_error', 'Cloudflare DNS request failed', 502);
    return projectResponse(parseBody(response.body), page, perPage);
  };
}

export const CLOUDFLARE_DNS_RECORDS_LIST_CONTRACT = Object.freeze({
  tool: TOOL,
  origin: ORIGIN,
  method: 'GET',
  path_template: '/client/v4/zones/{zone_id}/dns_records',
  required_permission: 'DNS Read',
  maximum_response_bytes: MAX_RESPONSE_BYTES,
  maximum_per_page: 100,
  releases_record_content: false,
});
