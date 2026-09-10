import { V2Error } from '../lib/operations-v2.js';
import { BROKER_VERSION } from '../version.js';

const TOOL = 'deepseek.models.list@1.0.0';
const ORIGIN = 'https://api.deepseek.com';
const PATH = '/models';
const RESOURCE = 'model-catalog';
const MAX_RESPONSE_BYTES = 256 * 1024;
const MAX_TOKEN_TTL_MS = 5 * 60_000;
const MODEL_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const OWNER_RE = /^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$/;

function fail(code, message, status = 400) {
  throw new V2Error(code, message, status);
}

function validateParameters(parameters) {
  if (
    !parameters ||
    typeof parameters !== 'object' ||
    Array.isArray(parameters) ||
    Object.keys(parameters).length !== 1 ||
    parameters.resource_ref !== RESOURCE
  ) {
    fail('deepseek_invalid_request', 'DeepSeek model catalog request is invalid');
  }
}

function validateLease(lease, accountRef, environment, now) {
  const expiresAt = Date.parse(lease?.expires_at);
  if (
    !lease ||
    typeof lease.token !== 'string' ||
    lease.token.length < 8 ||
    lease.token.length > 4096 ||
    lease.account_ref !== accountRef ||
    lease.environment !== environment ||
    lease.resource_ref !== RESOURCE ||
    !Number.isFinite(expiresAt) ||
    expiresAt <= now ||
    expiresAt > now + MAX_TOKEN_TTL_MS
  ) {
    fail('deepseek_credential_unavailable', 'DeepSeek credential is unavailable', 503);
  }
  return lease.token;
}

function parseBody(body) {
  if (body && typeof body === 'object' && !Buffer.isBuffer(body)) return body;
  const text = Buffer.isBuffer(body) ? body.toString('utf8') : String(body || '');
  if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES) {
    fail('deepseek_response_too_large', 'DeepSeek response exceeded the configured limit', 502);
  }
  try {
    return JSON.parse(text);
  } catch {
    fail('deepseek_invalid_response', 'DeepSeek returned an invalid response', 502);
  }
}

function projectResponse(body) {
  if (body?.object !== 'list' || !Array.isArray(body.data) || body.data.length > 100) {
    fail('deepseek_invalid_response', 'DeepSeek returned an invalid model catalog', 502);
  }
  const seen = new Set();
  const models = body.data.map((model) => {
    if (
      !model ||
      typeof model !== 'object' ||
      Array.isArray(model) ||
      model.object !== 'model' ||
      !MODEL_ID_RE.test(model.id || '') ||
      !OWNER_RE.test(model.owned_by || '') ||
      seen.has(model.id)
    ) {
      fail('deepseek_invalid_response', 'DeepSeek returned invalid model metadata', 502);
    }
    seen.add(model.id);
    return { id: model.id, owned_by: model.owned_by };
  });
  return { models };
}

export function createDeepSeekModelsListAdapter({ request, tokenProvider, now = Date.now } = {}) {
  if (typeof request !== 'function')
    throw new TypeError('DeepSeek adapter requires a pinned request transport');
  if (typeof tokenProvider !== 'function')
    throw new TypeError('DeepSeek adapter requires a scoped token provider');
  if (typeof now !== 'function') throw new TypeError('DeepSeek adapter requires a clock');

  return async function deepSeekModelsList(parameters, context = {}) {
    validateParameters(parameters);
    if (
      context.execution?.tool !== TOOL ||
      context.execution?.target !== RESOURCE ||
      context.execution?.environment !== context.environment
    ) {
      fail(
        'deepseek_execution_binding_mismatch',
        'Execution capability is not bound to the DeepSeek model catalog',
        403,
      );
    }
    if (typeof context.accountRef !== 'string' || !context.accountRef) {
      fail('deepseek_account_unavailable', 'DeepSeek account binding is unavailable', 503);
    }
    let lease;
    try {
      lease = await tokenProvider({
        account_ref: context.accountRef,
        environment: context.environment,
        resource_ref: RESOURCE,
        signal: context.signal,
      });
    } catch {
      fail('deepseek_credential_unavailable', 'DeepSeek credential is unavailable', 503);
    }
    const token = validateLease(lease, context.accountRef, context.environment, now());
    let response;
    try {
      response = await request({
        origin: ORIGIN,
        method: 'GET',
        path: PATH,
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
      fail('deepseek_unavailable', 'DeepSeek request failed', 502);
    }
    if ([301, 302, 303, 307, 308].includes(response?.status))
      fail('deepseek_redirect_denied', 'DeepSeek redirect was denied', 502);
    if (response?.status === 401)
      fail('deepseek_credential_rejected', 'DeepSeek credential was rejected', 502);
    if (response?.status === 403)
      fail('deepseek_forbidden', 'DeepSeek model access was denied', 403);
    if (response?.status === 429)
      fail('deepseek_rate_limited', 'DeepSeek rate limit was reached', 429);
    if (response?.status !== 200)
      fail('deepseek_upstream_error', 'DeepSeek model catalog request failed', 502);
    return projectResponse(parseBody(response.body));
  };
}

export const DEEPSEEK_MODELS_LIST_CONTRACT = Object.freeze({
  tool: TOOL,
  origin: ORIGIN,
  method: 'GET',
  path: PATH,
  resource_ref: RESOURCE,
  maximum_response_bytes: MAX_RESPONSE_BYTES,
  maximum_token_ttl_seconds: MAX_TOKEN_TTL_MS / 1000,
  arbitrary_url: false,
  credential_export: false,
});
