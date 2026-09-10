import { V2Error } from '../lib/operations-v2.js';
import { BROKER_VERSION } from '../version.js';

const TOOL = 'openai.models.list@1.0.0';
const ORIGIN = 'https://api.openai.com';
const PATH = '/v1/models';
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_TOKEN_TTL_MS = 5 * 60_000;
const PROJECT_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{2,127}$/;
const MODEL_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const EXECUTION_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const REQUEST_BINDING_RE = /^[A-Za-z0-9_-]{43}$/;

function fail(code, message, status = 400) {
  throw new V2Error(code, message, status);
}

function validateParameters(parameters) {
  if (
    !parameters ||
    typeof parameters !== 'object' ||
    Array.isArray(parameters) ||
    Object.keys(parameters).length !== 1 ||
    !PROJECT_ID_RE.test(parameters.resource_ref || '')
  ) {
    fail('openai_invalid_request', 'OpenAI model catalog request is invalid');
  }
}

function validateLease(lease, accountRef, environment, projectId, now) {
  const expiresAt = Date.parse(lease?.expires_at);
  if (
    !lease ||
    typeof lease.token !== 'string' ||
    lease.token.length < 8 ||
    lease.token.length > 4096 ||
    lease.account_ref !== accountRef ||
    lease.environment !== environment ||
    lease.resource_ref !== projectId ||
    !Number.isFinite(expiresAt) ||
    expiresAt <= now ||
    expiresAt > now + MAX_TOKEN_TTL_MS
  ) {
    fail('openai_credential_unavailable', 'OpenAI credential is unavailable', 503);
  }
  return lease.token;
}

function parseBody(body) {
  if (body && typeof body === 'object' && !Buffer.isBuffer(body)) return body;
  const text = Buffer.isBuffer(body) ? body.toString('utf8') : String(body || '');
  if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES) {
    fail('openai_response_too_large', 'OpenAI response exceeded the configured limit', 502);
  }
  try {
    return JSON.parse(text);
  } catch {
    fail('openai_invalid_response', 'OpenAI returned an invalid response', 502);
  }
}

function projectResponse(body) {
  if (body?.object !== 'list' || !Array.isArray(body.data) || body.data.length > 1000) {
    fail('openai_invalid_response', 'OpenAI returned an invalid model catalog', 502);
  }
  const seen = new Set();
  const models = body.data.map((model) => {
    if (
      !model ||
      typeof model !== 'object' ||
      Array.isArray(model) ||
      model.object !== 'model' ||
      !MODEL_ID_RE.test(model.id || '') ||
      seen.has(model.id)
    ) {
      fail('openai_invalid_response', 'OpenAI returned invalid model metadata', 502);
    }
    seen.add(model.id);
    return { id: model.id };
  });
  return { models };
}

export function createOpenAIModelsListAdapter({ request, tokenProvider, now = Date.now } = {}) {
  if (typeof request !== 'function')
    throw new TypeError('OpenAI adapter requires a pinned request transport');
  if (typeof tokenProvider !== 'function')
    throw new TypeError('OpenAI adapter requires a scoped token provider');
  if (typeof now !== 'function') throw new TypeError('OpenAI adapter requires a clock');

  return async function openAIModelsList(parameters, context = {}) {
    validateParameters(parameters);
    const projectId = parameters.resource_ref;
    if (
      context.execution?.tool !== TOOL ||
      context.execution?.target !== projectId ||
      context.execution?.environment !== context.environment ||
      !EXECUTION_ID_RE.test(context.execution?.execution_id || '') ||
      !REQUEST_BINDING_RE.test(context.execution?.request_binding || '')
    ) {
      fail(
        'openai_execution_binding_mismatch',
        'Execution capability is not bound to this OpenAI project',
        403,
      );
    }
    if (typeof context.accountRef !== 'string' || !context.accountRef) {
      fail('openai_account_unavailable', 'OpenAI account binding is unavailable', 503);
    }
    let lease;
    try {
      lease = await tokenProvider({
        account_ref: context.accountRef,
        environment: context.environment,
        resource_ref: projectId,
        execution_id: context.execution.execution_id,
        request_binding: context.execution.request_binding,
        signal: context.signal,
      });
    } catch {
      fail('openai_credential_unavailable', 'OpenAI credential is unavailable', 503);
    }
    const token = validateLease(lease, context.accountRef, context.environment, projectId, now());
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
      fail('openai_unavailable', 'OpenAI request failed', 502);
    }
    if ([301, 302, 303, 307, 308].includes(response?.status))
      fail('openai_redirect_denied', 'OpenAI redirect was denied', 502);
    if (response?.status === 401)
      fail('openai_credential_rejected', 'OpenAI credential was rejected', 502);
    if (response?.status === 403) fail('openai_forbidden', 'OpenAI model access was denied', 403);
    if (response?.status === 429) fail('openai_rate_limited', 'OpenAI rate limit was reached', 429);
    if (response?.status !== 200)
      fail('openai_upstream_error', 'OpenAI model catalog request failed', 502);
    return projectResponse(parseBody(response.body));
  };
}

export const OPENAI_MODELS_LIST_CONTRACT = Object.freeze({
  tool: TOOL,
  origin: ORIGIN,
  method: 'GET',
  path: PATH,
  maximum_response_bytes: MAX_RESPONSE_BYTES,
  maximum_models: 1000,
  maximum_token_ttl_seconds: MAX_TOKEN_TTL_MS / 1000,
  releases_model_owner: false,
  arbitrary_url: false,
  credential_export: false,
});
