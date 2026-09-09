import { V2Error } from '../lib/operations-v2.js';

const TOOL = 'docker.repository.tags.list@1.0.0';
const ORIGIN = 'https://registry-1.docker.io';
const COMPONENT_RE = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const TAG_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_TAGS = 100;
const MAX_TOKEN_TTL_MS = 300_000;

function fail(code, message, status = 400) {
  throw new V2Error(code, message, status);
}

function component(value, field) {
  if (typeof value !== 'string' || value.length > 128 || !COMPONENT_RE.test(value)) {
    fail('docker_invalid_repository', `Docker ${field} is invalid`);
  }
  return value;
}

function validateInput(parameters) {
  const namespace = component(parameters?.namespace, 'namespace');
  const repository = component(parameters?.repository, 'repository');
  const repositoryRef = `${namespace}/${repository}`;
  if (repositoryRef.length >= 256 || parameters?.resource_ref !== repositoryRef) {
    fail('docker_repository_binding_mismatch', 'Docker repository binding is invalid', 403);
  }
  return { namespace, repository, repositoryRef };
}

function validateLease(lease, repositoryRef, now) {
  if (
    !lease ||
    typeof lease.token !== 'string' ||
    lease.token.length < 8 ||
    lease.repository !== repositoryRef
  ) {
    fail('docker_credential_unavailable', 'Docker credential is unavailable', 503);
  }
  const expiresAt = Date.parse(lease.expires_at);
  if (!Number.isFinite(expiresAt) || expiresAt <= now || expiresAt > now + MAX_TOKEN_TTL_MS) {
    fail('docker_credential_expiry_invalid', 'Docker credential expiry is invalid', 503);
  }
  return lease.token;
}

function parseBody(body) {
  let encoded;
  try {
    encoded = Buffer.isBuffer(body)
      ? body
      : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
  } catch {
    fail('docker_invalid_response', 'Docker returned invalid JSON', 502);
  }
  if (encoded.length > MAX_RESPONSE_BYTES) {
    fail('docker_response_too_large', 'Docker response exceeds the configured limit', 502);
  }
  try {
    return Buffer.isBuffer(body) || typeof body === 'string'
      ? JSON.parse(encoded.toString('utf8'))
      : body;
  } catch {
    fail('docker_invalid_response', 'Docker returned invalid JSON', 502);
  }
}

function projectResponse(body, repositoryRef) {
  if (!body || typeof body !== 'object' || Array.isArray(body) || body.name !== repositoryRef) {
    fail('docker_scope_mismatch', 'Docker response does not match the authorized repository', 502);
  }
  const tags = body.tags === null ? [] : body.tags;
  if (
    !Array.isArray(tags) ||
    tags.length > MAX_TAGS ||
    tags.some((tag) => typeof tag !== 'string' || !TAG_RE.test(tag)) ||
    new Set(tags).size !== tags.length
  ) {
    fail('docker_invalid_response', 'Docker returned invalid tags', 502);
  }
  return { name: repositoryRef, tags: [...tags] };
}

export function createDockerRepositoryTagsListAdapter({
  request,
  tokenProvider,
  now = Date.now,
} = {}) {
  if (typeof request !== 'function') {
    throw new TypeError('Docker adapter requires a pinned request transport');
  }
  if (typeof tokenProvider !== 'function') {
    throw new TypeError('Docker adapter requires a scoped token provider');
  }
  if (typeof now !== 'function') throw new TypeError('Docker adapter requires a clock');

  return async function dockerRepositoryTagsList(parameters, context = {}) {
    const { namespace, repository, repositoryRef } = validateInput(parameters);
    if (
      context.execution?.tool !== TOOL ||
      context.execution?.target !== repositoryRef ||
      context.execution?.environment !== context.environment
    ) {
      fail(
        'docker_execution_binding_mismatch',
        'Execution capability is not bound to this Docker repository',
        403,
      );
    }
    if (typeof context.accountRef !== 'string' || !context.accountRef) {
      fail('docker_account_unavailable', 'Docker account binding is unavailable', 503);
    }

    let lease;
    try {
      lease = await tokenProvider({
        account_ref: context.accountRef,
        environment: context.environment,
        repository: repositoryRef,
        scope: `repository:${repositoryRef}:pull`,
        signal: context.signal,
      });
    } catch {
      fail('docker_credential_unavailable', 'Docker credential is unavailable', 503);
    }
    const token = validateLease(lease, repositoryRef, now());
    let response;
    try {
      response = await request({
        origin: ORIGIN,
        method: 'GET',
        path: `/v2/${namespace}/${repository}/tags/list?n=${MAX_TAGS}`,
        headers: {
          Accept: 'application/json',
          Authorization: `Bearer ${token}`,
        },
        max_response_bytes: MAX_RESPONSE_BYTES,
        redirect: 'manual',
        signal: context.signal,
      });
    } catch (error) {
      if (error instanceof V2Error) throw error;
      fail('docker_unavailable', 'Docker registry request failed', 502);
    }
    if ([301, 302, 303, 307, 308].includes(response?.status)) {
      fail('docker_redirect_denied', 'Docker registry redirect was denied', 502);
    }
    if (response?.status === 401) {
      fail('docker_credential_rejected', 'Docker credential was rejected', 502);
    }
    if (response?.status === 403) {
      fail('docker_forbidden', 'Docker token lacks repository pull access', 403);
    }
    if (response?.status === 404) fail('docker_not_found', 'Docker repository was not found', 404);
    if (response?.status === 429) fail('docker_rate_limited', 'Docker rate limit was reached', 429);
    if (response?.status !== 200) fail('docker_upstream_error', 'Docker tags request failed', 502);
    return projectResponse(parseBody(response.body), repositoryRef);
  };
}

export const DOCKER_REPOSITORY_TAGS_LIST_CONTRACT = Object.freeze({
  tool: TOOL,
  origin: ORIGIN,
  method: 'GET',
  path_template: '/v2/{namespace}/{repository}/tags/list?n=100',
  scope_template: 'repository:{namespace}/{repository}:pull',
  maximum_response_bytes: MAX_RESPONSE_BYTES,
  maximum_tags: MAX_TAGS,
  maximum_token_ttl_seconds: MAX_TOKEN_TTL_MS / 1000,
});
