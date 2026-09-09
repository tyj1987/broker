import { V2Error } from '../lib/operations-v2.js';
import { BROKER_VERSION } from '../version.js';

const TOOL = 'github.repository.read@1.0.0';
const ORIGIN = 'https://api.github.com';
const API_VERSION = '2026-03-10';
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_TOKEN_TTL_MS = 60 * 60_000 + 30_000;
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const REPO_RE = /^(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$/;

function fail(code, message, status = 400) {
  throw new V2Error(code, message, status);
}

function repositoryRef(owner, repo) {
  return `${owner}/${repo}`;
}

function parseJsonBody(body) {
  if (body && typeof body === 'object' && !Buffer.isBuffer(body)) return body;
  const text = Buffer.isBuffer(body) ? body.toString('utf8') : String(body || '');
  if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES) fail('github_response_too_large', 'GitHub response exceeded the configured limit', 502);
  try {
    return JSON.parse(text);
  } catch {
    fail('github_invalid_response', 'GitHub returned an invalid response', 502);
  }
}

function validateLease(lease, expectedRepository, now) {
  if (!lease || typeof lease !== 'object') fail('github_credential_unavailable', 'GitHub installation credential is unavailable', 503);
  if (typeof lease.token !== 'string' || lease.token.length < 1 || lease.token.length > 4096) {
    fail('github_credential_unavailable', 'GitHub installation credential is unavailable', 503);
  }
  if (typeof lease.repository !== 'string' || lease.repository.toLowerCase() !== expectedRepository.toLowerCase()) {
    fail('github_credential_scope_mismatch', 'GitHub installation credential is not repository scoped', 403);
  }
  const expiresAt = Date.parse(lease.expires_at);
  if (!Number.isFinite(expiresAt) || expiresAt <= now || expiresAt - now > MAX_TOKEN_TTL_MS) {
    fail('github_credential_expired', 'GitHub installation credential lifetime is invalid', 503);
  }
  return lease.token;
}

function projectRepository(body, expectedRepository) {
  if (!body || !Number.isSafeInteger(body.id) || body.id < 1
    || typeof body.full_name !== 'string' || body.full_name.toLowerCase() !== expectedRepository.toLowerCase()
    || !['public', 'private', 'internal'].includes(body.visibility)
    || typeof body.archived !== 'boolean') {
    fail('github_invalid_response', 'GitHub returned an invalid repository projection', 502);
  }
  return {
    id: body.id,
    full_name: body.full_name,
    visibility: body.visibility,
    archived: body.archived,
  };
}

export function createGitHubRepositoryReadAdapter({ request, tokenProvider, now = () => Date.now() } = {}) {
  if (typeof request !== 'function') throw new TypeError('GitHub adapter requires a pinned request transport');
  if (typeof tokenProvider !== 'function') throw new TypeError('GitHub adapter requires an installation token provider');

  return async function githubRepositoryRead(parameters, context = {}) {
    const owner = parameters?.owner;
    const repo = parameters?.repo;
    const target = repositoryRef(owner, repo);
    if (!OWNER_RE.test(owner || '') || !REPO_RE.test(repo || '')) fail('github_invalid_repository', 'GitHub repository identity is invalid');
    if (typeof parameters.resource_ref !== 'string' || parameters.resource_ref.toLowerCase() !== target.toLowerCase()) {
      fail('github_target_mismatch', 'GitHub repository target does not match typed parameters', 403);
    }
    if (context.execution?.tool !== TOOL || context.execution?.target?.toLowerCase() !== target.toLowerCase()
      || context.execution?.environment !== context.environment) {
      fail('github_execution_binding_mismatch', 'Execution capability is not bound to this GitHub repository', 403);
    }
    if (typeof context.accountRef !== 'string' || !context.accountRef) fail('github_account_unavailable', 'GitHub account binding is unavailable', 503);

    let lease;
    try {
      lease = await tokenProvider({
        account_ref: context.accountRef,
        environment: context.environment,
        owner,
        repo,
        repository: target,
        signal: context.signal,
      });
    } catch {
      fail('github_credential_unavailable', 'GitHub installation credential is unavailable', 503);
    }
    const token = validateLease(lease, target, now());
    let response;
    try {
      response = await request({
        origin: ORIGIN,
        method: 'GET',
        path: `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`,
        headers: {
          Accept: 'application/vnd.github+json',
          Authorization: `Bearer ${token}`,
          'X-GitHub-Api-Version': API_VERSION,
          'User-Agent': `secret-broker/${BROKER_VERSION}`,
        },
        max_response_bytes: MAX_RESPONSE_BYTES,
        redirect: 'manual',
        signal: context.signal,
      });
    } catch (error) {
      if (error instanceof V2Error) throw error;
      fail('github_unavailable', 'GitHub request failed', 502);
    }
    if ([301, 302, 303, 307, 308].includes(response?.status)) fail('github_redirect_denied', 'GitHub redirect was denied', 502);
    if (response?.status === 401) fail('github_credential_rejected', 'GitHub installation credential was rejected', 502);
    if (response?.status === 403) fail('github_forbidden', 'GitHub App lacks repository access', 403);
    if (response?.status === 404) fail('github_not_found', 'GitHub repository was not found', 404);
    if (response?.status !== 200) fail('github_upstream_error', 'GitHub repository request failed', 502);
    return projectRepository(parseJsonBody(response.body), target);
  };
}

export const GITHUB_REPOSITORY_READ_CONTRACT = Object.freeze({
  tool: TOOL,
  origin: ORIGIN,
  method: 'GET',
  api_version: API_VERSION,
  maximum_response_bytes: MAX_RESPONSE_BYTES,
  credential_maximum_ttl_seconds: 3600,
  required_permission: 'metadata:read',
});
