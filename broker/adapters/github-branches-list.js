import { V2Error } from '../lib/operations-v2.js';
import { BROKER_VERSION } from '../version.js';

const TOOL = 'github.branches.list@1.0.0';
const ORIGIN = 'https://api.github.com';
const API_VERSION = '2026-03-10';
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_TOKEN_TTL_MS = 60 * 60_000 + 30_000;
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const REPO_RE = /^(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$/;
const EXECUTION_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const REQUEST_BINDING_RE = /^[A-Za-z0-9_-]{43}$/;
const SHA_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i;
const UNSAFE_BRANCH_NAME_RE = /[\u0000-\u001f\u007f]/;

function fail(code, message, status = 400) {
  throw new V2Error(code, message, status);
}

function repositoryRef(owner, repo) {
  return `${owner}/${repo}`;
}

function boundedInteger(value, fallback, minimum, maximum, field) {
  const selected = value === undefined ? fallback : value;
  if (!Number.isSafeInteger(selected) || selected < minimum || selected > maximum) {
    fail('github_invalid_pagination', `${field} is invalid`);
  }
  return selected;
}

function parseJsonBody(body) {
  if (body && typeof body === 'object' && !Buffer.isBuffer(body)) return body;
  const text = Buffer.isBuffer(body) ? body.toString('utf8') : String(body || '');
  if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES) {
    fail('github_response_too_large', 'GitHub response exceeded the configured limit', 502);
  }
  try {
    return JSON.parse(text);
  } catch {
    fail('github_invalid_response', 'GitHub returned an invalid response', 502);
  }
}

function validateLease(lease, expectedRepository, now) {
  if (!lease || typeof lease !== 'object') {
    fail('github_credential_unavailable', 'GitHub installation credential is unavailable', 503);
  }
  if (typeof lease.token !== 'string' || lease.token.length < 1 || lease.token.length > 4096) {
    fail('github_credential_unavailable', 'GitHub installation credential is unavailable', 503);
  }
  if (
    typeof lease.repository !== 'string' ||
    lease.repository.toLowerCase() !== expectedRepository.toLowerCase() ||
    !lease.permissions ||
    lease.permissions.contents !== 'read' ||
    Object.keys(lease.permissions).some((key) => key !== 'contents')
  ) {
    fail(
      'github_credential_scope_mismatch',
      'GitHub installation credential is not bound to contents read',
      403,
    );
  }
  const expiresAt = Date.parse(lease.expires_at);
  if (!Number.isFinite(expiresAt) || expiresAt <= now || expiresAt - now > MAX_TOKEN_TTL_MS) {
    fail('github_credential_expired', 'GitHub installation credential lifetime is invalid', 503);
  }
  return lease.token;
}

function projectBranches(body, maximumItems) {
  if (!Array.isArray(body) || body.length > maximumItems) {
    fail('github_invalid_response', 'GitHub returned an invalid branch collection', 502);
  }
  return body.map((branch) => {
    if (
      !branch ||
      typeof branch !== 'object' ||
      typeof branch.name !== 'string' ||
      branch.name.length < 1 ||
      branch.name.length > 255 ||
      UNSAFE_BRANCH_NAME_RE.test(branch.name) ||
      !SHA_RE.test(branch.commit?.sha || '') ||
      typeof branch.protected !== 'boolean'
    ) {
      fail('github_invalid_response', 'GitHub returned an invalid branch projection', 502);
    }
    return { name: branch.name, sha: branch.commit.sha, protected: branch.protected };
  });
}

export function createGitHubBranchesListAdapter({
  request,
  tokenProvider,
  now = () => Date.now(),
} = {}) {
  if (typeof request !== 'function')
    throw new TypeError('GitHub branches adapter requires a pinned request transport');
  if (typeof tokenProvider !== 'function')
    throw new TypeError('GitHub branches adapter requires an installation token provider');

  return async function githubBranchesList(parameters, context = {}) {
    const owner = parameters?.owner;
    const repo = parameters?.repo;
    const target = repositoryRef(owner, repo);
    if (!OWNER_RE.test(owner || '') || !REPO_RE.test(repo || '')) {
      fail('github_invalid_repository', 'GitHub repository identity is invalid');
    }
    if (
      typeof parameters.resource_ref !== 'string' ||
      parameters.resource_ref.toLowerCase() !== target.toLowerCase()
    ) {
      fail(
        'github_target_mismatch',
        'GitHub repository target does not match typed parameters',
        403,
      );
    }
    if (parameters.protected !== undefined && typeof parameters.protected !== 'boolean') {
      fail('github_invalid_filter', 'GitHub protected filter is invalid');
    }
    const perPage = boundedInteger(parameters.per_page, 30, 1, 100, 'per_page');
    const page = boundedInteger(parameters.page, 1, 1, 10_000, 'page');
    if (
      context.execution?.tool !== TOOL ||
      context.execution?.target?.toLowerCase() !== target.toLowerCase() ||
      context.execution?.environment !== context.environment ||
      !EXECUTION_ID_RE.test(context.execution?.execution_id || '') ||
      !REQUEST_BINDING_RE.test(context.execution?.request_binding || '')
    ) {
      fail(
        'github_execution_binding_mismatch',
        'Execution capability is not bound to this GitHub repository',
        403,
      );
    }
    if (typeof context.accountRef !== 'string' || !context.accountRef) {
      fail('github_account_unavailable', 'GitHub account binding is unavailable', 503);
    }

    let lease;
    try {
      lease = await tokenProvider({
        account_ref: context.accountRef,
        environment: context.environment,
        owner,
        repo,
        repository: target,
        execution_id: context.execution.execution_id,
        request_binding: context.execution.request_binding,
        signal: context.signal,
      });
    } catch {
      fail('github_credential_unavailable', 'GitHub installation credential is unavailable', 503);
    }
    const token = validateLease(lease, target, now());
    const query = new URLSearchParams({ per_page: String(perPage), page: String(page) });
    if (parameters.protected !== undefined) query.set('protected', String(parameters.protected));

    let response;
    try {
      response = await request({
        origin: ORIGIN,
        method: 'GET',
        path: `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/branches?${query}`,
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
    if ([301, 302, 303, 307, 308].includes(response?.status)) {
      fail('github_redirect_denied', 'GitHub redirect was denied', 502);
    }
    if (response?.status === 401)
      fail('github_credential_rejected', 'GitHub installation credential was rejected', 502);
    if (response?.status === 403)
      fail('github_forbidden', 'GitHub App lacks contents read permission', 403);
    if (response?.status === 404) fail('github_not_found', 'GitHub repository was not found', 404);
    if (response?.status !== 200)
      fail('github_upstream_error', 'GitHub branches request failed', 502);
    const branches = projectBranches(parseJsonBody(response.body), perPage);
    return { branches, page, per_page: perPage, has_more: branches.length === perPage };
  };
}

export const GITHUB_BRANCHES_LIST_CONTRACT = Object.freeze({
  tool: TOOL,
  origin: ORIGIN,
  method: 'GET',
  path_template: '/repos/{owner}/{repo}/branches',
  api_version: API_VERSION,
  maximum_response_bytes: MAX_RESPONSE_BYTES,
  maximum_page_size: 100,
  credential_maximum_ttl_seconds: 3600,
  required_permission: 'contents:read',
});
