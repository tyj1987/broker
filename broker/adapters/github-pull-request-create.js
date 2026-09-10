import { V2Error } from '../lib/operations-v2.js';
import { BROKER_VERSION } from '../version.js';

const TOOL = 'github.pull-request.create@1.0.0';
const ORIGIN = 'https://api.github.com';
const API_VERSION = '2026-03-10';
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_TOKEN_TTL_MS = 60 * 60_000 + 30_000;
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const REPO_RE = /^(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$/;
const EXECUTION_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const REQUEST_BINDING_RE = /^[A-Za-z0-9_-]{43}$/;
const CONTROL_RE = /[\u0000-\u001f\u007f]/;
const MULTILINE_CONTROL_RE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;
const REF_RE = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$/;

function fail(code, message, status = 400) {
  throw new V2Error(code, message, status);
}

function validRef(value) {
  return (
    typeof value === 'string' &&
    REF_RE.test(value) &&
    !value.includes('..') &&
    !value.includes('//') &&
    !value.endsWith('/') &&
    !value.endsWith('.') &&
    !value.endsWith('.lock') &&
    !value.includes('@{')
  );
}

function boundedText(value, field, maximum, { optional = false, multiline = false } = {}) {
  if (optional && value === undefined) return undefined;
  if (
    typeof value !== 'string' ||
    value.length < 1 ||
    value.length > maximum ||
    (multiline ? MULTILINE_CONTROL_RE : CONTROL_RE).test(value)
  ) {
    fail('github_invalid_pull_request', `${field} is invalid`);
  }
  return value;
}

function validateLease(lease, repository, now) {
  const expiresAt = Date.parse(lease?.expires_at);
  if (
    !lease ||
    typeof lease !== 'object' ||
    typeof lease.token !== 'string' ||
    lease.token.length < 1 ||
    lease.token.length > 4096 ||
    lease.repository?.toLowerCase() !== repository.toLowerCase() ||
    !lease.permissions ||
    lease.permissions.pull_requests !== 'write' ||
    Object.keys(lease.permissions).some((key) => key !== 'pull_requests') ||
    !Number.isFinite(expiresAt) ||
    expiresAt <= now ||
    expiresAt - now > MAX_TOKEN_TTL_MS
  ) {
    fail(
      'github_credential_scope_mismatch',
      'GitHub installation credential is not bound to pull request creation',
      403,
    );
  }
  return lease.token;
}

function parseBody(body) {
  if (body && typeof body === 'object' && !Buffer.isBuffer(body)) return body;
  const text = Buffer.isBuffer(body) ? body.toString('utf8') : String(body || '');
  if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES) {
    fail('github_response_too_large', 'GitHub response exceeded the configured limit', 502);
  }
  try {
    return JSON.parse(text);
  } catch {
    fail('github_invalid_response', 'GitHub returned an invalid pull request response', 502);
  }
}

function projectResponse(body, owner, repo, head, base, draft) {
  if (
    !body ||
    typeof body !== 'object' ||
    !Number.isSafeInteger(body.number) ||
    body.number < 1 ||
    body.state !== 'open' ||
    body.draft !== draft ||
    body.head?.ref !== head ||
    body.base?.ref !== base
  ) {
    fail('github_invalid_response', 'GitHub returned an invalid pull request response', 502);
  }
  return {
    number: body.number,
    state: 'open',
    draft,
    head,
    base,
    url: `https://github.com/${owner}/${repo}/pull/${body.number}`,
  };
}

export function createGitHubPullRequestCreateAdapter({
  request,
  tokenProvider,
  now = () => Date.now(),
} = {}) {
  if (typeof request !== 'function')
    throw new TypeError('GitHub pull request adapter requires a pinned request transport');
  if (typeof tokenProvider !== 'function')
    throw new TypeError('GitHub pull request adapter requires an installation token provider');
  if (typeof now !== 'function')
    throw new TypeError('GitHub pull request adapter requires a clock');

  return async function githubPullRequestCreate(parameters, context = {}) {
    const owner = parameters?.owner;
    const repo = parameters?.repo;
    const repository = `${owner}/${repo}`;
    if (!OWNER_RE.test(owner || '') || !REPO_RE.test(repo || '')) {
      fail('github_invalid_repository', 'GitHub repository identity is invalid');
    }
    if (
      typeof parameters.resource_ref !== 'string' ||
      parameters.resource_ref.toLowerCase() !== repository.toLowerCase()
    ) {
      fail(
        'github_target_mismatch',
        'GitHub repository target does not match typed parameters',
        403,
      );
    }
    const title = boundedText(parameters.title, 'title', 256);
    const body = boundedText(parameters.body, 'body', 10_000, { optional: true, multiline: true });
    const head = parameters.head;
    const base = parameters.base;
    const draft = parameters.draft === undefined ? true : parameters.draft;
    if (!validRef(head) || !validRef(base) || head === base || typeof draft !== 'boolean') {
      fail('github_invalid_pull_request', 'GitHub pull request branch binding is invalid');
    }
    if (
      context.execution?.tool !== TOOL ||
      context.execution?.target?.toLowerCase() !== repository.toLowerCase() ||
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
        repository,
        execution_id: context.execution.execution_id,
        request_binding: context.execution.request_binding,
        signal: context.signal,
      });
    } catch {
      fail('github_credential_unavailable', 'GitHub installation credential is unavailable', 503);
    }
    const token = validateLease(lease, repository, now());
    const payload = { title, head, base, draft };
    if (body !== undefined) payload.body = body;

    let response;
    try {
      response = await request({
        origin: ORIGIN,
        method: 'POST',
        path: `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pulls`,
        headers: {
          Accept: 'application/vnd.github+json',
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
          'X-GitHub-Api-Version': API_VERSION,
          'User-Agent': `secret-broker/${BROKER_VERSION}`,
        },
        body: JSON.stringify(payload),
        max_response_bytes: MAX_RESPONSE_BYTES,
        redirect: 'manual',
        signal: context.signal,
      });
    } catch (error) {
      if (error instanceof V2Error) throw error;
      fail('github_unavailable', 'GitHub pull request request failed', 502);
    }
    if ([301, 302, 303, 307, 308].includes(response?.status)) {
      fail('github_redirect_denied', 'GitHub redirect was denied', 502);
    }
    if (response?.status === 401)
      fail('github_credential_rejected', 'GitHub installation credential was rejected', 502);
    if (response?.status === 403)
      fail('github_forbidden', 'GitHub App lacks pull request write permission', 403);
    if (response?.status === 404) fail('github_not_found', 'GitHub repository was not found', 404);
    if (response?.status === 422)
      fail('github_pull_request_rejected', 'GitHub rejected the pull request', 409);
    if (response?.status !== 201)
      fail('github_upstream_error', 'GitHub pull request creation failed', 502);
    return projectResponse(parseBody(response.body), owner, repo, head, base, draft);
  };
}

export const GITHUB_PULL_REQUEST_CREATE_CONTRACT = Object.freeze({
  tool: TOOL,
  origin: ORIGIN,
  method: 'POST',
  path_template: '/repos/{owner}/{repo}/pulls',
  api_version: API_VERSION,
  maximum_response_bytes: MAX_RESPONSE_BYTES,
  maximum_body_characters: 10_000,
  required_permission: 'pull_requests:write',
  default_draft: true,
  arbitrary_url: false,
  credential_export: false,
});
