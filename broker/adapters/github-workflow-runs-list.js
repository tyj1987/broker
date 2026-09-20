import { V2Error } from '../lib/operations-v2.js';
import { BROKER_VERSION } from '../version.js';

const TOOL = 'github.workflow-runs.list@1.0.0';
const ORIGIN = 'https://api.github.com';
const API_VERSION = '2026-03-10';
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_TOKEN_TTL_MS = 60 * 60_000 + 30_000;
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const REPO_RE = /^(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$/;
const EXECUTION_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const REQUEST_BINDING_RE = /^[A-Za-z0-9_-]{43}$/;
const SHA_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i;
const LOGIN_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const EVENT_RE = /^[a-z][a-z0-9_]{0,63}$/;
const UNSAFE_TEXT_RE = /[\u0000-\u001f\u007f]/;
const FILTER_STATUSES = new Set([
  'completed',
  'action_required',
  'cancelled',
  'failure',
  'neutral',
  'skipped',
  'stale',
  'success',
  'timed_out',
  'in_progress',
  'queued',
  'requested',
  'waiting',
  'pending',
]);
const RUN_STATUSES = new Set([
  'completed',
  'in_progress',
  'queued',
  'requested',
  'waiting',
  'pending',
]);
const CONCLUSIONS = new Set([
  'action_required',
  'cancelled',
  'failure',
  'neutral',
  'skipped',
  'stale',
  'success',
  'timed_out',
  'startup_failure',
]);

function fail(code, message, status = 400) {
  throw new V2Error(code, message, status);
}

function boundedInteger(value, fallback, minimum, maximum, field) {
  const selected = value === undefined ? fallback : value;
  if (!Number.isSafeInteger(selected) || selected < minimum || selected > maximum) {
    fail('github_invalid_pagination', `${field} is invalid`);
  }
  return selected;
}

function optionalString(value, field, pattern, maximum = 255) {
  if (value === undefined) return undefined;
  if (
    typeof value !== 'string' ||
    value.length < 1 ||
    value.length > maximum ||
    UNSAFE_TEXT_RE.test(value) ||
    (pattern && !pattern.test(value))
  ) {
    fail('github_invalid_filter', `${field} is invalid`);
  }
  return value;
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
  if (
    !lease ||
    typeof lease !== 'object' ||
    typeof lease.token !== 'string' ||
    lease.token.length < 1 ||
    lease.token.length > 4096
  ) {
    fail('github_credential_unavailable', 'GitHub installation credential is unavailable', 503);
  }
  if (
    typeof lease.repository !== 'string' ||
    lease.repository.toLowerCase() !== expectedRepository.toLowerCase() ||
    !lease.permissions ||
    lease.permissions.actions !== 'read' ||
    Object.keys(lease.permissions).some((key) => key !== 'actions')
  ) {
    fail('github_credential_scope_mismatch', 'GitHub credential is not bound to actions read', 403);
  }
  const expiresAt = Date.parse(lease.expires_at);
  if (!Number.isFinite(expiresAt) || expiresAt <= now || expiresAt - now > MAX_TOKEN_TTL_MS) {
    fail('github_credential_expired', 'GitHub installation credential lifetime is invalid', 503);
  }
  return lease.token;
}

function safeTimestamp(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) {
    fail('github_invalid_response', 'GitHub returned an invalid workflow run projection', 502);
  }
  const timestamp = Date.parse(value);
  const year = Number(value.slice(0, 4));
  if (
    !Number.isFinite(timestamp) ||
    year < 1970 ||
    year > 2099 ||
    new Date(timestamp).toISOString().replace('.000Z', 'Z') !== value
  ) {
    fail('github_invalid_response', 'GitHub returned an invalid workflow run projection', 502);
  }
  return value;
}

function safeNullableText(value, maximum) {
  if (value === null) return null;
  if (
    typeof value !== 'string' ||
    value.length < 1 ||
    value.length > maximum ||
    UNSAFE_TEXT_RE.test(value)
  ) {
    fail('github_invalid_response', 'GitHub returned an invalid workflow run projection', 502);
  }
  return value;
}

function projectRuns(body, maximumItems) {
  if (
    !body ||
    typeof body !== 'object' ||
    Array.isArray(body) ||
    !Number.isSafeInteger(body.total_count) ||
    body.total_count < 0 ||
    !Array.isArray(body.workflow_runs) ||
    body.workflow_runs.length > maximumItems
  ) {
    fail('github_invalid_response', 'GitHub returned an invalid workflow run collection', 502);
  }
  const workflowRuns = body.workflow_runs.map((item) => {
    if (
      !item ||
      typeof item !== 'object' ||
      !Number.isSafeInteger(item.id) ||
      item.id < 1 ||
      !Number.isSafeInteger(item.run_number) ||
      item.run_number < 1 ||
      !Number.isSafeInteger(item.run_attempt) ||
      item.run_attempt < 1 ||
      typeof item.name !== 'string' ||
      item.name.length < 1 ||
      item.name.length > 255 ||
      UNSAFE_TEXT_RE.test(item.name) ||
      !EVENT_RE.test(item.event || '') ||
      !RUN_STATUSES.has(item.status) ||
      (item.conclusion !== null && !CONCLUSIONS.has(item.conclusion)) ||
      !SHA_RE.test(item.head_sha || '')
    ) {
      fail('github_invalid_response', 'GitHub returned an invalid workflow run projection', 502);
    }
    return {
      id: item.id,
      name: item.name,
      content_trust: 'untrusted_external',
      event: item.event,
      status: item.status,
      conclusion: item.conclusion,
      head_branch: safeNullableText(item.head_branch, 255),
      head_sha: item.head_sha,
      run_number: item.run_number,
      run_attempt: item.run_attempt,
      created_at: safeTimestamp(item.created_at),
      updated_at: safeTimestamp(item.updated_at),
    };
  });
  return { totalCount: body.total_count, workflowRuns };
}

export function createGitHubWorkflowRunsListAdapter({
  request,
  tokenProvider,
  now = () => Date.now(),
} = {}) {
  if (typeof request !== 'function')
    throw new TypeError('GitHub workflow runs adapter requires a pinned request transport');
  if (typeof tokenProvider !== 'function')
    throw new TypeError('GitHub workflow runs adapter requires an installation token provider');

  return async function githubWorkflowRunsList(parameters, context = {}) {
    const owner = parameters?.owner;
    const repo = parameters?.repo;
    const target = `${owner}/${repo}`;
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
    const actor = optionalString(parameters.actor, 'actor', LOGIN_RE, 39);
    const branch = optionalString(parameters.branch, 'branch', null, 255);
    const event = optionalString(parameters.event, 'event', EVENT_RE, 64);
    const headSha = optionalString(parameters.head_sha, 'head_sha', SHA_RE, 64);
    const status = parameters.status === undefined ? undefined : parameters.status;
    if (status !== undefined && !FILTER_STATUSES.has(status))
      fail('github_invalid_filter', 'status is invalid');
    if (
      parameters.exclude_pull_requests !== undefined &&
      typeof parameters.exclude_pull_requests !== 'boolean'
    ) {
      fail('github_invalid_filter', 'exclude_pull_requests is invalid');
    }
    const checkSuiteId =
      parameters.check_suite_id === undefined ? undefined : parameters.check_suite_id;
    if (checkSuiteId !== undefined && (!Number.isSafeInteger(checkSuiteId) || checkSuiteId < 1)) {
      fail('github_invalid_filter', 'check_suite_id is invalid');
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
    for (const [key, value] of Object.entries({
      actor,
      branch,
      event,
      status,
      head_sha: headSha,
    })) {
      if (value !== undefined) query.set(key, value);
    }
    if (parameters.exclude_pull_requests !== undefined)
      query.set('exclude_pull_requests', String(parameters.exclude_pull_requests));
    if (checkSuiteId !== undefined) query.set('check_suite_id', String(checkSuiteId));

    let response;
    try {
      response = await request({
        origin: ORIGIN,
        method: 'GET',
        path: `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/actions/runs?${query}`,
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
    if ([301, 302, 303, 307, 308].includes(response?.status))
      fail('github_redirect_denied', 'GitHub redirect was denied', 502);
    if (response?.status === 401)
      fail('github_credential_rejected', 'GitHub installation credential was rejected', 502);
    if (response?.status === 403)
      fail('github_forbidden', 'GitHub App lacks actions read permission', 403);
    if (response?.status === 404) fail('github_not_found', 'GitHub repository was not found', 404);
    if (response?.status === 400 || response?.status === 422)
      fail('github_filter_rejected', 'GitHub rejected the workflow run filters', 400);
    if (response?.status !== 200)
      fail('github_upstream_error', 'GitHub workflow runs request failed', 502);
    const { totalCount, workflowRuns } = projectRuns(parseJsonBody(response.body), perPage);
    return {
      workflow_runs: workflowRuns,
      total_count: totalCount,
      page,
      per_page: perPage,
      has_more: page * perPage < totalCount,
    };
  };
}

export const GITHUB_WORKFLOW_RUNS_LIST_CONTRACT = Object.freeze({
  tool: TOOL,
  origin: ORIGIN,
  method: 'GET',
  path_template: '/repos/{owner}/{repo}/actions/runs',
  api_version: API_VERSION,
  maximum_response_bytes: MAX_RESPONSE_BYTES,
  maximum_page_size: 100,
  credential_maximum_ttl_seconds: 3600,
  required_permission: 'actions:read',
  output_content_trust: 'untrusted_external',
  output_excludes: Object.freeze([
    'pull_requests',
    'jobs',
    'logs',
    'artifacts',
    'authorization',
    'token',
  ]),
});
