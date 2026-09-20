import { V2Error } from '../lib/operations-v2.js';
import { BROKER_VERSION } from '../version.js';

const ORIGIN = 'https://api.github.com';
const API_VERSION = '2026-03-10';
const MAX_RESPONSE_BYTES = 256 * 1024;
const MAX_TOKEN_TTL_MS = 60 * 60_000 + 30_000;
const CLIENT_ID_RE = /^[A-Za-z0-9._-]{3,128}$/;
const ACCOUNT_REF_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const ENVIRONMENT_RE = /^[a-z][a-z0-9_-]{0,31}$/;
const EXECUTION_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const REQUEST_BINDING_RE = /^[A-Za-z0-9_-]{43}$/;
const REPOSITORY_RE = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$/;
const PERMISSION_LEVELS = Object.freeze({
  actions: Object.freeze(['read']),
  contents: Object.freeze(['read']),
  deployments: Object.freeze(['read']),
  issues: Object.freeze(['read']),
  metadata: Object.freeze(['read']),
  pull_requests: Object.freeze(['read', 'write']),
});

function fail(code, message, status = 400) {
  throw new V2Error(code, message, status);
}

function encode(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function parseBody(body) {
  if (body && typeof body === 'object' && !Buffer.isBuffer(body)) return body;
  const text = Buffer.isBuffer(body) ? body.toString('utf8') : String(body || '');
  if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES) {
    fail(
      'github_token_response_too_large',
      'GitHub token response exceeded the configured limit',
      502,
    );
  }
  try {
    return JSON.parse(text);
  } catch {
    fail('github_token_invalid_response', 'GitHub returned an invalid token response', 502);
  }
}

function validateBinding(binding, request) {
  if (
    !binding ||
    typeof binding !== 'object' ||
    binding.account_ref !== request.account_ref ||
    binding.environment !== request.environment ||
    !CLIENT_ID_RE.test(binding.client_id || '') ||
    !Number.isSafeInteger(binding.installation_id) ||
    binding.installation_id < 1 ||
    !Array.isArray(binding.repositories) ||
    !binding.repositories.some(
      (item) => typeof item === 'string' && item.toLowerCase() === request.repository.toLowerCase(),
    )
  ) {
    fail('github_app_binding_unavailable', 'GitHub App account binding is unavailable', 503);
  }
  return binding;
}

function validateRequest(input) {
  if (
    !ACCOUNT_REF_RE.test(input?.account_ref || '') ||
    !ENVIRONMENT_RE.test(input?.environment || '') ||
    !EXECUTION_ID_RE.test(input?.execution_id || '') ||
    !REQUEST_BINDING_RE.test(input?.request_binding || '') ||
    !REPOSITORY_RE.test(input?.repository || '') ||
    input.repository.toLowerCase() !== `${input.owner}/${input.repo}`.toLowerCase()
  ) {
    fail('github_token_request_invalid', 'GitHub token request binding is invalid');
  }
}

function validateSignature(signature) {
  if (
    !(signature instanceof Uint8Array) ||
    signature.byteLength < 256 ||
    signature.byteLength > 1024
  ) {
    fail('github_app_signing_failed', 'GitHub App signing capability failed', 503);
  }
  return Buffer.from(signature).toString('base64url');
}

function normalizePermissions(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('GitHub token provider permissions must be a non-empty object');
  }
  const entries = Object.entries(value);
  if (entries.length < 1)
    throw new TypeError('GitHub token provider permissions must be a non-empty object');
  if (
    entries.some(
      ([key, level]) =>
        !Object.hasOwn(PERMISSION_LEVELS, key) || !PERMISSION_LEVELS[key].includes(level),
    )
  ) {
    throw new TypeError('GitHub token provider permissions exceed the supported operation set');
  }
  return Object.freeze(
    Object.fromEntries(entries.sort(([left], [right]) => left.localeCompare(right))),
  );
}

function validateTokenResponse(response, repository, now, requiredPermissions) {
  if (response.status !== 201)
    fail('github_token_request_failed', 'GitHub installation token request failed', 502);
  const body = parseBody(response.body);
  const expiresAt = Date.parse(body?.expires_at);
  const repositories = body?.repositories;
  const permissions = body?.permissions;
  if (
    typeof body.token !== 'string' ||
    body.token.length < 1 ||
    body.token.length > 4096 ||
    !Number.isFinite(expiresAt) ||
    expiresAt <= now ||
    expiresAt - now > MAX_TOKEN_TTL_MS ||
    !Array.isArray(repositories) ||
    repositories.length !== 1 ||
    repositories[0]?.full_name?.toLowerCase() !== repository.toLowerCase() ||
    !permissions ||
    typeof permissions !== 'object' ||
    Array.isArray(permissions) ||
    JSON.stringify(
      Object.fromEntries(
        Object.entries(permissions).sort(([left], [right]) => left.localeCompare(right)),
      ),
    ) !== JSON.stringify(requiredPermissions)
  ) {
    fail(
      'github_token_scope_mismatch',
      'GitHub installation token scope could not be verified',
      502,
    );
  }
  return {
    token: body.token,
    repository,
    expires_at: body.expires_at,
    permissions: { ...requiredPermissions },
  };
}

export function createGitHubAppInstallationTokenProvider({
  request,
  signer,
  accountResolver,
  now = () => Date.now(),
  permissions = { metadata: 'read' },
} = {}) {
  if (typeof request !== 'function')
    throw new TypeError('GitHub token provider requires a pinned request transport');
  if (typeof signer !== 'function')
    throw new TypeError('GitHub token provider requires a non-exportable signing capability');
  if (typeof accountResolver !== 'function')
    throw new TypeError('GitHub token provider requires an account binding resolver');
  const requiredPermissions = normalizePermissions(permissions);

  return async function provideInstallationToken(input) {
    validateRequest(input);
    let binding;
    try {
      binding = validateBinding(
        await accountResolver({
          account_ref: input.account_ref,
          environment: input.environment,
          repository: input.repository,
          signal: input.signal,
        }),
        input,
      );
    } catch {
      fail('github_app_binding_unavailable', 'GitHub App account binding is unavailable', 503);
    }

    const issuedAt = Math.floor(now() / 1000) - 60;
    const signingInput = `${encode({ alg: 'RS256', typ: 'JWT' })}.${encode({
      iat: issuedAt,
      exp: issuedAt + 600,
      iss: binding.client_id,
    })}`;
    let signature;
    try {
      signature = validateSignature(
        await signer({
          algorithm: 'RS256',
          signing_input: signingInput,
          account_ref: input.account_ref,
          environment: input.environment,
          client_id: binding.client_id,
          execution_id: input.execution_id,
          request_binding: input.request_binding,
          signal: input.signal,
        }),
      );
    } catch {
      fail('github_app_signing_failed', 'GitHub App signing capability failed', 503);
    }
    const jwt = `${signingInput}.${signature}`;

    let response;
    try {
      response = await request({
        origin: ORIGIN,
        method: 'POST',
        path: `/app/installations/${binding.installation_id}/access_tokens`,
        headers: {
          Accept: 'application/vnd.github+json',
          Authorization: `Bearer ${jwt}`,
          'Content-Type': 'application/json',
          'X-GitHub-Api-Version': API_VERSION,
          'User-Agent': `secret-broker/${BROKER_VERSION}`,
        },
        body: JSON.stringify({ repositories: [input.repo], permissions: requiredPermissions }),
        max_response_bytes: MAX_RESPONSE_BYTES,
        redirect: 'manual',
        signal: input.signal,
      });
    } catch (error) {
      if (error instanceof V2Error) throw error;
      fail('github_token_unavailable', 'GitHub installation token service is unavailable', 502);
    }
    if ([301, 302, 303, 307, 308].includes(response?.status)) {
      fail('github_token_redirect_denied', 'GitHub installation token redirect was denied', 502);
    }
    return validateTokenResponse(response || {}, input.repository, now(), requiredPermissions);
  };
}

export const GITHUB_APP_TOKEN_CONTRACT = Object.freeze({
  origin: ORIGIN,
  method: 'POST',
  api_version: API_VERSION,
  jwt_algorithm: 'RS256',
  jwt_maximum_ttl_seconds: 600,
  credential_maximum_ttl_seconds: 3600,
  maximum_response_bytes: MAX_RESPONSE_BYTES,
  permissions: Object.freeze({ metadata: 'read' }),
});
