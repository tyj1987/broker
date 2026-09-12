import { createHash } from 'node:crypto';

import { V2Error } from '../lib/operations-v2.js';
import { BROKER_VERSION } from '../version.js';

const ORIGIN = 'https://api.github.com';
const API_VERSION = '2026-03-10';
const MAX_RESPONSE_BYTES = 256 * 1024;
const ACCOUNT_REF_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const CLIENT_ID_RE = /^[A-Za-z0-9._-]{3,128}$/;
const REPOSITORY_RE = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$/;
const EXECUTION_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const REQUEST_BINDING_RE = /^[A-Za-z0-9_-]{43}$/;
const LOGIN_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,98}[A-Za-z0-9])?$/;
const TOOL = 'github.repository.read@1.0.0';

function fail(code, message, status = 400) {
  throw new V2Error(code, message, status);
}

function encode(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function digest(value) {
  return createHash('sha256').update(String(value), 'utf8').digest('hex');
}

function parseBody(body) {
  if (body && typeof body === 'object' && !Buffer.isBuffer(body)) return body;
  const text = Buffer.isBuffer(body) ? body.toString('utf8') : String(body || '');
  if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES) {
    fail(
      'github_authority_response_too_large',
      'GitHub authority response exceeded the limit',
      502,
    );
  }
  try {
    return JSON.parse(text);
  } catch {
    fail('github_authority_invalid_response', 'GitHub returned an invalid authority response', 502);
  }
}

function projectAuthority(body, installationId) {
  if (
    !body ||
    !Number.isSafeInteger(body.id) ||
    body.id !== installationId ||
    !Number.isSafeInteger(body.account?.id) ||
    body.account.id < 1 ||
    !LOGIN_RE.test(body.account.login || '') ||
    !['User', 'Organization', 'Enterprise'].includes(body.target_type)
  ) {
    fail(
      'github_authority_invalid_response',
      'GitHub returned an invalid authority projection',
      502,
    );
  }
  return Object.freeze({
    installation_id_sha256: digest(body.id),
    account_id_sha256: digest(body.account.id),
    account_login_sha256: digest(body.account.login.toLowerCase()),
    target_type: body.target_type,
  });
}

export function createGitHubInstallationAuthorityProvider({
  request,
  signer,
  accountResolver,
  now = () => Date.now(),
} = {}) {
  if (typeof request !== 'function')
    throw new TypeError('GitHub authority provider requires transport');
  if (typeof signer !== 'function')
    throw new TypeError('GitHub authority provider requires signer');
  if (typeof accountResolver !== 'function')
    throw new TypeError('GitHub authority provider requires account resolver');
  if (typeof now !== 'function') throw new TypeError('GitHub authority provider requires clock');

  return async function readInstallationAuthority(input) {
    if (
      !ACCOUNT_REF_RE.test(input?.account_ref || '') ||
      input?.tool !== TOOL ||
      input?.target?.toLowerCase() !== input?.repository?.toLowerCase() ||
      input?.resource_ref?.toLowerCase() !== input?.repository?.toLowerCase() ||
      input?.execution_environment !== input?.environment ||
      !REPOSITORY_RE.test(input?.repository || '') ||
      !EXECUTION_ID_RE.test(input?.execution_id || '') ||
      !REQUEST_BINDING_RE.test(input?.request_binding || '')
    ) {
      fail('github_authority_request_invalid', 'GitHub authority request binding is invalid');
    }
    let binding;
    try {
      binding = await accountResolver({
        account_ref: input.account_ref,
        environment: input.environment,
        repository: input.repository,
        signal: input.signal,
      });
    } catch {
      fail('github_authority_binding_unavailable', 'GitHub authority binding is unavailable', 503);
    }
    if (
      binding?.account_ref !== input.account_ref ||
      binding?.environment !== input.environment ||
      !CLIENT_ID_RE.test(binding?.client_id || '') ||
      !Number.isSafeInteger(binding?.installation_id) ||
      binding.installation_id < 1 ||
      !binding.repositories?.some(
        (repository) => repository.toLowerCase() === input.repository.toLowerCase(),
      )
    ) {
      fail('github_authority_binding_unavailable', 'GitHub authority binding is unavailable', 503);
    }
    const issuedAt = Math.floor(now() / 1000) - 60;
    const signingInput = `${encode({ alg: 'RS256', typ: 'JWT' })}.${encode({
      iat: issuedAt,
      exp: issuedAt + 600,
      iss: binding.client_id,
    })}`;
    let signature;
    try {
      signature = await signer({
        algorithm: 'RS256',
        signing_input: signingInput,
        account_ref: input.account_ref,
        environment: input.environment,
        client_id: binding.client_id,
        execution_id: input.execution_id,
        request_binding: input.request_binding,
        signal: input.signal,
      });
    } catch {
      fail('github_authority_signing_failed', 'GitHub authority signing failed', 503);
    }
    if (
      !(signature instanceof Uint8Array) ||
      signature.byteLength < 256 ||
      signature.byteLength > 1024
    ) {
      fail('github_authority_signing_failed', 'GitHub authority signing failed', 503);
    }
    let response;
    try {
      response = await request({
        origin: ORIGIN,
        method: 'GET',
        path: `/app/installations/${binding.installation_id}`,
        headers: {
          Accept: 'application/vnd.github+json',
          Authorization: `Bearer ${signingInput}.${Buffer.from(signature).toString('base64url')}`,
          'X-GitHub-Api-Version': API_VERSION,
          'User-Agent': `secret-broker/${BROKER_VERSION}`,
        },
        max_response_bytes: MAX_RESPONSE_BYTES,
        redirect: 'manual',
        signal: input.signal,
      });
    } catch (error) {
      if (error instanceof V2Error) throw error;
      fail('github_authority_unavailable', 'GitHub authority request failed', 502);
    }
    if ([301, 302, 303, 307, 308].includes(response?.status))
      fail('github_authority_redirect_denied', 'GitHub authority redirect was denied', 502);
    if (response?.status === 401)
      fail('github_authority_credential_rejected', 'GitHub App credential was rejected', 502);
    if (response?.status === 404)
      fail('github_authority_not_found', 'GitHub installation was not found', 404);
    if (response?.status !== 200)
      fail('github_authority_upstream_error', 'GitHub authority request failed', 502);
    return Object.freeze({
      authority: projectAuthority(parseBody(response.body), binding.installation_id),
      binding: Object.freeze({
        account_ref: binding.account_ref,
        environment: binding.environment,
        client_id: binding.client_id,
        installation_id: binding.installation_id,
        repositories: Object.freeze([...binding.repositories]),
      }),
    });
  };
}

export const GITHUB_INSTALLATION_AUTHORITY_CONTRACT = Object.freeze({
  origin: ORIGIN,
  method: 'GET',
  path_template: '/app/installations/{installation_id}',
  api_version: API_VERSION,
  maximum_response_bytes: MAX_RESPONSE_BYTES,
  output_contains_identifiers: false,
});
