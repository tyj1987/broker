import { V2Error } from '../lib/operations-v2.js';
import { redact } from '../lib/redact.js';

const TOOL = 'google_drive.document.read@1.0.0';
const ORIGIN = 'https://www.googleapis.com';
const SCOPE = 'https://www.googleapis.com/auth/drive.file';
const MIME_TYPE = 'text/plain';
const FILE_ID_RE = /^[A-Za-z0-9_-]{10,128}$/;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_TOKEN_TTL_MS = 300_000;
const FILTER_KEYS = new Set([
  'account_ref',
  'environment',
  'file_id',
  'classification',
  'content',
  'redactions',
]);

function fail(code, message, status = 400) {
  throw new V2Error(code, message, status);
}

function validateParameters(parameters) {
  if (
    !parameters ||
    typeof parameters !== 'object' ||
    Array.isArray(parameters) ||
    Object.keys(parameters).length !== 1 ||
    !Object.hasOwn(parameters, 'resource_ref')
  ) {
    fail('google_drive_invalid_request', 'Google Drive document read accepts only resource_ref');
  }
  if (typeof parameters.resource_ref !== 'string' || !FILE_ID_RE.test(parameters.resource_ref)) {
    fail('google_drive_invalid_file', 'Google Drive file reference is invalid');
  }
  return parameters.resource_ref;
}

function validateLease(lease, accountRef, environment, fileId, now) {
  if (
    !lease ||
    typeof lease.token !== 'string' ||
    lease.token.length < 8 ||
    lease.account_ref !== accountRef ||
    lease.environment !== environment ||
    lease.file_id !== fileId ||
    lease.scope !== SCOPE
  ) {
    fail('google_drive_credential_unavailable', 'Google Drive credential is unavailable', 503);
  }
  const expiresAt = Date.parse(lease.expires_at);
  if (!Number.isFinite(expiresAt) || expiresAt <= now || expiresAt > now + MAX_TOKEN_TTL_MS) {
    fail(
      'google_drive_credential_expiry_invalid',
      'Google Drive credential expiry is invalid',
      503,
    );
  }
  return lease.token;
}

function decodeText(body) {
  let encoded;
  try {
    encoded = Buffer.isBuffer(body)
      ? body
      : Buffer.from(typeof body === 'string' ? body : body || []);
  } catch {
    fail('google_drive_invalid_response', 'Google Drive returned invalid document bytes', 502);
  }
  if (encoded.byteLength > MAX_RESPONSE_BYTES) {
    fail(
      'google_drive_response_too_large',
      'Google Drive document exceeds the configured limit',
      502,
    );
  }
  const content = encoded.toString('utf8');
  if (content.includes('\u0000') || content.includes('\uFFFD')) {
    fail('google_drive_invalid_response', 'Google Drive returned invalid document text', 502);
  }
  return content;
}

function validateFiltered(result, accountRef, environment, fileId) {
  if (
    !result ||
    typeof result !== 'object' ||
    Array.isArray(result) ||
    Object.keys(result).some((key) => !FILTER_KEYS.has(key)) ||
    result.account_ref !== accountRef ||
    result.environment !== environment ||
    result.file_id !== fileId ||
    result.classification !== 'approved' ||
    typeof result.content !== 'string' ||
    !Number.isSafeInteger(result.redactions) ||
    result.redactions < 0
  ) {
    fail('google_drive_content_denied', 'Google Drive content was not approved for release', 403);
  }
  const content = redact(result.content);
  if (Buffer.byteLength(content, 'utf8') > MAX_RESPONSE_BYTES) {
    fail(
      'google_drive_filtered_response_too_large',
      'Filtered Google Drive content is too large',
      502,
    );
  }
  return {
    file_id: fileId,
    mime_type: MIME_TYPE,
    content,
    redactions: result.redactions + (content === result.content ? 0 : 1),
  };
}

export function createGoogleDriveDocumentReadAdapter({
  request,
  tokenProvider,
  contentFilter,
  now = Date.now,
} = {}) {
  if (typeof request !== 'function') {
    throw new TypeError('Google Drive adapter requires a pinned request transport');
  }
  if (typeof tokenProvider !== 'function') {
    throw new TypeError('Google Drive adapter requires a file-bound token provider');
  }
  if (typeof contentFilter !== 'function') {
    throw new TypeError('Google Drive adapter requires a content release filter');
  }
  if (typeof now !== 'function') throw new TypeError('Google Drive adapter requires a clock');

  return async function googleDriveDocumentRead(parameters, context = {}) {
    const fileId = validateParameters(parameters);
    if (
      context.execution?.tool !== TOOL ||
      context.execution?.target !== fileId ||
      context.execution?.environment !== context.environment
    ) {
      fail(
        'google_drive_execution_binding_mismatch',
        'Execution capability is not bound to this Google Drive file',
        403,
      );
    }
    if (typeof context.accountRef !== 'string' || !context.accountRef) {
      fail('google_drive_account_unavailable', 'Google Drive account binding is unavailable', 503);
    }

    let lease;
    try {
      lease = await tokenProvider({
        account_ref: context.accountRef,
        environment: context.environment,
        file_id: fileId,
        scope: SCOPE,
        signal: context.signal,
      });
    } catch {
      fail('google_drive_credential_unavailable', 'Google Drive credential is unavailable', 503);
    }
    const token = validateLease(lease, context.accountRef, context.environment, fileId, now());

    let response;
    try {
      response = await request({
        origin: ORIGIN,
        method: 'GET',
        path: `/drive/v3/files/${fileId}/export?mimeType=text%2Fplain`,
        headers: {
          Accept: MIME_TYPE,
          Authorization: `Bearer ${token}`,
        },
        max_response_bytes: MAX_RESPONSE_BYTES,
        redirect: 'manual',
        signal: context.signal,
      });
    } catch (error) {
      if (error instanceof V2Error) throw error;
      fail('google_drive_unavailable', 'Google Drive request failed', 502);
    }
    if ([301, 302, 303, 307, 308].includes(response?.status)) {
      fail('google_drive_redirect_denied', 'Google Drive redirect was denied', 502);
    }
    if (response?.status === 401) {
      fail('google_drive_credential_rejected', 'Google Drive credential was rejected', 502);
    }
    if (response?.status === 403) {
      fail('google_drive_forbidden', 'Google Drive file access was denied', 403);
    }
    if (response?.status === 404)
      fail('google_drive_not_found', 'Google Drive file was not found', 404);
    if (response?.status === 429)
      fail('google_drive_rate_limited', 'Google Drive rate limit was reached', 429);
    if (response?.status !== 200)
      fail('google_drive_upstream_error', 'Google Drive export failed', 502);
    const contentType = String(response.headers?.['content-type'] || '').toLowerCase();
    if (!contentType.startsWith(MIME_TYPE)) {
      fail(
        'google_drive_invalid_response',
        'Google Drive returned an unexpected content type',
        502,
      );
    }
    const rawContent = decodeText(response.body);

    let filtered;
    try {
      filtered = await contentFilter({
        account_ref: context.accountRef,
        environment: context.environment,
        file_id: fileId,
        mime_type: MIME_TYPE,
        content: rawContent,
        signal: context.signal,
      });
    } catch {
      fail(
        'google_drive_content_filter_unavailable',
        'Google Drive content filter is unavailable',
        503,
      );
    }
    return validateFiltered(filtered, context.accountRef, context.environment, fileId);
  };
}

export const GOOGLE_DRIVE_DOCUMENT_READ_CONTRACT = Object.freeze({
  tool: TOOL,
  origin: ORIGIN,
  method: 'GET',
  path_template: '/drive/v3/files/{file_id}/export?mimeType=text%2Fplain',
  scope: SCOPE,
  mime_type: MIME_TYPE,
  maximum_response_bytes: MAX_RESPONSE_BYTES,
  maximum_token_ttl_seconds: MAX_TOKEN_TTL_MS / 1000,
  content_filter_required: true,
});
