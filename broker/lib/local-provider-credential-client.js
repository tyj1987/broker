import { lstat } from 'node:fs/promises';
import net from 'node:net';

const SOCKET_DIRECTORY = '/run/secret-broker-credentials';
const SOCKETS = Object.freeze({
  cloudflare: `${SOCKET_DIRECTORY}/cloudflare.sock`,
  deepseek: `${SOCKET_DIRECTORY}/deepseek.sock`,
  docker: `${SOCKET_DIRECTORY}/docker.sock`,
  openai: `${SOCKET_DIRECTORY}/openai.sock`,
});
const OPERATIONS = Object.freeze({
  cloudflare: Object.freeze(['zones.list', 'dns.records.list']),
  deepseek: Object.freeze(['models.list']),
  docker: Object.freeze(['repository.tags.list']),
  openai: Object.freeze(['models.list']),
});
const MAX_REQUEST_BYTES = 4 * 1024;
const MAX_RESPONSE_BYTES = 8 * 1024;
const MAX_LEASE_TTL_MS = 5 * 60_000;
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const ENVIRONMENT_RE = /^[a-z][a-z0-9_-]{0,31}$/;
const EXECUTION_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const REQUEST_BINDING_RE = /^[A-Za-z0-9_-]{43}$/;
const CLOUDFLARE_ACCOUNT_ID_RE = /^[a-f0-9]{32}$/;
const DOCKER_COMPONENT_RE = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;

export class LocalProviderCredentialError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'LocalProviderCredentialError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new LocalProviderCredentialError(code, message);
}

function validResource(provider, operationId, value) {
  if (!OPERATIONS[provider]?.includes(operationId)) return false;
  if (provider === 'cloudflare') return CLOUDFLARE_ACCOUNT_ID_RE.test(value || '');
  if (provider === 'deepseek') return value === 'model-catalog';
  if (provider === 'openai') return ID_RE.test(value || '');
  if (provider === 'docker') {
    if (typeof value !== 'string' || value.length >= 256) return false;
    const parts = value.split('/');
    return parts.length === 2 && parts.every((part) => DOCKER_COMPONENT_RE.test(part));
  }
  return false;
}

function validateRequest(provider, input) {
  if (
    !input ||
    typeof input !== 'object' ||
    Array.isArray(input) ||
    Object.keys(input).some(
      (key) =>
        ![
          'operation_id',
          'account_ref',
          'environment',
          'resource_ref',
          'execution_id',
          'request_binding',
          'signal',
        ].includes(key),
    ) ||
    !ID_RE.test(input.operation_id || '') ||
    !ID_RE.test(input.account_ref || '') ||
    !ENVIRONMENT_RE.test(input.environment || '') ||
    !validResource(provider, input.operation_id, input.resource_ref) ||
    !EXECUTION_ID_RE.test(input.execution_id || '') ||
    !REQUEST_BINDING_RE.test(input.request_binding || '') ||
    (input.signal !== undefined && !(input.signal instanceof AbortSignal)) ||
    !Object.hasOwn(SOCKETS, provider)
  ) {
    fail('credential_request_invalid', 'Local provider credential request is invalid');
  }
}

function encodeRequest(provider, input) {
  const payload = `${JSON.stringify({
    version: 2,
    provider,
    operation_id: input.operation_id,
    account_ref: input.account_ref,
    environment: input.environment,
    resource_ref: input.resource_ref,
    execution_id: input.execution_id,
    request_binding: input.request_binding,
  })}\n`;
  if (Buffer.byteLength(payload) > MAX_REQUEST_BYTES) {
    fail('credential_request_invalid', 'Local provider credential request is invalid');
  }
  return payload;
}

function decodeResponse(provider, input, value, now) {
  let document;
  try {
    document = JSON.parse(value);
  } catch {
    fail('credential_response_invalid', 'Local provider credential response is invalid');
  }
  const allowed = [
    'version',
    'provider',
    'operation_id',
    'account_ref',
    'environment',
    'resource_ref',
    'execution_id',
    'request_binding',
    'token',
    'expires_at',
  ];
  const expiresAt = Date.parse(document?.expires_at);
  if (
    !document ||
    typeof document !== 'object' ||
    Array.isArray(document) ||
    Object.keys(document).some((key) => !allowed.includes(key)) ||
    document.version !== 2 ||
    document.provider !== provider ||
    document.operation_id !== input.operation_id ||
    document.account_ref !== input.account_ref ||
    document.environment !== input.environment ||
    document.resource_ref !== input.resource_ref ||
    document.execution_id !== input.execution_id ||
    document.request_binding !== input.request_binding ||
    typeof document.token !== 'string' ||
    document.token.length < 8 ||
    document.token.length > 4096 ||
    !/^[\x21-\x7e]+$/.test(document.token) ||
    !Number.isFinite(expiresAt) ||
    expiresAt <= now ||
    expiresAt > now + MAX_LEASE_TTL_MS
  ) {
    fail('credential_response_invalid', 'Local provider credential response is invalid');
  }
  return Object.freeze({ token: document.token, expires_at: document.expires_at });
}

export function createLocalProviderCredentialClient({
  provider,
  connect = net.createConnection,
  stat = lstat,
  timeoutMs = 2_000,
  now = Date.now,
  processUid = typeof process.getuid === 'function' ? process.getuid() : null,
  processGroups = typeof process.getgroups === 'function' ? process.getgroups() : [],
} = {}) {
  if (!Object.hasOwn(SOCKETS, provider)) {
    throw new TypeError('Local provider credential provider is unsupported');
  }
  if (typeof connect !== 'function' || typeof stat !== 'function' || typeof now !== 'function') {
    throw new TypeError('Local provider credential dependencies are invalid');
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10_000) {
    throw new TypeError('Local provider credential timeout is invalid');
  }
  if (processUid !== null && (!Number.isSafeInteger(processUid) || processUid < 0)) {
    throw new TypeError('Local provider credential process identity is invalid');
  }
  if (
    !Array.isArray(processGroups) ||
    processGroups.some((group) => !Number.isSafeInteger(group) || group < 0)
  ) {
    throw new TypeError('Local provider credential process groups are invalid');
  }
  const socketPath = SOCKETS[provider];

  async function probe() {
    let directoryMetadata;
    let metadata;
    try {
      directoryMetadata = await stat(SOCKET_DIRECTORY);
      metadata = await stat(socketPath);
    } catch {
      fail('credential_provider_unavailable', 'Local provider credential service is unavailable');
    }
    if (
      !directoryMetadata?.isDirectory?.() ||
      directoryMetadata.isSymbolicLink?.() === true ||
      (directoryMetadata.mode & 0o022) !== 0 ||
      !Number.isSafeInteger(processUid) ||
      directoryMetadata.uid === processUid ||
      !processGroups.includes(directoryMetadata.gid) ||
      (directoryMetadata.mode & 0o010) === 0 ||
      !metadata?.isSocket?.() ||
      metadata.isSymbolicLink?.() === true ||
      (metadata.mode & 0o007) !== 0 ||
      metadata.uid !== directoryMetadata.uid ||
      metadata.uid === processUid ||
      metadata.gid !== directoryMetadata.gid ||
      !processGroups.includes(metadata.gid) ||
      (metadata.mode & 0o060) !== 0o060
    ) {
      fail('credential_provider_boundary_invalid', 'Local provider credential boundary is invalid');
    }
    return true;
  }

  async function lease(input) {
    validateRequest(provider, input);
    if (input.signal?.aborted)
      fail('credential_request_aborted', 'Local provider credential request was aborted');
    await probe();
    const payload = encodeRequest(provider, input);
    return new Promise((resolve, reject) => {
      let socket;
      let settled = false;
      let size = 0;
      const chunks = [];
      const finish = (handler, value) => {
        if (settled) return;
        settled = true;
        input.signal?.removeEventListener('abort', abort);
        socket?.destroy?.();
        handler(value);
      };
      const rejectSafe = (code, message) =>
        finish(reject, new LocalProviderCredentialError(code, message));
      const abort = () =>
        rejectSafe('credential_request_aborted', 'Local provider credential request was aborted');
      try {
        socket = connect({ path: socketPath }, () => socket.end(payload));
        socket.setTimeout(timeoutMs, () =>
          rejectSafe('credential_provider_timeout', 'Local provider credential request timed out'),
        );
        socket.on('data', (chunk) => {
          if (settled) return;
          const encoded = Buffer.from(chunk);
          size += encoded.byteLength;
          if (size > MAX_RESPONSE_BYTES) {
            rejectSafe(
              'credential_response_too_large',
              'Local provider credential response exceeded the limit',
            );
            return;
          }
          chunks.push(encoded);
        });
        socket.on('end', () => {
          if (settled) return;
          try {
            finish(
              resolve,
              decodeResponse(provider, input, Buffer.concat(chunks).toString('utf8').trim(), now()),
            );
          } catch (error) {
            finish(
              reject,
              error instanceof LocalProviderCredentialError
                ? error
                : new LocalProviderCredentialError(
                    'credential_response_invalid',
                    'Local provider credential response is invalid',
                  ),
            );
          }
        });
        socket.on('error', () =>
          rejectSafe(
            'credential_provider_unavailable',
            'Local provider credential service is unavailable',
          ),
        );
        input.signal?.addEventListener('abort', abort, { once: true });
        if (input.signal?.aborted) abort();
      } catch {
        rejectSafe(
          'credential_provider_unavailable',
          'Local provider credential service is unavailable',
        );
      }
    });
  }

  return Object.freeze({ provider, socketPath, probe, lease });
}

export const LOCAL_PROVIDER_CREDENTIAL_CONTRACT = Object.freeze({
  socket_directory: SOCKET_DIRECTORY,
  socket_paths: SOCKETS,
  allowed_operations: OPERATIONS,
  protocol_version: 2,
  maximum_request_bytes: MAX_REQUEST_BYTES,
  maximum_response_bytes: MAX_RESPONSE_BYTES,
  maximum_lease_ttl_seconds: MAX_LEASE_TTL_MS / 1000,
  secret_available_to_agent: false,
});
