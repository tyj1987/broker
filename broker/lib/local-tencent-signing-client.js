import { lstat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import net from 'node:net';

const SOCKET_DIRECTORY = '/run/secret-broker-signer';
const SOCKET_PATH = `${SOCKET_DIRECTORY}/tencent.sock`;
const MAX_REQUEST_BYTES = 16 * 1024;
const MAX_RESPONSE_BYTES = 16 * 1024;
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const ENVIRONMENT_RE = /^[a-z][a-z0-9_-]{0,31}$/;
const REGION_RE = /^[a-z0-9]+(?:-[a-z0-9]+){1,4}$/;
const EXECUTION_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const REQUEST_BINDING_RE = /^[A-Za-z0-9_-]{43}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;

export class LocalTencentSigningError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'LocalTencentSigningError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new LocalTencentSigningError(code, message);
}

function validateInput(input) {
  let payload;
  try {
    payload = JSON.parse(input?.payload);
  } catch {
    fail('tencent_signing_request_invalid', 'Local Tencent Cloud signing request is invalid');
  }
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
          'region',
          'execution_id',
          'request_binding',
          'method',
          'path',
          'payload',
          'payload_sha256',
          'signal',
        ].includes(key),
    ) ||
    input.operation_id !== 'cvm.instances.list' ||
    !ID_RE.test(input.account_ref || '') ||
    !ENVIRONMENT_RE.test(input.environment || '') ||
    !ID_RE.test(input.resource_ref || '') ||
    !REGION_RE.test(input.region || '') ||
    !EXECUTION_ID_RE.test(input.execution_id || '') ||
    !REQUEST_BINDING_RE.test(input.request_binding || '') ||
    input.method !== 'POST' ||
    input.path !== '/' ||
    !SHA256_RE.test(input.payload_sha256 || '') ||
    !payload ||
    typeof payload !== 'object' ||
    Array.isArray(payload) ||
    JSON.stringify(Object.keys(payload)) !== '["Limit","Offset"]' ||
    JSON.stringify(payload) !== input.payload ||
    !Number.isSafeInteger(payload.Offset) ||
    payload.Offset < 0 ||
    payload.Offset > 10_000 ||
    !Number.isSafeInteger(payload.Limit) ||
    payload.Limit < 1 ||
    payload.Limit > 100 ||
    createHash('sha256').update(input.payload).digest('hex') !== input.payload_sha256 ||
    (input.signal !== undefined && !(input.signal instanceof AbortSignal))
  ) {
    fail('tencent_signing_request_invalid', 'Local Tencent Cloud signing request is invalid');
  }
}

function encodeRequest(input) {
  const payload = `${JSON.stringify({
    version: 1,
    provider: 'tencent',
    operation_id: input.operation_id,
    account_ref: input.account_ref,
    environment: input.environment,
    resource_ref: input.resource_ref,
    region: input.region,
    execution_id: input.execution_id,
    request_binding: input.request_binding,
    method: input.method,
    path: input.path,
    payload: input.payload,
    payload_sha256: input.payload_sha256,
  })}\n`;
  if (Buffer.byteLength(payload) > MAX_REQUEST_BYTES) {
    fail('tencent_signing_request_invalid', 'Local Tencent Cloud signing request is invalid');
  }
  return payload;
}

function decodeResponse(input, value) {
  let document;
  try {
    document = JSON.parse(value);
  } catch {
    fail(
      'tencent_signing_response_invalid',
      'Local Tencent Cloud signer returned an invalid response',
    );
  }
  const allowed = [
    'version',
    'provider',
    'operation_id',
    'account_ref',
    'environment',
    'resource_ref',
    'region',
    'execution_id',
    'request_binding',
    'payload_sha256',
    'headers',
  ];
  if (
    !document ||
    typeof document !== 'object' ||
    Array.isArray(document) ||
    Object.keys(document).some((key) => !allowed.includes(key)) ||
    document.version !== 1 ||
    document.provider !== 'tencent' ||
    document.operation_id !== input.operation_id ||
    document.account_ref !== input.account_ref ||
    document.environment !== input.environment ||
    document.resource_ref !== input.resource_ref ||
    document.region !== input.region ||
    document.execution_id !== input.execution_id ||
    document.request_binding !== input.request_binding ||
    document.payload_sha256 !== input.payload_sha256 ||
    !document.headers ||
    typeof document.headers !== 'object' ||
    Array.isArray(document.headers)
  ) {
    fail(
      'tencent_signing_response_invalid',
      'Local Tencent Cloud signer returned an invalid response',
    );
  }
  return Object.freeze({
    account_ref: document.account_ref,
    environment: document.environment,
    resource_ref: document.resource_ref,
    region: document.region,
    execution_id: document.execution_id,
    request_binding: document.request_binding,
    payload_sha256: document.payload_sha256,
    headers: Object.freeze({ ...document.headers }),
  });
}

export function createLocalTencentSigningClient({
  connect = net.createConnection,
  stat = lstat,
  timeoutMs = 2_000,
  processUid = typeof process.getuid === 'function' ? process.getuid() : null,
  processGroups = typeof process.getgroups === 'function' ? process.getgroups() : [],
} = {}) {
  if (typeof connect !== 'function' || typeof stat !== 'function') {
    throw new TypeError('Local Tencent Cloud signer dependencies are invalid');
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10_000) {
    throw new TypeError('Local Tencent Cloud signer timeout is invalid');
  }
  if (processUid !== null && (!Number.isSafeInteger(processUid) || processUid < 0)) {
    throw new TypeError('Local Tencent Cloud signer process identity is invalid');
  }
  if (
    !Array.isArray(processGroups) ||
    processGroups.some((group) => !Number.isSafeInteger(group) || group < 0)
  ) {
    throw new TypeError('Local Tencent Cloud signer process groups are invalid');
  }

  async function probe() {
    let directoryMetadata;
    let metadata;
    try {
      directoryMetadata = await stat(SOCKET_DIRECTORY);
      metadata = await stat(SOCKET_PATH);
    } catch {
      fail('tencent_signer_unavailable', 'Local Tencent Cloud signer is unavailable');
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
      fail('tencent_signer_boundary_invalid', 'Local Tencent Cloud signer boundary is invalid');
    }
    return true;
  }

  async function sign(input) {
    validateInput(input);
    if (input.signal?.aborted) {
      fail('tencent_signing_aborted', 'Local Tencent Cloud signing request was aborted');
    }
    await probe();
    const payload = encodeRequest(input);
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
        finish(reject, new LocalTencentSigningError(code, message));
      const abort = () =>
        rejectSafe('tencent_signing_aborted', 'Local Tencent Cloud signing request was aborted');
      try {
        socket = connect({ path: SOCKET_PATH }, () => socket.end(payload));
        socket.setTimeout(timeoutMs, () =>
          rejectSafe('tencent_signer_timeout', 'Local Tencent Cloud signer timed out'),
        );
        socket.on('data', (chunk) => {
          if (settled) return;
          const encoded = Buffer.from(chunk);
          size += encoded.byteLength;
          if (size > MAX_RESPONSE_BYTES) {
            rejectSafe(
              'tencent_signing_response_too_large',
              'Local Tencent Cloud signer response exceeded the limit',
            );
            return;
          }
          chunks.push(encoded);
        });
        socket.on('end', () => {
          if (settled) return;
          try {
            finish(resolve, decodeResponse(input, Buffer.concat(chunks).toString('utf8').trim()));
          } catch (error) {
            finish(
              reject,
              error instanceof LocalTencentSigningError
                ? error
                : new LocalTencentSigningError(
                    'tencent_signing_response_invalid',
                    'Local Tencent Cloud signer returned an invalid response',
                  ),
            );
          }
        });
        socket.on('error', () =>
          rejectSafe('tencent_signer_unavailable', 'Local Tencent Cloud signer is unavailable'),
        );
        input.signal?.addEventListener('abort', abort, { once: true });
        if (input.signal?.aborted) abort();
      } catch {
        rejectSafe('tencent_signer_unavailable', 'Local Tencent Cloud signer is unavailable');
      }
    });
  }

  return Object.freeze({ socketPath: SOCKET_PATH, probe, sign });
}

export const LOCAL_TENCENT_SIGNING_CONTRACT = Object.freeze({
  socket_directory: SOCKET_DIRECTORY,
  socket_path: SOCKET_PATH,
  protocol_version: 1,
  supported_operations: Object.freeze(['cvm.instances.list']),
  maximum_request_bytes: MAX_REQUEST_BYTES,
  maximum_response_bytes: MAX_RESPONSE_BYTES,
  maximum_timeout_ms: 10_000,
  secret_key_available_to_broker: false,
  credential_available_to_agent: false,
});
