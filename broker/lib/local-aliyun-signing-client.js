import { lstat } from 'node:fs/promises';
import net from 'node:net';

const SOCKET_DIRECTORY = '/run/secret-broker-aliyun-signer';
const SOCKET_PATH = `${SOCKET_DIRECTORY}/signer.sock`;
const MAX_REQUEST_BYTES = 8 * 1024;
const MAX_RESPONSE_BYTES = 16 * 1024;
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const ENVIRONMENT_RE = /^[a-z][a-z0-9_-]{0,31}$/;
const REGION_RE = /^[a-z0-9]+(?:-[a-z0-9]+){1,4}$/;
const EXECUTION_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const REQUEST_BINDING_RE = /^[A-Za-z0-9_-]{43}$/;

export class LocalAliyunSigningError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'LocalAliyunSigningError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new LocalAliyunSigningError(code, message);
}

function validateInput(input) {
  const query = input?.query;
  const ecsRequest = input?.operation_id === 'ecs.instances.list';
  const authorityRequest = input?.operation_id === 'sts.caller-identity.read';
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
          'region_id',
          'execution_id',
          'request_binding',
          'method',
          'path',
          'query',
          'signal',
        ].includes(key),
    ) ||
    (!ecsRequest && !authorityRequest) ||
    !ID_RE.test(input.account_ref || '') ||
    !ENVIRONMENT_RE.test(input.environment || '') ||
    !ID_RE.test(input.resource_ref || '') ||
    !REGION_RE.test(input.region_id || '') ||
    !EXECUTION_ID_RE.test(input.execution_id || '') ||
    !REQUEST_BINDING_RE.test(input.request_binding || '') ||
    input.method !== 'POST' ||
    input.path !== '/' ||
    !query ||
    typeof query !== 'object' ||
    Array.isArray(query) ||
    (ecsRequest &&
      Object.keys(query).some((key) => !['MaxResults', 'NextToken', 'RegionId'].includes(key))) ||
    (authorityRequest && Object.keys(query).length !== 0) ||
    (ecsRequest && query.RegionId !== input.region_id) ||
    (ecsRequest &&
      (!Number.isSafeInteger(query.MaxResults) ||
        query.MaxResults < 1 ||
        query.MaxResults > 100)) ||
    (ecsRequest &&
      query.NextToken !== undefined &&
      (typeof query.NextToken !== 'string' ||
        !/^[A-Za-z0-9._~-]{1,2048}$/.test(query.NextToken))) ||
    (input.signal !== undefined && !(input.signal instanceof AbortSignal))
  ) {
    fail('aliyun_signing_request_invalid', 'Local Alibaba Cloud signing request is invalid');
  }
}

function encodeRequest(input) {
  const payload = `${JSON.stringify({
    version: 3,
    provider: 'aliyun',
    operation_id: input.operation_id,
    account_ref: input.account_ref,
    environment: input.environment,
    resource_ref: input.resource_ref,
    region_id: input.region_id,
    execution_id: input.execution_id,
    request_binding: input.request_binding,
    method: input.method,
    path: input.path,
    query: input.query,
  })}\n`;
  if (Buffer.byteLength(payload) > MAX_REQUEST_BYTES) {
    fail('aliyun_signing_request_invalid', 'Local Alibaba Cloud signing request is invalid');
  }
  return payload;
}

function decodeResponse(input, value) {
  let document;
  try {
    document = JSON.parse(value);
  } catch {
    fail(
      'aliyun_signing_response_invalid',
      'Local Alibaba Cloud signer returned an invalid response',
    );
  }
  const allowed = [
    'version',
    'provider',
    'operation_id',
    'account_ref',
    'environment',
    'resource_ref',
    'region_id',
    'execution_id',
    'request_binding',
    'credential_binding',
    'headers',
  ];
  if (
    !document ||
    typeof document !== 'object' ||
    Array.isArray(document) ||
    Object.keys(document).some((key) => !allowed.includes(key)) ||
    document.version !== 3 ||
    document.provider !== 'aliyun' ||
    document.operation_id !== input.operation_id ||
    document.account_ref !== input.account_ref ||
    document.environment !== input.environment ||
    document.resource_ref !== input.resource_ref ||
    document.region_id !== input.region_id ||
    document.execution_id !== input.execution_id ||
    document.request_binding !== input.request_binding ||
    !/^[A-Za-z0-9_-]{43}$/.test(document.credential_binding || '') ||
    !document.headers ||
    typeof document.headers !== 'object' ||
    Array.isArray(document.headers)
  ) {
    fail(
      'aliyun_signing_response_invalid',
      'Local Alibaba Cloud signer returned an invalid response',
    );
  }
  return Object.freeze({
    account_ref: document.account_ref,
    environment: document.environment,
    resource_ref: document.resource_ref,
    region_id: document.region_id,
    execution_id: document.execution_id,
    request_binding: document.request_binding,
    credential_binding: document.credential_binding,
    headers: Object.freeze({ ...document.headers }),
  });
}

export function createLocalAliyunSigningClient({
  connect = net.createConnection,
  stat = lstat,
  timeoutMs = 2_000,
  processUid = typeof process.getuid === 'function' ? process.getuid() : null,
  processGroups = typeof process.getgroups === 'function' ? process.getgroups() : [],
} = {}) {
  if (typeof connect !== 'function' || typeof stat !== 'function') {
    throw new TypeError('Local Alibaba Cloud signer dependencies are invalid');
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10_000) {
    throw new TypeError('Local Alibaba Cloud signer timeout is invalid');
  }
  if (processUid !== null && (!Number.isSafeInteger(processUid) || processUid < 0)) {
    throw new TypeError('Local Alibaba Cloud signer process identity is invalid');
  }
  if (
    !Array.isArray(processGroups) ||
    processGroups.some((group) => !Number.isSafeInteger(group) || group < 0)
  ) {
    throw new TypeError('Local Alibaba Cloud signer process groups are invalid');
  }

  async function probe() {
    let directoryMetadata;
    let metadata;
    try {
      directoryMetadata = await stat(SOCKET_DIRECTORY);
      metadata = await stat(SOCKET_PATH);
    } catch {
      fail('aliyun_signer_unavailable', 'Local Alibaba Cloud signer is unavailable');
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
      fail('aliyun_signer_boundary_invalid', 'Local Alibaba Cloud signer boundary is invalid');
    }
    return true;
  }

  async function sign(input) {
    validateInput(input);
    if (input.signal?.aborted) {
      fail('aliyun_signing_aborted', 'Local Alibaba Cloud signing request was aborted');
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
        finish(reject, new LocalAliyunSigningError(code, message));
      const abort = () =>
        rejectSafe('aliyun_signing_aborted', 'Local Alibaba Cloud signing request was aborted');
      try {
        socket = connect({ path: SOCKET_PATH }, () => socket.end(payload));
        socket.setTimeout(timeoutMs, () =>
          rejectSafe('aliyun_signer_timeout', 'Local Alibaba Cloud signer timed out'),
        );
        socket.on('data', (chunk) => {
          if (settled) return;
          const encoded = Buffer.from(chunk);
          size += encoded.byteLength;
          if (size > MAX_RESPONSE_BYTES) {
            rejectSafe(
              'aliyun_signing_response_too_large',
              'Local Alibaba Cloud signer response exceeded the limit',
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
              error instanceof LocalAliyunSigningError
                ? error
                : new LocalAliyunSigningError(
                    'aliyun_signing_response_invalid',
                    'Local Alibaba Cloud signer returned an invalid response',
                  ),
            );
          }
        });
        socket.on('error', () =>
          rejectSafe('aliyun_signer_unavailable', 'Local Alibaba Cloud signer is unavailable'),
        );
        input.signal?.addEventListener('abort', abort, { once: true });
        if (input.signal?.aborted) abort();
      } catch {
        rejectSafe('aliyun_signer_unavailable', 'Local Alibaba Cloud signer is unavailable');
      }
    });
  }

  return Object.freeze({ socketPath: SOCKET_PATH, probe, sign });
}

export const LOCAL_ALIYUN_SIGNING_CONTRACT = Object.freeze({
  socket_directory: SOCKET_DIRECTORY,
  socket_path: SOCKET_PATH,
  protocol_version: 3,
  supported_operations: Object.freeze(['ecs.instances.list', 'sts.caller-identity.read']),
  maximum_request_bytes: MAX_REQUEST_BYTES,
  maximum_response_bytes: MAX_RESPONSE_BYTES,
  maximum_timeout_ms: 10_000,
  access_key_secret_available_to_broker: false,
  credential_available_to_agent: false,
});
