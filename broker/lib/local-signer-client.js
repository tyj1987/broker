import { lstat } from 'node:fs/promises';
import net from 'node:net';

const SOCKET_PATH = '/run/secret-broker-signer/github.sock';
const SOCKET_DIRECTORY = '/run/secret-broker-signer';
const MAX_REQUEST_BYTES = 8 * 1024;
const MAX_RESPONSE_BYTES = 4 * 1024;
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const ENVIRONMENT_RE = /^[a-z][a-z0-9_-]{0,31}$/;
const CLIENT_ID_RE = /^[A-Za-z0-9._-]{3,128}$/;
const SIGNING_INPUT_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

export class LocalSignerError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'LocalSignerError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new LocalSignerError(code, message);
}

function validateInput(input) {
  if (
    !input ||
    typeof input !== 'object' ||
    Array.isArray(input) ||
    Object.keys(input).some(
      (key) =>
        !['algorithm', 'signing_input', 'account_ref', 'environment', 'client_id', 'signal'].includes(
          key,
        ),
    ) ||
    input.algorithm !== 'RS256' ||
    !ID_RE.test(input.account_ref || '') ||
    !ENVIRONMENT_RE.test(input.environment || '') ||
    !CLIENT_ID_RE.test(input.client_id || '') ||
    typeof input.signing_input !== 'string' ||
    input.signing_input.length < 20 ||
    input.signing_input.length > 4096 ||
    !SIGNING_INPUT_RE.test(input.signing_input) ||
    (input.signal !== undefined && !(input.signal instanceof AbortSignal))
  ) {
    fail('signer_request_invalid', 'Local signer request is invalid');
  }
}

function encodeRequest(input) {
  const payload = `${JSON.stringify({
    version: 1,
    algorithm: input.algorithm,
    signing_input: input.signing_input,
    account_ref: input.account_ref,
    environment: input.environment,
    client_id: input.client_id,
  })}\n`;
  if (Buffer.byteLength(payload) > MAX_REQUEST_BYTES) {
    fail('signer_request_invalid', 'Local signer request is invalid');
  }
  return payload;
}

function decodeResponse(value) {
  let document;
  try {
    document = JSON.parse(value);
  } catch {
    fail('signer_response_invalid', 'Local signer returned an invalid response');
  }
  if (
    !document ||
    typeof document !== 'object' ||
    Array.isArray(document) ||
    Object.keys(document).some((key) => !['version', 'signature'].includes(key)) ||
    document.version !== 1 ||
    typeof document.signature !== 'string' ||
    !/^[A-Za-z0-9_-]+$/.test(document.signature)
  ) {
    fail('signer_response_invalid', 'Local signer returned an invalid response');
  }
  const signature = Buffer.from(document.signature, 'base64url');
  if (
    signature.byteLength < 256 ||
    signature.byteLength > 1024 ||
    signature.toString('base64url') !== document.signature
  ) {
    fail('signer_response_invalid', 'Local signer returned an invalid response');
  }
  return signature;
}

export function createLocalSignerClient({
  socketPath = SOCKET_PATH,
  connect = net.createConnection,
  stat = lstat,
  timeoutMs = 2_000,
  processUid = typeof process.getuid === 'function' ? process.getuid() : null,
  processGroups = typeof process.getgroups === 'function' ? process.getgroups() : [],
} = {}) {
  if (socketPath !== SOCKET_PATH) {
    throw new TypeError('Local signer socket path must use the fixed runtime boundary');
  }
  if (typeof connect !== 'function' || typeof stat !== 'function') {
    throw new TypeError('Local signer dependencies are invalid');
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10_000) {
    throw new TypeError('Local signer timeout is invalid');
  }
  if (
    processUid !== null &&
    (!Number.isSafeInteger(processUid) || processUid < 0)
  ) {
    throw new TypeError('Local signer process identity is invalid');
  }
  if (
    !Array.isArray(processGroups) ||
    processGroups.some((group) => !Number.isSafeInteger(group) || group < 0)
  ) {
    throw new TypeError('Local signer process groups are invalid');
  }

  async function probe() {
    let directoryMetadata;
    let metadata;
    try {
      directoryMetadata = await stat(SOCKET_DIRECTORY);
      metadata = await stat(socketPath);
    } catch {
      fail('signer_unavailable', 'Local signer is unavailable');
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
      fail('signer_boundary_invalid', 'Local signer boundary is invalid');
    }
    return true;
  }

  async function sign(input) {
    validateInput(input);
    if (input.signal?.aborted) fail('signer_aborted', 'Local signer request was aborted');
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
        finish(reject, new LocalSignerError(code, message));
      const abort = () => rejectSafe('signer_aborted', 'Local signer request was aborted');

      try {
        socket = connect({ path: socketPath }, () => socket.end(payload));
        socket.setTimeout(timeoutMs, () =>
          rejectSafe('signer_timeout', 'Local signer request timed out'),
        );
        socket.on('data', (chunk) => {
          if (settled) return;
          const value = Buffer.from(chunk);
          size += value.byteLength;
          if (size > MAX_RESPONSE_BYTES) {
            rejectSafe('signer_response_too_large', 'Local signer response exceeded the limit');
            return;
          }
          chunks.push(value);
        });
        socket.on('end', () => {
          if (settled) return;
          try {
            finish(resolve, decodeResponse(Buffer.concat(chunks).toString('utf8').trim()));
          } catch (error) {
            finish(
              reject,
              error instanceof LocalSignerError
                ? error
                : new LocalSignerError('signer_response_invalid', 'Local signer returned an invalid response'),
            );
          }
        });
        socket.on('error', () => rejectSafe('signer_unavailable', 'Local signer is unavailable'));
        input.signal?.addEventListener('abort', abort, { once: true });
        if (input.signal?.aborted) abort();
      } catch {
        rejectSafe('signer_unavailable', 'Local signer is unavailable');
      }
    });
  }

  return Object.freeze({ socketPath, probe, sign });
}

export const LOCAL_SIGNER_CONTRACT = Object.freeze({
  socket_directory: SOCKET_DIRECTORY,
  socket_path: SOCKET_PATH,
  algorithm: 'RS256',
  protocol_version: 1,
  maximum_request_bytes: MAX_REQUEST_BYTES,
  maximum_response_bytes: MAX_RESPONSE_BYTES,
  maximum_timeout_ms: 10_000,
  private_key_available_to_broker: false,
});
