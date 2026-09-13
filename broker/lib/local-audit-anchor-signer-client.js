import { lstat } from 'node:fs/promises';
import net from 'node:net';
import {
  ANCHOR_PURPOSE,
  AuditAnchorError,
  SIGNATURE_ALGORITHMS,
  attachAuditAnchorSignature,
  createAuditAnchorSigningInput,
} from './audit-anchor.js';

const SOCKET_DIRECTORY = '/run/secret-broker-audit-anchor';
const SOCKET_PATH = `${SOCKET_DIRECTORY}/signer.sock`;
const MAX_REQUEST_BYTES = 8 * 1024;
const MAX_RESPONSE_BYTES = 8 * 1024;
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export class LocalAuditAnchorSignerError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'LocalAuditAnchorSignerError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new LocalAuditAnchorSignerError(code, message);
}

function signingInput(request, algorithm, keyId) {
  try {
    return createAuditAnchorSigningInput(request, { algorithm, keyId });
  } catch (error) {
    if (error instanceof AuditAnchorError) {
      fail('anchor_signer_request_invalid', 'Audit anchor signer request is invalid');
    }
    throw error;
  }
}

function encodeRequest(request, algorithm, keyId) {
  const input = signingInput(request, algorithm, keyId);
  const encoded = `${JSON.stringify({
    version: 2,
    purpose: ANCHOR_PURPOSE,
    algorithm,
    key_id: keyId,
    stream_id: request.payload.stream_id,
    sequence: request.payload.sequence,
    previous_anchor_digest: request.payload.previous_anchor_digest,
    payload_digest: request.payload_digest,
    signing_input: input.toString('base64url'),
  })}\n`;
  if (Buffer.byteLength(encoded) > MAX_REQUEST_BYTES) {
    fail('anchor_signer_request_invalid', 'Audit anchor signer request is invalid');
  }
  return encoded;
}

function decodeResponse(request, algorithm, keyId, value) {
  let document;
  try {
    document = JSON.parse(value);
  } catch {
    fail('anchor_signer_response_invalid', 'Audit anchor signer returned an invalid response');
  }
  const allowed = new Set([
    'version',
    'purpose',
    'algorithm',
    'key_id',
    'payload_digest',
    'signature',
  ]);
  if (
    !document ||
    typeof document !== 'object' ||
    Array.isArray(document) ||
    Object.keys(document).length !== allowed.size ||
    Object.keys(document).some((key) => !allowed.has(key)) ||
    document.version !== 2 ||
    document.purpose !== ANCHOR_PURPOSE ||
    document.algorithm !== algorithm ||
    document.key_id !== keyId ||
    document.payload_digest !== request.payload_digest
  ) {
    fail('anchor_signer_response_invalid', 'Audit anchor signer returned an invalid response');
  }
  try {
    return attachAuditAnchorSignature(request, {
      algorithm,
      key_id: keyId,
      value: document.signature,
    }).signature;
  } catch {
    fail('anchor_signer_response_invalid', 'Audit anchor signer returned an invalid response');
  }
}

export function createLocalAuditAnchorSignerClient({
  algorithm,
  keyId,
  connect = net.createConnection,
  stat = lstat,
  timeoutMs = 2_000,
  processUid = typeof process.getuid === 'function' ? process.getuid() : null,
  processGroups = typeof process.getgroups === 'function' ? process.getgroups() : [],
} = {}) {
  if (!SIGNATURE_ALGORITHMS.has(algorithm) || !ID_RE.test(keyId || '')) {
    throw new TypeError('Audit anchor signer identity is invalid');
  }
  if (typeof connect !== 'function' || typeof stat !== 'function') {
    throw new TypeError('Audit anchor signer dependencies are invalid');
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10_000) {
    throw new TypeError('Audit anchor signer timeout is invalid');
  }
  if (processUid !== null && (!Number.isSafeInteger(processUid) || processUid < 0)) {
    throw new TypeError('Audit anchor signer process identity is invalid');
  }
  if (
    !Array.isArray(processGroups) ||
    processGroups.some((group) => !Number.isSafeInteger(group) || group < 0)
  ) {
    throw new TypeError('Audit anchor signer process groups are invalid');
  }

  async function probe() {
    let directoryMetadata;
    let metadata;
    try {
      directoryMetadata = await stat(SOCKET_DIRECTORY);
      metadata = await stat(SOCKET_PATH);
    } catch {
      fail('anchor_signer_unavailable', 'Audit anchor signer is unavailable');
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
      fail('anchor_signer_boundary_invalid', 'Audit anchor signer boundary is invalid');
    }
    return true;
  }

  async function signAnchor(request, { signal } = {}) {
    if (signal !== undefined && !(signal instanceof AbortSignal)) {
      fail('anchor_signer_request_invalid', 'Audit anchor signer request is invalid');
    }
    const payload = encodeRequest(request, algorithm, keyId);
    if (signal?.aborted) fail('anchor_signer_aborted', 'Audit anchor signing was aborted');
    await probe();
    if (signal?.aborted) fail('anchor_signer_aborted', 'Audit anchor signing was aborted');
    return new Promise((resolve, reject) => {
      let socket;
      let settled = false;
      let size = 0;
      const chunks = [];
      const finish = (handler, result) => {
        if (settled) return;
        settled = true;
        signal?.removeEventListener('abort', abort);
        socket?.destroy?.();
        handler(result);
      };
      const rejectSafe = (code, message) =>
        finish(reject, new LocalAuditAnchorSignerError(code, message));
      const abort = () =>
        rejectSafe('anchor_signer_aborted', 'Audit anchor signing was aborted');
      try {
        socket = connect({ path: SOCKET_PATH }, () => {
          if (settled || signal?.aborted) {
            socket.destroy();
            return;
          }
          socket.end(payload);
        });
        socket.setTimeout(timeoutMs, () =>
          rejectSafe('anchor_signer_timeout', 'Audit anchor signer request timed out'),
        );
        socket.on('data', (chunk) => {
          if (settled) return;
          const encoded = Buffer.from(chunk);
          size += encoded.byteLength;
          if (size > MAX_RESPONSE_BYTES) {
            rejectSafe(
              'anchor_signer_response_too_large',
              'Audit anchor signer response exceeded the limit',
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
              decodeResponse(
                request,
                algorithm,
                keyId,
                Buffer.concat(chunks).toString('utf8').trim(),
              ),
            );
          } catch (error) {
            finish(
              reject,
              error instanceof LocalAuditAnchorSignerError
                ? error
                : new LocalAuditAnchorSignerError(
                    'anchor_signer_response_invalid',
                    'Audit anchor signer returned an invalid response',
                  ),
            );
          }
        });
        socket.on('error', () =>
          rejectSafe('anchor_signer_unavailable', 'Audit anchor signer is unavailable'),
        );
        signal?.addEventListener('abort', abort, { once: true });
        if (signal?.aborted) abort();
      } catch {
        rejectSafe('anchor_signer_unavailable', 'Audit anchor signer is unavailable');
      }
    });
  }

  return Object.freeze({ algorithm, keyId, socketPath: SOCKET_PATH, probe, signAnchor });
}

export const LOCAL_AUDIT_ANCHOR_SIGNER_CONTRACT = Object.freeze({
  socket_directory: SOCKET_DIRECTORY,
  socket_path: SOCKET_PATH,
  protocol_version: 2,
  maximum_request_bytes: MAX_REQUEST_BYTES,
  maximum_response_bytes: MAX_RESPONSE_BYTES,
  maximum_timeout_ms: 10_000,
  private_key_available_to_broker: false,
  audit_content_available_to_signer: false,
});
