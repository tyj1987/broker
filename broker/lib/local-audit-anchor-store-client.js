import { randomUUID } from 'node:crypto';
import { lstat } from 'node:fs/promises';
import net from 'node:net';
import { ANCHOR_PURPOSE } from './audit-anchor.js';

const SOCKET_DIRECTORY = '/run/secret-broker-audit-store';
const SOCKET_PATH = `${SOCKET_DIRECTORY}/store.sock`;
const STORE_PURPOSE = 'secret-broker.audit-anchor-store';
const PROTOCOL_VERSION = 1;
const MAX_REQUEST_BYTES = 24 * 1024;
const MAX_RESPONSE_BYTES = 576 * 1024;
const MAX_ENVELOPE_BYTES = 16 * 1024;
const MAX_WIRE_PAGE_SIZE = 32;
const MAX_SAFE_SEQUENCE = Number.MAX_SAFE_INTEGER;
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DIGEST_RE = /^[0-9a-f]{64}$/;
const TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const REASON_RE = /^[a-z][a-z0-9_]{1,63}$/;
const ERROR_CODES = new Set([
  'request_invalid',
  'operation_denied',
  'store_unavailable',
  'store_invalid',
  'deadline_exceeded',
  'server_busy',
  'internal_error',
]);

export class LocalAuditAnchorStoreError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'LocalAuditAnchorStoreError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new LocalAuditAnchorStoreError(code, message);
}

function exactKeys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length === expected.size && keys.every((key) => expected.has(key));
}

function validSequence(value, minimum = 0) {
  return Number.isSafeInteger(value) && value >= minimum && value <= MAX_SAFE_SEQUENCE;
}

function validateEnvelope(envelope, streamId) {
  if (
    !exactKeys(envelope, new Set(['version', 'payload', 'payload_digest', 'signature'])) ||
    envelope.version !== 1 ||
    !exactKeys(
      envelope.payload,
      new Set([
        'purpose',
        'version',
        'stream_id',
        'sequence',
        'captured_at',
        'chain_head',
        'event_count',
        'file_count',
        'previous_anchor_digest',
      ]),
    ) ||
    envelope.payload.purpose !== ANCHOR_PURPOSE ||
    envelope.payload.version !== 1 ||
    envelope.payload.stream_id !== streamId ||
    !validSequence(envelope.payload.sequence, 1) ||
    !TIMESTAMP_RE.test(envelope.payload.captured_at || '') ||
    !DIGEST_RE.test(envelope.payload.chain_head || '') ||
    !validSequence(envelope.payload.event_count) ||
    !validSequence(envelope.payload.file_count) ||
    !DIGEST_RE.test(envelope.payload.previous_anchor_digest || '') ||
    !DIGEST_RE.test(envelope.payload_digest || '') ||
    !exactKeys(envelope.signature, new Set(['algorithm', 'key_id', 'value'])) ||
    envelope.signature.algorithm !== 'ecdsa-p256-sha256' ||
    !ID_RE.test(envelope.signature.key_id || '') ||
    typeof envelope.signature.value !== 'string' ||
    !/^[A-Za-z0-9_-]{43,4096}$/.test(envelope.signature.value)
  ) {
    fail('anchor_store_envelope_invalid', 'Audit anchor store envelope is invalid');
  }
  let encoded;
  try {
    encoded = JSON.stringify(envelope);
  } catch {
    fail('anchor_store_envelope_invalid', 'Audit anchor store envelope is invalid');
  }
  if (Buffer.byteLength(encoded) > MAX_ENVELOPE_BYTES) {
    fail('anchor_store_envelope_invalid', 'Audit anchor store envelope is invalid');
  }
  return structuredClone(envelope);
}

function encodeRequest({ requestId, operation, streamId, parameters }) {
  const encoded = `${JSON.stringify({
    version: PROTOCOL_VERSION,
    purpose: STORE_PURPOSE,
    request_id: requestId,
    operation,
    stream_id: streamId,
    parameters,
  })}\n`;
  if (Buffer.byteLength(encoded) > MAX_REQUEST_BYTES) {
    fail('anchor_store_request_invalid', 'Audit anchor store request is invalid');
  }
  return encoded;
}

function decodeResponse({ requestId, operation, streamId }, value) {
  if (!value.endsWith('\n') || value.slice(0, -1).includes('\n') || value.includes('\r')) {
    fail('anchor_store_response_invalid', 'Audit anchor store returned an invalid response');
  }
  let document;
  try {
    document = JSON.parse(value.slice(0, -1));
  } catch {
    fail('anchor_store_response_invalid', 'Audit anchor store returned an invalid response');
  }
  if (
    document?.status === 'error' &&
    exactKeys(
      document,
      new Set(['version', 'purpose', 'request_id', 'operation', 'status', 'error_code']),
    ) &&
    document.version === PROTOCOL_VERSION &&
    document.purpose === STORE_PURPOSE &&
    document.request_id === requestId &&
    document.operation === operation &&
    ERROR_CODES.has(document.error_code)
  ) {
    fail(`anchor_${document.error_code}`, 'Audit anchor store request failed');
  }
  if (
    !exactKeys(
      document,
      new Set(['version', 'purpose', 'request_id', 'operation', 'status', 'stream_id', 'result']),
    ) ||
    document.version !== PROTOCOL_VERSION ||
    document.purpose !== STORE_PURPOSE ||
    document.request_id !== requestId ||
    document.operation !== operation ||
    document.status !== 'ok' ||
    document.stream_id !== streamId
  ) {
    fail('anchor_store_response_invalid', 'Audit anchor store returned an invalid response');
  }
  return document.result;
}

function decodeHead(result, streamId) {
  if (
    !exactKeys(result, new Set(['current', 'previous'])) ||
    (result.current === null && result.previous !== null)
  ) {
    fail('anchor_store_response_invalid', 'Audit anchor store returned an invalid response');
  }
  const current = result.current === null ? null : validateEnvelope(result.current, streamId);
  const previous = result.previous === null ? null : validateEnvelope(result.previous, streamId);
  if (
    current !== null &&
    ((current.payload.sequence === 1 && previous !== null) ||
      (current.payload.sequence > 1 &&
        (previous === null ||
          previous.payload.sequence !== current.payload.sequence - 1 ||
          previous.payload_digest !== current.payload.previous_anchor_digest)))
  ) {
    fail('anchor_store_response_invalid', 'Audit anchor store returned an invalid response');
  }
  return Object.freeze({ current, previous });
}

export function createLocalAuditAnchorStoreClient({
  streamId,
  connect = net.createConnection,
  stat = lstat,
  timeoutMs = 40_000,
  createRequestId = randomUUID,
  processUid = typeof process.getuid === 'function' ? process.getuid() : null,
  processGroups = typeof process.getgroups === 'function' ? process.getgroups() : [],
} = {}) {
  if (!ID_RE.test(streamId || '')) {
    throw new TypeError('Audit anchor store stream is invalid');
  }
  if (
    typeof connect !== 'function' ||
    typeof stat !== 'function' ||
    typeof createRequestId !== 'function'
  ) {
    throw new TypeError('Audit anchor store dependencies are invalid');
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60_000) {
    throw new TypeError('Audit anchor store timeout is invalid');
  }
  if (processUid !== null && (!Number.isSafeInteger(processUid) || processUid < 0)) {
    throw new TypeError('Audit anchor store process identity is invalid');
  }
  if (
    !Array.isArray(processGroups) ||
    processGroups.some((group) => !Number.isSafeInteger(group) || group < 0)
  ) {
    throw new TypeError('Audit anchor store process groups are invalid');
  }

  async function probe() {
    let directoryMetadata;
    let metadata;
    try {
      directoryMetadata = await stat(SOCKET_DIRECTORY);
      metadata = await stat(SOCKET_PATH);
    } catch {
      fail('anchor_store_unavailable', 'Audit anchor store is unavailable');
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
      fail('anchor_store_boundary_invalid', 'Audit anchor store boundary is invalid');
    }
    return true;
  }

  async function exchange(operation, parameters, { signal } = {}) {
    if (signal !== undefined && !(signal instanceof AbortSignal)) {
      fail('anchor_store_request_invalid', 'Audit anchor store request is invalid');
    }
    if (signal?.aborted) fail('anchor_store_aborted', 'Audit anchor store request was aborted');
    let requestId;
    try {
      requestId = createRequestId();
    } catch {
      fail('anchor_store_request_invalid', 'Audit anchor store request is invalid');
    }
    if (!ID_RE.test(requestId || '')) {
      fail('anchor_store_request_invalid', 'Audit anchor store request is invalid');
    }
    const payload = encodeRequest({ requestId, operation, streamId, parameters });
    await probe();
    if (signal?.aborted) fail('anchor_store_aborted', 'Audit anchor store request was aborted');
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
        finish(reject, new LocalAuditAnchorStoreError(code, message));
      const abort = () =>
        rejectSafe('anchor_store_aborted', 'Audit anchor store request was aborted');
      try {
        socket = connect({ path: SOCKET_PATH }, () => {
          if (settled || signal?.aborted) {
            socket.destroy();
            return;
          }
          socket.end(payload);
        });
        socket.setTimeout(timeoutMs, () =>
          rejectSafe('anchor_store_timeout', 'Audit anchor store request timed out'),
        );
        socket.on('data', (chunk) => {
          if (settled) return;
          const encoded = Buffer.from(chunk);
          size += encoded.byteLength;
          if (size > MAX_RESPONSE_BYTES) {
            rejectSafe(
              'anchor_store_response_too_large',
              'Audit anchor store response exceeded the limit',
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
                { requestId, operation, streamId },
                Buffer.concat(chunks).toString('utf8'),
              ),
            );
          } catch (error) {
            finish(
              reject,
              error instanceof LocalAuditAnchorStoreError
                ? error
                : new LocalAuditAnchorStoreError(
                    'anchor_store_response_invalid',
                    'Audit anchor store returned an invalid response',
                  ),
            );
          }
        });
        socket.on('error', () =>
          rejectSafe('anchor_store_unavailable', 'Audit anchor store is unavailable'),
        );
        signal?.addEventListener('abort', abort, { once: true });
        if (signal?.aborted) abort();
      } catch {
        rejectSafe('anchor_store_unavailable', 'Audit anchor store is unavailable');
      }
    });
  }

  async function readHead({ streamId: requestedStream, signal } = {}) {
    if (requestedStream !== streamId) {
      fail('anchor_store_request_invalid', 'Audit anchor store request is invalid');
    }
    return decodeHead(await exchange('read_head', {}, { signal }), streamId);
  }

  async function publish({
    streamId: requestedStream,
    expectedPreviousDigest,
    envelope,
    signal,
  } = {}) {
    if (requestedStream !== streamId || !DIGEST_RE.test(expectedPreviousDigest || '')) {
      fail('anchor_store_request_invalid', 'Audit anchor store request is invalid');
    }
    const safeEnvelope = validateEnvelope(envelope, streamId);
    if (safeEnvelope.payload.previous_anchor_digest !== expectedPreviousDigest) {
      fail('anchor_store_request_invalid', 'Audit anchor store request is invalid');
    }
    const result = await exchange(
      'publish',
      {
        expected_previous_digest: expectedPreviousDigest,
        envelope: safeEnvelope,
      },
      { signal },
    );
    if (exactKeys(result, new Set(['status'])) && result.status === 'published') {
      return Object.freeze({ status: 'published' });
    }
    if (exactKeys(result, new Set(['status', 'current'])) && result.status === 'conflict') {
      const current = validateEnvelope(result.current, streamId);
      if (
        current.payload.sequence !== safeEnvelope.payload.sequence ||
        current.payload.previous_anchor_digest !== expectedPreviousDigest
      ) {
        fail('anchor_store_response_invalid', 'Audit anchor store returned an invalid response');
      }
      return Object.freeze({ status: 'conflict', current });
    }
    fail('anchor_store_response_invalid', 'Audit anchor store returned an invalid response');
  }

  async function readPage({
    streamId: requestedStream,
    afterSequence,
    throughSequence,
    limit,
    signal,
  } = {}) {
    if (
      requestedStream !== streamId ||
      !validSequence(afterSequence) ||
      !validSequence(throughSequence, 1) ||
      afterSequence >= throughSequence ||
      !Number.isSafeInteger(limit) ||
      limit < 1 ||
      limit > 1_000
    ) {
      fail('anchor_store_request_invalid', 'Audit anchor store request is invalid');
    }
    const wireLimit = Math.min(limit, MAX_WIRE_PAGE_SIZE);
    const result = await exchange(
      'read_page',
      {
        after_sequence: afterSequence,
        through_sequence: throughSequence,
        limit: wireLimit,
      },
      { signal },
    );
    if (
      !exactKeys(result, new Set(['after_sequence', 'through_sequence', 'anchors'])) ||
      result.after_sequence !== afterSequence ||
      result.through_sequence !== throughSequence ||
      !Array.isArray(result.anchors) ||
      result.anchors.length > wireLimit
    ) {
      fail('anchor_store_response_invalid', 'Audit anchor store returned an invalid response');
    }
    let expectedSequence = afterSequence + 1;
    const anchors = result.anchors.map((envelope) => {
      const safeEnvelope = validateEnvelope(envelope, streamId);
      if (
        safeEnvelope.payload.sequence !== expectedSequence ||
        expectedSequence > throughSequence
      ) {
        fail('anchor_store_response_invalid', 'Audit anchor store returned an invalid response');
      }
      expectedSequence += 1;
      return safeEnvelope;
    });
    return Object.freeze({ anchors });
  }

  async function health({ streamId: requestedStream, signal } = {}) {
    if (requestedStream !== streamId) {
      fail('anchor_store_request_invalid', 'Audit anchor store request is invalid');
    }
    const result = await exchange('health', {}, { signal });
    if (
      !exactKeys(
        result,
        new Set(['status', 'lock_contract', 'mirror_state', 'common_sequence', 'reason_code']),
      ) ||
      !new Set(['ready', 'repair_required', 'blocked']).has(result.status) ||
      !new Set(['verified', 'unverified']).has(result.lock_contract) ||
      !new Set(['in_sync', 'lagging', 'invalid']).has(result.mirror_state) ||
      !validSequence(result.common_sequence) ||
      !REASON_RE.test(result.reason_code || '') ||
      (result.status === 'ready' &&
        (result.lock_contract !== 'verified' ||
          result.mirror_state !== 'in_sync' ||
          result.reason_code !== 'ok')) ||
      (result.status === 'repair_required' &&
        (result.lock_contract !== 'verified' || result.mirror_state !== 'lagging')) ||
      (result.status !== 'ready' && result.reason_code === 'ok')
    ) {
      fail('anchor_store_response_invalid', 'Audit anchor store returned an invalid response');
    }
    return Object.freeze(structuredClone(result));
  }

  return Object.freeze({
    streamId,
    socketPath: SOCKET_PATH,
    probe,
    readHead,
    publish,
    readPage,
    health,
  });
}

export const LOCAL_AUDIT_ANCHOR_STORE_CONTRACT = Object.freeze({
  socket_directory: SOCKET_DIRECTORY,
  socket_path: SOCKET_PATH,
  protocol_version: PROTOCOL_VERSION,
  purpose: STORE_PURPOSE,
  maximum_request_bytes: MAX_REQUEST_BYTES,
  maximum_response_bytes: MAX_RESPONSE_BYTES,
  maximum_envelope_bytes: MAX_ENVELOPE_BYTES,
  maximum_wire_page_size: MAX_WIRE_PAGE_SIZE,
  maximum_timeout_ms: 60_000,
  provider_credentials_available_to_client: false,
  retention_mutation_available_to_client: false,
  deletion_available_to_client: false,
});
