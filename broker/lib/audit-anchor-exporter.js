import {
  AuditAnchorError,
  attachAuditAnchorSignature,
  createAuditAnchorRequest,
  verifyAuditAnchorEnvelope,
} from './audit-anchor.js';
import { GENESIS_HASH } from './audit-hash-chain.js';

const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export class AuditAnchorExporterError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'AuditAnchorExporterError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new AuditAnchorExporterError(code, message);
}

function validateSignal(signal) {
  if (signal !== undefined && !(signal instanceof AbortSignal)) {
    fail('anchor_export_request_invalid', 'Audit anchor export request is invalid');
  }
  if (signal?.aborted) fail('anchor_export_aborted', 'Audit anchor export was aborted');
}

function exactKeys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length === expected.size && keys.every((key) => expected.has(key));
}

function sameChainState(envelope, state) {
  return envelope.payload.chain_head === state.lastHash
    && envelope.payload.event_count === state.count
    && envelope.payload.file_count === state.files;
}

export function createAuditAnchorExporter({
  streamId,
  signer,
  store,
  loadChainState,
  loadChainProof,
  trustedKeyIds,
  revokedKeyIds = new Set(),
  verifySignature,
  now = () => Date.now(),
} = {}) {
  if (
    !ID_RE.test(streamId || '') ||
    !signer ||
    typeof signer.signAnchor !== 'function' ||
    !store ||
    typeof store.readHead !== 'function' ||
    typeof store.publish !== 'function' ||
    typeof loadChainState !== 'function' ||
    typeof loadChainProof !== 'function' ||
    !(trustedKeyIds instanceof Set) ||
    trustedKeyIds.size === 0 ||
    !(revokedKeyIds instanceof Set) ||
    typeof verifySignature !== 'function' ||
    typeof now !== 'function'
  ) {
    throw new TypeError('Audit anchor exporter configuration is invalid');
  }

  async function chainState(signal) {
    try {
      return await loadChainState({ signal });
    } catch {
      if (signal?.aborted) fail('anchor_export_aborted', 'Audit anchor export was aborted');
      fail('anchor_chain_unavailable', 'Audit chain state is unavailable');
    }
  }

  async function chainProof(eventCount, signal) {
    try {
      return await loadChainProof(eventCount, { signal });
    } catch {
      if (signal?.aborted) fail('anchor_export_aborted', 'Audit anchor export was aborted');
      fail('anchor_chain_unavailable', 'Audit chain proof is unavailable');
    }
  }

  async function readHead(signal) {
    let head;
    try {
      head = await store.readHead({ streamId, signal });
    } catch {
      if (signal?.aborted) fail('anchor_export_aborted', 'Audit anchor export was aborted');
      fail('anchor_store_unavailable', 'Audit anchor store is unavailable');
    }
    if (
      !exactKeys(head, new Set(['current', 'previous'])) ||
      (head.current === null && head.previous !== null)
    ) {
      fail('anchor_store_invalid', 'Audit anchor store returned an invalid head');
    }
    return head;
  }

  async function verifyStored(envelope, previousEnvelope, signal) {
    if (!envelope || envelope?.payload?.stream_id !== streamId) {
      fail('anchor_store_invalid', 'Audit anchor store returned an invalid head');
    }
    try {
      const proof = await chainProof(envelope.payload.event_count, signal);
      verifyAuditAnchorEnvelope(envelope, {
        chainProof: proof,
        previousEnvelope,
        trustedKeyIds,
        revokedKeyIds,
        verifySignature,
      });
    } catch (error) {
      if (error instanceof AuditAnchorExporterError) throw error;
      fail('anchor_store_invalid', 'Audit anchor store returned an invalid head');
    }
  }

  async function publish(envelope, expectedPreviousDigest, signal) {
    let result;
    try {
      result = await store.publish({
        streamId,
        expectedPreviousDigest,
        envelope: structuredClone(envelope),
        signal,
      });
    } catch {
      if (signal?.aborted) fail('anchor_export_aborted', 'Audit anchor export was aborted');
      fail('anchor_store_unavailable', 'Audit anchor store is unavailable');
    }
    const published = exactKeys(result, new Set(['status'])) && result.status === 'published';
    const conflict = exactKeys(result, new Set(['status', 'current']))
      && result.status === 'conflict';
    if (!published && !conflict) {
      fail('anchor_store_invalid', 'Audit anchor store returned an invalid publish result');
    }
    return result;
  }

  async function exportAnchor({ signal } = {}) {
    validateSignal(signal);
    const state = await chainState(signal);
    validateSignal(signal);
    const head = await readHead(signal);
    validateSignal(signal);

    if (head.current !== null) {
      await verifyStored(head.current, head.previous, signal);
      if (sameChainState(head.current, state)) {
        return Object.freeze({
          status: 'already_published',
          envelope: structuredClone(head.current),
        });
      }
    }

    let request;
    try {
      request = createAuditAnchorRequest(state, {
        streamId,
        sequence: head.current === null ? 1 : head.current.payload.sequence + 1,
        previousAnchorDigest:
          head.current === null ? GENESIS_HASH : head.current.payload_digest,
        now,
      });
    } catch (error) {
      if (error instanceof AuditAnchorError && error.code === 'invalid_chain_state') {
        fail('anchor_chain_invalid', 'Audit chain state is invalid');
      }
      if (error instanceof AuditAnchorError) {
        fail('anchor_export_request_invalid', 'Audit anchor export request is invalid');
      }
      fail('anchor_export_request_invalid', 'Audit anchor export request is invalid');
    }

    let signature;
    try {
      signature = await signer.signAnchor(request, { signal });
    } catch {
      if (signal?.aborted) fail('anchor_export_aborted', 'Audit anchor export was aborted');
      fail('anchor_signer_unavailable', 'Audit anchor signer is unavailable');
    }
    validateSignal(signal);

    let envelope;
    try {
      envelope = attachAuditAnchorSignature(request, signature);
      verifyAuditAnchorEnvelope(envelope, {
        chainState: state,
        previousEnvelope: head.current,
        trustedKeyIds,
        revokedKeyIds,
        verifySignature,
      });
    } catch {
      fail('anchor_signature_invalid', 'Audit anchor signature verification failed');
    }

    const result = await publish(
      envelope,
      head.current === null ? GENESIS_HASH : head.current.payload_digest,
      signal,
    );
    validateSignal(signal);
    if (result.status === 'published') {
      return Object.freeze({ status: 'published', envelope });
    }

    try {
      verifyAuditAnchorEnvelope(result.current, {
        chainState: state,
        previousEnvelope: head.current,
        trustedKeyIds,
        revokedKeyIds,
        verifySignature,
      });
    } catch {
      fail('anchor_publish_conflict', 'Audit anchor sequence changed during publication');
    }
    return Object.freeze({
      status: 'already_published',
      envelope: structuredClone(result.current),
    });
  }

  return Object.freeze({ streamId, exportAnchor });
}
