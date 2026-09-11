import { verifyAuditAnchorEnvelope } from './audit-anchor.js';

const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DEFAULT_PAGE_SIZE = 100;
const DEFAULT_MAX_ANCHORS = 100_000;

export class AuditAnchorRecoveryError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'AuditAnchorRecoveryError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new AuditAnchorRecoveryError(code, message);
}

function validateSignal(signal) {
  if (signal !== undefined && !(signal instanceof AbortSignal)) {
    fail('anchor_recovery_request_invalid', 'Audit anchor recovery request is invalid');
  }
  if (signal?.aborted) fail('anchor_recovery_aborted', 'Audit anchor recovery was aborted');
}

function exactKeys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length === expected.size && keys.every((key) => expected.has(key));
}

export function createAuditAnchorRecoveryVerifier({
  streamId,
  store,
  loadChainProof,
  trustedKeyIds,
  revokedKeyIds = new Set(),
  verifySignature,
  pageSize = DEFAULT_PAGE_SIZE,
  maxAnchors = DEFAULT_MAX_ANCHORS,
} = {}) {
  if (
    !ID_RE.test(streamId || '') ||
    !store ||
    typeof store.readHead !== 'function' ||
    typeof store.readPage !== 'function' ||
    typeof loadChainProof !== 'function' ||
    !(trustedKeyIds instanceof Set) ||
    trustedKeyIds.size === 0 ||
    !(revokedKeyIds instanceof Set) ||
    typeof verifySignature !== 'function' ||
    !Number.isSafeInteger(pageSize) ||
    pageSize < 1 ||
    pageSize > 1_000 ||
    !Number.isSafeInteger(maxAnchors) ||
    maxAnchors < 1 ||
    maxAnchors > 1_000_000
  ) {
    throw new TypeError('Audit anchor recovery verifier configuration is invalid');
  }

  async function readHead(signal) {
    let head;
    try {
      head = await store.readHead({ streamId, signal });
    } catch {
      if (signal?.aborted) fail('anchor_recovery_aborted', 'Audit anchor recovery was aborted');
      fail('anchor_store_unavailable', 'Audit anchor store is unavailable');
    }
    if (
      !exactKeys(head, new Set(['current', 'previous'])) ||
      (head.current === null && head.previous !== null) ||
      (head.current !== null && head.current?.payload?.stream_id !== streamId)
    ) {
      fail('anchor_store_invalid', 'Audit anchor store returned an invalid head');
    }
    return head;
  }

  async function readPage(afterSequence, throughSequence, signal) {
    let page;
    try {
      page = await store.readPage({
        streamId,
        afterSequence,
        throughSequence,
        limit: pageSize,
        signal,
      });
    } catch {
      if (signal?.aborted) fail('anchor_recovery_aborted', 'Audit anchor recovery was aborted');
      fail('anchor_store_unavailable', 'Audit anchor store is unavailable');
    }
    if (
      !exactKeys(page, new Set(['anchors'])) ||
      !Array.isArray(page.anchors) ||
      page.anchors.length > pageSize
    ) {
      fail('anchor_store_invalid', 'Audit anchor store returned an invalid page');
    }
    return page.anchors;
  }

  async function verifyRecovery({ signal } = {}) {
    validateSignal(signal);
    const head = await readHead(signal);
    validateSignal(signal);
    if (head.current === null) {
      return Object.freeze({ status: 'empty', count: 0, sequence: 0, payload_digest: null });
    }

    const throughSequence = head.current.payload.sequence;
    if (!Number.isSafeInteger(throughSequence) || throughSequence < 1) {
      fail('anchor_store_invalid', 'Audit anchor store returned an invalid head');
    }
    if (throughSequence > maxAnchors) {
      fail('anchor_recovery_limit', 'Audit anchor recovery exceeded its configured limit');
    }

    let previousEnvelope = null;
    let expectedSequence = 1;
    while (expectedSequence <= throughSequence) {
      const anchors = await readPage(expectedSequence - 1, throughSequence, signal);
      validateSignal(signal);
      if (anchors.length === 0) {
        fail('anchor_recovery_incomplete', 'Audit anchor recovery is incomplete');
      }
      for (const envelope of anchors) {
        if (
          envelope?.payload?.stream_id !== streamId ||
          envelope?.payload?.sequence !== expectedSequence ||
          expectedSequence > throughSequence
        ) {
          fail('anchor_store_invalid', 'Audit anchor store returned a non-contiguous page');
        }
        let proof;
        try {
          proof = await loadChainProof(envelope.payload.event_count, { signal });
        } catch {
          if (signal?.aborted) fail('anchor_recovery_aborted', 'Audit anchor recovery was aborted');
          fail('anchor_chain_unavailable', 'Audit chain proof is unavailable');
        }
        try {
          verifyAuditAnchorEnvelope(envelope, {
            chainProof: proof,
            previousEnvelope,
            trustedKeyIds,
            revokedKeyIds,
            verifySignature,
          });
        } catch {
          fail('anchor_recovery_invalid', 'Audit anchor recovery verification failed');
        }
        previousEnvelope = envelope;
        expectedSequence += 1;
      }
    }

    if (
      previousEnvelope.payload_digest !== head.current.payload_digest ||
      (throughSequence === 1 && head.previous !== null) ||
      (throughSequence > 1 &&
        head.previous?.payload_digest !== previousEnvelope.payload.previous_anchor_digest)
    ) {
      fail('anchor_store_invalid', 'Audit anchor store head changed during recovery');
    }
    return Object.freeze({
      status: 'verified',
      count: throughSequence,
      sequence: throughSequence,
      payload_digest: previousEnvelope.payload_digest,
    });
  }

  return Object.freeze({ streamId, pageSize, maxAnchors, verifyRecovery });
}

export const AUDIT_ANCHOR_RECOVERY_LIMITS = Object.freeze({
  default_page_size: DEFAULT_PAGE_SIZE,
  maximum_page_size: 1_000,
  default_maximum_anchors: DEFAULT_MAX_ANCHORS,
  maximum_anchors: 1_000_000,
});
