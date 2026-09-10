import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'node:crypto';
import { basename, dirname, isAbsolute, join } from 'node:path';
import { V2Error } from './operations-v2.js';

const STATE_VERSION = 2;
const ENVELOPE_VERSION = 1;
const ALGORITHM = 'A256GCM';
const MAX_STATE_BYTES = 16 * 1024 * 1024;
const ROOT_KEYS_V1 = new Set(['version', 'generation', 'captured_at', 'approvals', 'execution_tokens', 'tasks']);
const ROOT_KEYS_V2 = new Set([...ROOT_KEYS_V1, 'operations']);
const ENVELOPE_KEYS = new Set(['version', 'generation', 'algorithm', 'iv', 'tag', 'ciphertext']);
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

function failure(code, message, status = 500) {
  return new V2Error(code, message, status);
}

function exactKeys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length === expected.size && keys.every((key) => expected.has(key));
}

function validTimestamp(value) {
  if (typeof value !== 'string') return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function requireComponent(component, name) {
  if (!component || typeof component.exportState !== 'function' || typeof component.restoreState !== 'function') {
    throw failure('state_component_invalid', `${name} state component is unavailable`);
  }
  return component;
}

function validateSnapshot(snapshot) {
  const rootKeys = snapshot?.version === 1 ? ROOT_KEYS_V1 : ROOT_KEYS_V2;
  if (!exactKeys(snapshot, rootKeys) || ![1, STATE_VERSION].includes(snapshot.version)
    || !Number.isSafeInteger(snapshot.generation) || snapshot.generation < 1
    || !validTimestamp(snapshot.captured_at)
    || !snapshot.approvals || typeof snapshot.approvals !== 'object' || Array.isArray(snapshot.approvals)
    || !snapshot.execution_tokens || typeof snapshot.execution_tokens !== 'object' || Array.isArray(snapshot.execution_tokens)
    || !snapshot.tasks || typeof snapshot.tasks !== 'object' || Array.isArray(snapshot.tasks)
    || (snapshot.version === STATE_VERSION
      && (!snapshot.operations || typeof snapshot.operations !== 'object' || Array.isArray(snapshot.operations)))) {
    throw failure('state_corrupt', 'control-plane state snapshot is invalid');
  }
}

export class ControlPlaneStateCoordinator {
  constructor({ approvals, executionTokens, tasks, operations, now = () => Date.now() } = {}) {
    this.approvals = requireComponent(approvals, 'approval');
    this.executionTokens = requireComponent(executionTokens, 'execution token');
    this.tasks = requireComponent(tasks, 'automation task');
    this.operations = requireComponent(operations, 'operation');
    this.now = now;
    this.generation = 0;
  }

  exportState() {
    const generation = this.generation + 1;
    return {
      version: STATE_VERSION,
      generation,
      captured_at: new Date(this.now()).toISOString(),
      approvals: this.approvals.exportState(),
      execution_tokens: this.executionTokens.exportState(),
      tasks: this.tasks.exportState(),
      operations: this.operations.exportState(),
    };
  }

  restoreState(snapshot) {
    validateSnapshot(snapshot);
    if (snapshot.generation < this.generation) {
      throw failure('state_rollback_detected', 'control-plane state generation is older than the active state');
    }
    const previous = {
      approvals: this.approvals.exportState(),
      executionTokens: this.executionTokens.exportState(),
      tasks: this.tasks.exportState(),
      operations: this.operations.exportState(),
      generation: this.generation,
    };
    try {
      this.approvals.restoreState(structuredClone(snapshot.approvals));
      this.executionTokens.restoreState(structuredClone(snapshot.execution_tokens));
      this.tasks.restoreState(structuredClone(snapshot.tasks));
      this.operations.restoreState(structuredClone(snapshot.version === 1 ? {
        version: 1, operations: [], otp_tasks: [], used_nonces: [], browser_claims: [], browser_leases: [],
      } : snapshot.operations));
      this.generation = snapshot.generation;
    } catch {
      try {
        this.approvals.restoreState(previous.approvals);
        this.executionTokens.restoreState(previous.executionTokens);
        this.tasks.restoreState(previous.tasks);
        this.operations.restoreState(previous.operations);
        this.generation = previous.generation;
      } catch {
        throw failure('state_rollback_failed', 'control-plane state rollback failed');
      }
      throw failure('state_restore_failed', 'control-plane state restore failed');
    }
  }

  commitGeneration(generation) {
    if (!Number.isSafeInteger(generation) || generation !== this.generation + 1) {
      throw failure('state_generation_invalid', 'control-plane state generation is invalid');
    }
    this.generation = generation;
  }
}

function decodeKey(contents) {
  if (contents.length === 32) return Buffer.from(contents);
  const encoded = contents.toString('utf8').trim();
  if (!/^[A-Za-z0-9_-]{43}$/.test(encoded)) throw failure('state_key_invalid', 'control-plane state key must contain exactly 256 bits');
  const decoded = Buffer.from(encoded, 'base64url');
  if (decoded.length !== 32) throw failure('state_key_invalid', 'control-plane state key must contain exactly 256 bits');
  return decoded;
}

export function loadControlPlaneStateKey(path) {
  if (typeof path !== 'string' || !isAbsolute(path)) {
    throw failure('state_key_invalid', 'control-plane state key path must be absolute');
  }
  try {
    const metadata = lstatSync(path);
    if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error('not a regular file');
    if (process.platform !== 'win32' && (metadata.mode & 0o077) !== 0) throw new Error('permissions are too broad');
    return decodeKey(readFileSync(path));
  } catch (error) {
    if (error instanceof V2Error) throw error;
    throw failure('state_key_unavailable', 'control-plane state key is unavailable');
  }
}

function aad(generation) {
  return Buffer.from(`secret-broker:control-plane-state:v${ENVELOPE_VERSION}:g${generation}`, 'utf8');
}

function syncParentDirectory(path) {
  if (process.platform === 'win32') return;
  const descriptor = openSync(path, 'r');
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function parseEnvelope(serialized) {
  let envelope;
  try {
    envelope = JSON.parse(serialized);
  } catch {
    throw failure('state_corrupt', 'encrypted control-plane state envelope is invalid');
  }
  if (!exactKeys(envelope, ENVELOPE_KEYS) || envelope.version !== ENVELOPE_VERSION
    || envelope.algorithm !== ALGORITHM || !Number.isSafeInteger(envelope.generation)
    || envelope.generation < 1 || !BASE64URL_RE.test(envelope.iv || '')
    || !BASE64URL_RE.test(envelope.tag || '') || !BASE64URL_RE.test(envelope.ciphertext || '')) {
    throw failure('state_corrupt', 'encrypted control-plane state envelope is invalid');
  }
  const iv = Buffer.from(envelope.iv, 'base64url');
  const tag = Buffer.from(envelope.tag, 'base64url');
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64url');
  if (iv.length !== 12 || tag.length !== 16 || ciphertext.length < 1 || ciphertext.length > MAX_STATE_BYTES) {
    throw failure('state_corrupt', 'encrypted control-plane state envelope bounds are invalid');
  }
  return { envelope, iv, tag, ciphertext };
}

export class EncryptedControlPlaneStateStore {
  constructor({ path, key, coordinator, syncDirectory = syncParentDirectory } = {}) {
    if (typeof path !== 'string' || !isAbsolute(path) || basename(path).length < 1) {
      throw failure('state_path_invalid', 'control-plane state path must be absolute');
    }
    if (!Buffer.isBuffer(key) || key.length !== 32) {
      throw failure('state_key_invalid', 'control-plane state key must contain exactly 256 bits');
    }
    this.path = path;
    this.key = Buffer.from(key);
    if (!(coordinator instanceof ControlPlaneStateCoordinator)) {
      throw failure('state_component_invalid', 'control-plane state coordinator is unavailable');
    }
    this.coordinator = coordinator;
    if (typeof syncDirectory !== 'function') {
      throw failure('state_component_invalid', 'control-plane directory sync is unavailable');
    }
    this.syncDirectory = syncDirectory;
    this.closed = false;
  }

  assertOpen() {
    if (this.closed) throw failure('state_store_closed', 'control-plane state store is closed', 503);
  }

  save() {
    this.assertOpen();
    const snapshot = this.coordinator.exportState();
    validateSnapshot(snapshot);
    const plaintext = Buffer.from(JSON.stringify(snapshot), 'utf8');
    if (plaintext.length > MAX_STATE_BYTES) throw failure('state_too_large', 'control-plane state exceeds the storage limit', 503);
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    cipher.setAAD(aad(snapshot.generation));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    plaintext.fill(0);
    const envelope = {
      version: ENVELOPE_VERSION,
      generation: snapshot.generation,
      algorithm: ALGORITHM,
      iv: iv.toString('base64url'),
      tag: cipher.getAuthTag().toString('base64url'),
      ciphertext: ciphertext.toString('base64url'),
    };
    const targetDirectory = dirname(this.path);
    const temporary = join(targetDirectory, `.${basename(this.path)}.${randomUUID()}.tmp`);
    let descriptor;
    let replaced = false;
    try {
      descriptor = openSync(temporary, 'wx', 0o600);
      writeFileSync(descriptor, `${JSON.stringify(envelope)}\n`, 'utf8');
      fsyncSync(descriptor);
      closeSync(descriptor);
      descriptor = undefined;
      chmodSync(temporary, 0o600);
      renameSync(temporary, this.path);
      replaced = true;
      this.coordinator.commitGeneration(snapshot.generation);
      this.syncDirectory(targetDirectory);
      return { version: envelope.version, generation: envelope.generation };
    } catch {
      if (descriptor !== undefined) {
        try { closeSync(descriptor); } catch { /* best effort */ }
      }
      if (existsSync(temporary)) {
        try { unlinkSync(temporary); } catch { /* best effort */ }
      }
      if (replaced) {
        throw failure(
          'state_commit_indeterminate',
          'control-plane state may have been committed and requires reconciliation',
          503,
        );
      }
      throw failure('state_write_failed', 'control-plane state could not be committed', 503);
    }
  }

  load({ required = true } = {}) {
    this.assertOpen();
    if (typeof required !== 'boolean') throw failure('invalid_request', 'required must be boolean', 400);
    if (!existsSync(this.path)) {
      if (required) throw failure('state_unavailable', 'control-plane state is unavailable', 503);
      return false;
    }
    let serialized;
    try {
      const metadata = lstatSync(this.path);
      if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size < 1
        || metadata.size > Math.ceil(MAX_STATE_BYTES * 1.5)) throw new Error('invalid state file');
      serialized = readFileSync(this.path, 'utf8');
    } catch {
      throw failure('state_unavailable', 'control-plane state is unavailable', 503);
    }
    const { envelope, iv, tag, ciphertext } = parseEnvelope(serialized);
    let plaintext;
    try {
      const decipher = createDecipheriv('aes-256-gcm', this.key, iv);
      decipher.setAAD(aad(envelope.generation));
      decipher.setAuthTag(tag);
      plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch {
      throw failure('state_decrypt_failed', 'control-plane state authentication failed', 503);
    }
    let snapshot;
    try {
      snapshot = JSON.parse(plaintext.toString('utf8'));
    } catch {
      throw failure('state_corrupt', 'control-plane state payload is invalid');
    } finally {
      plaintext.fill(0);
    }
    if (snapshot?.generation !== envelope.generation) {
      throw failure('state_corrupt', 'control-plane state generation does not match its envelope');
    }
    this.coordinator.restoreState(snapshot);
    return true;
  }

  close() {
    if (!this.closed) this.key.fill(0);
    this.closed = true;
  }
}
