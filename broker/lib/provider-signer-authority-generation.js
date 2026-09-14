import { randomBytes as cryptoRandomBytes } from 'node:crypto';
import net from 'node:net';

const PROBE_VERSION = 1;
const PROBE_OPERATION = 'authority_generation.read';
const MAX_RESPONSE_BYTES = 512;
const SHA256_RE = /^[a-f0-9]{64}$/u;
const CHALLENGE_RE = /^[A-Za-z0-9_-]{43}$/u;
const PROVIDERS = Object.freeze({
  github: '/run/secret-broker-github-signer/signer.sock',
  aliyun: '/run/secret-broker-aliyun-signer/signer.sock',
});

export class ProviderSignerGenerationError extends Error {
  constructor(code) {
    super(code);
    this.name = 'ProviderSignerGenerationError';
    this.code = code;
  }
}

function fail() {
  throw new ProviderSignerGenerationError('provider_signer_generation_unavailable');
}

function decodeResponse(value, challenge) {
  if (!Buffer.isBuffer(value) || value.length < 2 || value.length > MAX_RESPONSE_BYTES) fail();
  const text = value.toString('utf8');
  if (!text.endsWith('\n') || text.endsWith('\n\n') || text.includes('\r')) fail();
  let response;
  try {
    response = JSON.parse(text.slice(0, -1));
  } catch {
    fail();
  }
  const keys =
    response && typeof response === 'object' && !Array.isArray(response)
      ? Object.keys(response)
      : [];
  const canonicalResponse = `${JSON.stringify({
    version: response?.version,
    operation: response?.operation,
    challenge: response?.challenge,
    authority_generation_sha256: response?.authority_generation_sha256,
  })}\n`;
  if (
    text !== canonicalResponse ||
    keys.length !== 4 ||
    !keys.every((key) =>
      ['version', 'operation', 'challenge', 'authority_generation_sha256'].includes(key),
    ) ||
    response.version !== PROBE_VERSION ||
    response.operation !== PROBE_OPERATION ||
    response.challenge !== challenge ||
    typeof response.authority_generation_sha256 !== 'string' ||
    !SHA256_RE.test(response.authority_generation_sha256)
  ) {
    fail();
  }
  return response.authority_generation_sha256;
}

function probeOne({ socketPath, connect, randomBytes, timeoutMs, setTimer, clearTimer }) {
  let challenge;
  try {
    challenge = Buffer.from(randomBytes(32)).toString('base64url');
  } catch {
    fail();
  }
  if (!CHALLENGE_RE.test(challenge)) fail();
  const payload = `${JSON.stringify({
    version: PROBE_VERSION,
    operation: PROBE_OPERATION,
    challenge,
  })}\n`;
  return new Promise((resolve, reject) => {
    let socket;
    let settled = false;
    let size = 0;
    const chunks = [];
    let timer;
    const finish = (handler, value) => {
      if (settled) return;
      settled = true;
      clearTimer(timer);
      socket?.destroy?.();
      handler(value);
    };
    const rejectSafe = () =>
      finish(reject, new ProviderSignerGenerationError('provider_signer_generation_unavailable'));
    timer = setTimer(rejectSafe, timeoutMs);
    try {
      socket = connect({ path: socketPath }, () => socket.end(payload));
      socket.on('data', (chunk) => {
        if (settled) return;
        const bytes = Buffer.from(chunk);
        size += bytes.length;
        if (size > MAX_RESPONSE_BYTES) return rejectSafe();
        chunks.push(bytes);
      });
      socket.on('end', () => {
        if (settled) return;
        try {
          finish(resolve, decodeResponse(Buffer.concat(chunks), challenge));
        } catch {
          rejectSafe();
        }
      });
      socket.on('error', rejectSafe);
    } catch {
      rejectSafe();
    }
  });
}

export async function readProviderSignerAuthorityGenerations({
  connect = net.createConnection,
  randomBytes = cryptoRandomBytes,
  timeoutMs = 2_000,
  setTimer = setTimeout,
  clearTimer = clearTimeout,
} = {}) {
  if (
    typeof connect !== 'function' ||
    typeof randomBytes !== 'function' ||
    typeof setTimer !== 'function' ||
    typeof clearTimer !== 'function' ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 100 ||
    timeoutMs > 10_000
  ) {
    throw new TypeError('Provider signer generation probe configuration is invalid');
  }
  const [github, aliyun] = await Promise.all(
    Object.values(PROVIDERS).map((socketPath) =>
      probeOne({ socketPath, connect, randomBytes, timeoutMs, setTimer, clearTimer }),
    ),
  );
  return Object.freeze({ github, aliyun });
}

export const PROVIDER_SIGNER_AUTHORITY_GENERATION_CONTRACT = Object.freeze({
  version: PROBE_VERSION,
  operation: PROBE_OPERATION,
  providers: Object.freeze(Object.keys(PROVIDERS)),
  sockets: PROVIDERS,
  maximum_response_bytes: MAX_RESPONSE_BYTES,
  maximum_timeout_ms: 10_000,
  secret_material_returned: false,
});
