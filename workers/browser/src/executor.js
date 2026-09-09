const ID_RE = /^[a-z0-9][a-z0-9._:-]{0,127}$/;
const FORBIDDEN_INPUT_KEYS = /^(?:url|uri|selector|script|javascript|headers?|cookies?|storage_state|storageState|devtools|cdp)$/i;
const SENSITIVE_OUTPUT_KEYS = /(?:secret|token|password|authorization|cookie|session|credential|private.?key|otp|code)/i;
const MAX_RESULT_BYTES = 64 * 1024;
const REQUEST_KEYS = new Set(['provider', 'operation_id', 'account_ref', 'environment', 'typed_parameters']);
const ENVIRONMENTS = new Set(['development', 'staging', 'production']);

export class BrowserWorkerError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'BrowserWorkerError';
    this.code = code;
  }
}

function requireId(value, field) {
  if (typeof value !== 'string' || !ID_RE.test(value)) {
    throw new BrowserWorkerError('invalid_request', `${field} has an invalid format`);
  }
  return value;
}

function inspectTypedValue(value, depth = 0) {
  if (depth > 8) throw new BrowserWorkerError('invalid_request', 'typed_parameters is too deeply nested');
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) return;
  if (Array.isArray(value)) {
    if (value.length > 100) throw new BrowserWorkerError('invalid_request', 'typed_parameters array is too large');
    for (const item of value) inspectTypedValue(item, depth + 1);
    return;
  }
  if (typeof value !== 'object') throw new BrowserWorkerError('invalid_request', 'typed_parameters contains an unsupported value');
  for (const [key, item] of Object.entries(value)) {
    if (FORBIDDEN_INPUT_KEYS.test(key)) {
      throw new BrowserWorkerError('forbidden_parameter', `typed parameter is controlled by the adapter: ${key}`);
    }
    inspectTypedValue(item, depth + 1);
  }
}

function normalizedDescriptor(adapter) {
  const provider = requireId(adapter?.provider, 'provider');
  const operationId = requireId(adapter?.operationId, 'operation_id');
  if (typeof adapter.execute !== 'function') throw new BrowserWorkerError('invalid_adapter', 'adapter execute function is required');
  let start;
  try { start = new URL(adapter.startUrl); } catch { throw new BrowserWorkerError('invalid_adapter', 'adapter start URL is invalid'); }
  if (start.protocol !== 'https:' || start.username || start.password || start.hash) {
    throw new BrowserWorkerError('invalid_adapter', 'adapter start URL must be a credential-free HTTPS URL');
  }
  const origins = new Set((adapter.allowedOrigins || []).map((value) => new URL(value).origin));
  origins.add(start.origin);
  for (const origin of origins) {
    if (!origin.startsWith('https://')) throw new BrowserWorkerError('invalid_adapter', 'adapter origins must use HTTPS');
  }
  return Object.freeze({ provider, operationId, startUrl: start.toString(), origins, execute: adapter.execute });
}

function inspectResult(value, depth = 0) {
  if (depth > 8) throw new BrowserWorkerError('unsafe_result', 'adapter result is too deeply nested');
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) return;
  if (Array.isArray(value)) {
    for (const item of value) inspectResult(item, depth + 1);
    return;
  }
  if (typeof value !== 'object') throw new BrowserWorkerError('unsafe_result', 'adapter result contains an unsupported value');
  for (const [key, item] of Object.entries(value)) {
    if (SENSITIVE_OUTPUT_KEYS.test(key)) throw new BrowserWorkerError('unsafe_result', 'adapter result contains a sensitive field');
    inspectResult(item, depth + 1);
  }
}

function safeResult(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new BrowserWorkerError('unsafe_result', 'adapter result must be an object');
  }
  inspectResult(value);
  let encoded;
  try { encoded = JSON.stringify(value); } catch { throw new BrowserWorkerError('unsafe_result', 'adapter result is not serializable'); }
  if (Buffer.byteLength(encoded) > MAX_RESULT_BYTES) throw new BrowserWorkerError('unsafe_result', 'adapter result is too large');
  return JSON.parse(encoded);
}

export class BrowserOperationExecutor {
  constructor({ browser, adapters, timeoutMs = 60_000 }) {
    if (!browser || typeof browser.newContext !== 'function') throw new BrowserWorkerError('invalid_runtime', 'browser is required');
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 300_000) {
      throw new BrowserWorkerError('invalid_runtime', 'timeout must be from 1 to 300 seconds');
    }
    this.browser = browser;
    this.timeoutMs = timeoutMs;
    this.adapters = new Map();
    for (const adapter of adapters || []) {
      const descriptor = normalizedDescriptor(adapter);
      const key = `${descriptor.provider}:${descriptor.operationId}`;
      if (this.adapters.has(key)) throw new BrowserWorkerError('invalid_adapter', 'duplicate adapter');
      this.adapters.set(key, descriptor);
    }
  }

  async execute(request) {
    if (!request || typeof request !== 'object' || Array.isArray(request)) {
      throw new BrowserWorkerError('invalid_request', 'operation request must be an object');
    }
    for (const key of Object.keys(request)) {
      if (!REQUEST_KEYS.has(key)) throw new BrowserWorkerError('forbidden_parameter', `request field is not allowed: ${key}`);
    }
    const provider = requireId(request?.provider, 'provider');
    const operationId = requireId(request?.operation_id, 'operation_id');
    requireId(request?.account_ref, 'account_ref');
    if (!ENVIRONMENTS.has(request?.environment)) throw new BrowserWorkerError('invalid_request', 'environment is invalid');
    const parameters = request.typed_parameters || {};
    if (!parameters || typeof parameters !== 'object' || Array.isArray(parameters)) {
      throw new BrowserWorkerError('invalid_request', 'typed_parameters must be an object');
    }
    let encodedParameters;
    try { encodedParameters = JSON.stringify(parameters); } catch { throw new BrowserWorkerError('invalid_request', 'typed_parameters is not serializable'); }
    if (Buffer.byteLength(encodedParameters) > MAX_RESULT_BYTES) {
      throw new BrowserWorkerError('invalid_request', 'typed_parameters is too large');
    }
    inspectTypedValue(parameters);
    const adapter = this.adapters.get(`${provider}:${operationId}`);
    if (!adapter) throw new BrowserWorkerError('operation_denied', 'operation has no reviewed browser adapter');

    const context = await this.browser.newContext({
      acceptDownloads: false,
      serviceWorkers: 'block',
      permissions: [],
    });
    let timer;
    try {
      await context.route('**/*', async (route) => {
        let origin;
        try { origin = new URL(route.request().url()).origin; } catch { return route.abort('blockedbyclient'); }
        return adapter.origins.has(origin) ? route.continue() : route.abort('blockedbyclient');
      });
      const page = await context.newPage();
      const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => reject(new BrowserWorkerError('operation_timeout', 'browser operation timed out')), this.timeoutMs);
        timer.unref?.();
      });
      const result = await Promise.race([
        adapter.execute({ page, startUrl: adapter.startUrl, parameters: structuredClone(parameters) }),
        timeout,
      ]);
      return safeResult(result);
    } finally {
      clearTimeout(timer);
      await context.close({ reason: 'operation_complete' });
    }
  }
}
