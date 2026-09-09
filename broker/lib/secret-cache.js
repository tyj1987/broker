const SECRET_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;

export class SecretCacheLoadError extends Error {
  constructor(message, options = {}) {
    super(message, options);
    this.name = 'SecretCacheLoadError';
    this.code = 'secret_store_invalid';
  }
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function buildSecretCache(document, normalizeEntry) {
  if (!isRecord(document) || !isRecord(document.secrets) || typeof normalizeEntry !== 'function') {
    throw new SecretCacheLoadError('structured secret store is invalid');
  }
  const candidate = new Map();
  try {
    for (const [name, entry] of Object.entries(document.secrets)) {
      if (!SECRET_NAME_RE.test(name) || !isRecord(entry)) throw new Error('invalid secret entry');
      candidate.set(name, normalizeEntry(name, entry));
    }
  } catch (cause) {
    throw new SecretCacheLoadError('structured secret store is invalid', { cause });
  }
  return candidate;
}

export async function loadSecretCacheCandidate({
  structuredExists,
  legacyExists,
  readStructured,
  migrateLegacy,
  normalizeEntry,
}) {
  if (structuredExists) {
    try {
      const document = await readStructured();
      return { cache: buildSecretCache(document, normalizeEntry), source: 'structured' };
    } catch (cause) {
      if (cause instanceof SecretCacheLoadError) throw cause;
      throw new SecretCacheLoadError('structured secret store could not be loaded', { cause });
    }
  }
  if (legacyExists) {
    try {
      const secrets = await migrateLegacy();
      return { cache: buildSecretCache({ secrets }, normalizeEntry), source: 'legacy' };
    } catch (cause) {
      if (cause instanceof SecretCacheLoadError) throw cause;
      throw new SecretCacheLoadError('legacy secret store could not be migrated', { cause });
    }
  }
  return { cache: new Map(), source: 'empty' };
}

export function replaceSecretCache(active, candidate) {
  if (!(active instanceof Map) || !(candidate instanceof Map)) {
    throw new TypeError('secret caches must be maps');
  }
  active.clear();
  for (const [name, entry] of candidate) active.set(name, entry);
}
