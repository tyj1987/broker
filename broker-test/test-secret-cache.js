import assert from 'node:assert/strict';
import {
  SecretCacheLoadError,
  buildSecretCache,
  loadSecretCacheCandidate,
  replaceSecretCache,
} from '../broker/lib/secret-cache.js';

const normalize = (name, entry) => ({ name, fields: { ...entry.fields } });

const candidate = buildSecretCache({ secrets: { github: { fields: { token: 'canary' } } } }, normalize);
assert.equal(candidate.get('github').fields.token, 'canary');
assert.throws(() => buildSecretCache(null, normalize), SecretCacheLoadError);
assert.throws(() => buildSecretCache({ secrets: [] }, normalize), SecretCacheLoadError);
assert.throws(() => buildSecretCache({ secrets: {} }, null), SecretCacheLoadError);
assert.throws(
  () => buildSecretCache({ secrets: { github: { fields: {} } } }, () => { throw new Error('bad normalization'); }),
  SecretCacheLoadError,
);

const active = new Map([['current', { fields: { token: 'preserved' } }]]);
assert.throws(
  () => buildSecretCache({ secrets: { valid: { fields: {} }, 'bad/name': { fields: {} } } }, normalize),
  (error) => error instanceof SecretCacheLoadError && !error.message.includes('preserved'),
);
assert.equal(active.get('current').fields.token, 'preserved');

let legacyCalls = 0;
await assert.rejects(
  loadSecretCacheCandidate({
    structuredExists: true,
    legacyExists: true,
    readStructured: async () => { throw new Error('canary-secret-must-not-leak'); },
    migrateLegacy: async () => { legacyCalls++; return {}; },
    normalizeEntry: normalize,
  }),
  (error) => error instanceof SecretCacheLoadError
    && error.code === 'secret_store_invalid'
    && !error.message.includes('canary-secret-must-not-leak'),
);
assert.equal(legacyCalls, 0, 'a broken structured store must not reactivate legacy credentials');
assert.equal(active.get('current').fields.token, 'preserved');

const structured = await loadSecretCacheCandidate({
  structuredExists: true,
  legacyExists: false,
  readStructured: async () => ({ secrets: { current: { fields: {} } } }),
  migrateLegacy: async () => ({}),
  normalizeEntry: normalize,
});
assert.equal(structured.source, 'structured');
await assert.rejects(
  loadSecretCacheCandidate({
    structuredExists: true,
    legacyExists: false,
    readStructured: async () => ({ secrets: null }),
    migrateLegacy: async () => ({}),
    normalizeEntry: normalize,
  }),
  SecretCacheLoadError,
);

const migrated = await loadSecretCacheCandidate({
  structuredExists: false,
  legacyExists: true,
  readStructured: async () => { throw new Error('must not run'); },
  migrateLegacy: async () => ({ migrated: { fields: { token: 'short-lived' } } }),
  normalizeEntry: normalize,
});
assert.equal(migrated.source, 'legacy');
assert.equal(active.has('migrated'), false, 'candidate loading does not mutate active state');
replaceSecretCache(active, migrated.cache);
assert.equal(active.has('current'), false);
assert.equal(active.get('migrated').fields.token, 'short-lived');
await assert.rejects(
  loadSecretCacheCandidate({
    structuredExists: false,
    legacyExists: true,
    readStructured: async () => ({}),
    migrateLegacy: async () => { throw new Error('migration unavailable'); },
    normalizeEntry: normalize,
  }),
  (error) => error instanceof SecretCacheLoadError && error.message === 'legacy secret store could not be migrated',
);
await assert.rejects(
  loadSecretCacheCandidate({
    structuredExists: false,
    legacyExists: true,
    readStructured: async () => ({}),
    migrateLegacy: async () => null,
    normalizeEntry: normalize,
  }),
  SecretCacheLoadError,
);
assert.throws(() => replaceSecretCache({}, new Map()), TypeError);
assert.throws(() => replaceSecretCache(new Map(), {}), TypeError);

const empty = await loadSecretCacheCandidate({
  structuredExists: false,
  legacyExists: false,
  readStructured: async () => ({}),
  migrateLegacy: async () => ({}),
  normalizeEntry: normalize,
});
assert.equal(empty.source, 'empty');
assert.equal(empty.cache.size, 0);

console.log('secret cache: candidate loading, fail-closed fallback and atomic replacement passed');
