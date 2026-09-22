// Review regressions: isolated module fixtures, not Docker/Nginx acceptance.
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { runInNewContext } from 'node:vm';
import { normalizeProxyMethod } from '../broker/can-proxy.js';
import { generateMasterKey, createChildKey, findApiKey, isExpired } from '../broker/api-keys.js';
import { resolveUpstreamUrl } from '../broker/lib/upstream-url.js';
import {
  buildProxyRequestHeaders,
  sanitizeProxyResponseHeaders,
} from '../broker/lib/proxy-headers.js';
import { sopsEncryptAtomic } from '../broker/lib/sops.js';
import { migrateV2ToV3 } from '../broker/migrate-v2-to-v3.js';
let checks = 0;
function check(name, condition) {
  assert.ok(condition, name);
  checks += 1;
  console.log(`PASS ${name}`);
}
{
  const { key_obj: parent } = generateMasterKey('review-parent', 'fixture-owner');
  const keys = [parent];
  const child = createChildKey(keys, parent, 'review-child');
  check('child authenticates while parent is valid', !!findApiKey(keys, child.secret));
  parent.revoked_at = new Date().toISOString();
  check(
    'parent revocation immediately rejects existing child',
    findApiKey(keys, child.secret) === null,
  );
  parent.revoked_at = null;
  const expiry = parent.expires_at;
  parent.expires_at = new Date(Date.now() - 1).toISOString();
  check('expired parent rejects child', findApiKey(keys, child.secret) === null);
  parent.expires_at = expiry;
  check(
    'missing parent rejects child',
    findApiKey(
      keys.filter((k) => k !== parent),
      child.secret,
    ) === null,
  );
  parent.client = 'different-owner';
  check('changed parent ownership rejects child', findApiKey(keys, child.secret) === null);
  parent.expires_at = new Date(Date.now() + 300).toISOString();
  check(
    'sub-second parent lifetime cannot mint a longer child',
    !createChildKey(keys, parent, 'too-late').ok,
  );
  check('missing expiry is denied', isExpired({}));
  check('malformed expiry is denied', isExpired({ expires_at: 'invalid' }));
  check('expiry boundary is exclusive', isExpired({ expires_at: new Date().toISOString() }));
}
{
  const base = 'https://upstream.invalid/';
  check(
    'dot segments are canonicalized before authorization',
    resolveUpstreamUrl(base, '/safe/%2e%2e/admin').pathname === '/admin',
  );
  for (const path of [
    '/safe%2fadmin',
    '/safe%5cadmin',
    '/safe/%252e%252e/admin',
    '/bad%zz',
    '/path#fragment',
    'https://u:p@upstream.invalid/safe',
    '/bad\\path',
  ]) {
    let denied = false;
    try {
      resolveUpstreamUrl(base, path);
    } catch {
      denied = true;
    }
    check(`ambiguous URL rejected: ${path}`, denied);
  }
  check(
    'query encoding remains supported',
    resolveUpstreamUrl(base, '/safe?q=a%2Fb').search === '?q=a%2Fb',
  );
  const outgoing = buildProxyRequestHeaders({
    userHeaders: { Connection: 'X-Hop', 'X-Hop': 'untrusted', Accept: 'application/json' },
  });
  check(
    'Connection-nominated request header is stripped',
    !('X-Hop' in outgoing) && outgoing.Accept === 'application/json',
  );
  const incoming = sanitizeProxyResponseHeaders({
    Connection: 'X-Hop',
    'X-Hop': 'private',
    'Set-Cookie': 'bad=1',
    'Content-Type': 'application/json',
  });
  check(
    'Connection-nominated response header is stripped',
    !('X-Hop' in incoming) && !('Set-Cookie' in incoming),
  );
}
{
  const dir = mkdtempSync(join(tmpdir(), 'broker-sops-review-'));
  const target = join(dir, 'broker.yaml');
  const original = 'encrypted-original-sentinel\n';
  writeFileSync(target, original);
  const beforePath = process.env.PATH;
  try {
    process.env.PATH = dir;
    const results = await Promise.allSettled(
      Array.from({ length: 8 }, (_, i) =>
        sopsEncryptAtomic(target, `fixture-${i}`, { ageKeyFile: join(dir, 'missing-age.key') }),
      ),
    );
    check(
      'all missing-SOPS writes reject',
      results.every((r) => r.status === 'rejected'),
    );
    check(
      'failed concurrent writes preserve original ciphertext',
      readFileSync(target, 'utf8') === original,
    );
    check('spawn failures leave no plaintext scratch files', readdirSync(dir).length === 1);
  } finally {
    process.env.PATH = beforePath;
    rmSync(dir, { recursive: true, force: true });
  }
}
{
  const config = { clients: {}, api_keys: { unexpected: { id: 'must-not-disappear' } } };
  const before = JSON.stringify(config);
  let denied = false;
  try {
    await migrateV2ToV3(
      config,
      'unused',
      () => {},
      async () => {},
    );
  } catch {
    denied = true;
  }
  check(
    'migration refuses to discard a non-empty legacy key store',
    denied && JSON.stringify(config) === before,
  );
}
// Administrative route boundary regressions discovered by the real preproduction
// suite. Exercise the existing pure normalization/validation functions without
// importing server.js (which would start a broker and read host credentials).
{
  const require = createRequire(new URL('../broker/package.json', import.meta.url));
  const { parse } = require('espree');
  const source = readFileSync(new URL('../broker/server.js', import.meta.url), 'utf8');
  const tree = parse(source, { ecmaVersion: 'latest', sourceType: 'module', range: true });
  const nodes = [];
  const visit = (node) => {
    if (!node || typeof node !== 'object') return;
    if (typeof node.type === 'string') nodes.push(node);
    for (const value of Object.values(node)) {
      if (Array.isArray(value)) value.forEach(visit);
      else if (value && typeof value === 'object') visit(value);
    }
  };
  visit(tree);
  const functionSource = (name) => {
    const node = nodes.find((n) => n.type === 'FunctionDeclaration' && n.id?.name === name);
    assert.ok(node, `missing function ${name}`);
    return source.slice(...node.range);
  };
  const helpers = runInNewContext(
    `${functionSource('normalizeServiceConfig')}\n${functionSource('validateServiceConfig')}\n({ normalizeServiceConfig, validateServiceConfig })`,
    {
      normalizeProxyMethod,
      validateConfiguredUpstream: () => new URL('https://fixture.invalid/'),
      isValidServiceName: (name) => name === 'fixture',
      isValidSecretName: () => true,
    },
    { timeout: 1000 },
  );
  const valid = helpers.normalizeServiceConfig({
    type: 'bearer',
    upstream: 'https://fixture.invalid/',
    allow_methods: ['get', 'POST', 'get'],
  });
  check(
    'service API retains and normalizes explicit method restrictions',
    JSON.stringify(valid.allow_methods) === JSON.stringify(['GET', 'POST']),
  );
  check('valid method restriction passes validation', helpers.validateServiceConfig('fixture', valid).length === 0);
  check(
    'description-only updates do not erase the existing method policy',
    !Object.hasOwn(helpers.normalizeServiceConfig({ description: 'changed' }), 'allow_methods'),
  );
  for (const value of ['GET', [], ['CONNECT'], [null]]) {
    const invalid = helpers.normalizeServiceConfig({ ...valid, allow_methods: value });
    check(
      `malformed method restriction fails closed: ${JSON.stringify(value)}`,
      helpers.validateServiceConfig('fixture', invalid).length > 0,
    );
  }
  const masterCalls = nodes.filter(
    (node) => node.type === 'CallExpression' && node.callee?.name === 'generateMasterKey',
  );
  check('master key creation has one reviewed routing boundary', masterCalls.length === 1);
  const argument = masterCalls[0].arguments[2];
  assert.equal(argument.type, 'ObjectExpression');
  const body = { allowed_services: ['echo'], allowed_secrets: ['visible'], child_scopes: ['services:proxy'] };
  const passedOptions = runInNewContext(
    `(${source.slice(...argument.range)})`,
    { body, ctx: { clientName: 'fixture' } },
    { timeout: 1000 },
  );
  check(
    'master route forwards the service allowlist to the key issuer',
    JSON.stringify(passedOptions.allowed_services) === JSON.stringify(body.allowed_services),
  );
  check(
    'master route forwards the secret allowlist to the key issuer',
    JSON.stringify(passedOptions.allowed_secrets) === JSON.stringify(body.allowed_secrets),
  );
  const { key_obj: parent } = generateMasterKey('restricted-master', 'fixture', passedOptions);
  check(
    'route-provided parent allowlist denies out-of-scope child services',
    !createChildKey([parent], parent, 'rejected-child', { allowed_services: ['hidden'] }).ok,
  );
}
console.log(`review-regressions: ${checks} passed, 0 failed`);
