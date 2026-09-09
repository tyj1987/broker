import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';

import { createGitHubRepositoryReadExecutor } from '../broker/adapters/github-repository-read-executor.js';

const NOW = 2_000_000_000_000;
const calls = [];
const requestImpl = (options, callback) => {
  const request = new EventEmitter();
  request.setTimeout = () => {};
  request.destroy = () => {};
  request.end = (body) => {
    calls.push({ options, body: body?.toString() });
    const tokenRequest = options.path.includes('/access_tokens');
    const responseBody = tokenRequest
      ? {
          token: 'short-lived-installation-token',
          expires_at: new Date(NOW + 60 * 60_000).toISOString(),
          permissions: { metadata: 'read' },
          repositories: [{ full_name: 'tyj1987/broker' }],
        }
      : { id: 123, full_name: 'tyj1987/broker', visibility: 'public', archived: false };
    const response = Readable.from([JSON.stringify(responseBody)]);
    response.statusCode = tokenRequest ? 201 : 200;
    response.headers = { 'content-type': 'application/json' };
    queueMicrotask(() => callback(response));
  };
  return request;
};

const executor = createGitHubRepositoryReadExecutor({
  now: () => NOW,
  resolveHost: async () => [{ address: '93.184.216.34', family: 4 }],
  requestImpl,
  accountResolver: async ({ account_ref, environment }) => ({
    account_ref,
    environment,
    client_id: 'Iv1.integration-test',
    installation_id: 12345,
    repositories: ['tyj1987/broker'],
  }),
  signer: async () => Buffer.alloc(256, 9),
});
const result = await executor(
  { resource_ref: 'tyj1987/broker', owner: 'tyj1987', repo: 'broker' },
  {
    accountRef: 'github-primary',
    environment: 'production',
    execution: {
      tool: 'github.repository.read@1.0.0',
      target: 'tyj1987/broker',
      environment: 'production',
    },
  },
);
assert.deepEqual(result, {
  id: 123,
  full_name: 'tyj1987/broker',
  visibility: 'public',
  archived: false,
});
assert.equal(calls.length, 2);
assert.equal(calls[0].options.path, '/app/installations/12345/access_tokens');
assert.deepEqual(JSON.parse(calls[0].body), {
  repositories: ['broker'],
  permissions: { metadata: 'read' },
});
assert.match(calls[0].options.headers.authorization, /^Bearer [^.]+\.[^.]+\.[^.]+$/);
assert.equal(calls[1].options.path, '/repos/tyj1987/broker');
assert.equal(calls[1].options.headers.authorization, 'Bearer short-lived-installation-token');
assert.equal(JSON.stringify(result).includes('short-lived-installation-token'), false);

console.log('github repository executor: signer to scoped token to bounded business result passed');
