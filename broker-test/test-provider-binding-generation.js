import assert from 'node:assert/strict';

import { providerBindingGeneration } from '../broker/lib/provider-binding-generation.js';

const config = {
  provider_accounts: {
    github: {
      'github-isolated': {
        client_id: 'Iv1.test',
        installation_id: 123,
        environments: ['staging'],
        repositories: ['owner/repository'],
      },
    },
    aliyun: {
      'aliyun-isolated': {
        environments: ['staging'],
        regions: ['cn-hangzhou'],
        resources: ['isolated-inventory'],
      },
    },
  },
  operation_policies: {
    github: {
      'repo.read': {
        enabled: true,
        contract_verified: true,
        execution_mode: 'adapter',
        accounts: ['github-isolated'],
      },
    },
    aliyun: {
      'ecs.instances.list': {
        enabled: true,
        contract_verified: true,
        execution_mode: 'adapter',
        accounts: ['aliyun-isolated'],
      },
    },
  },
};

const first = providerBindingGeneration(config);
assert.match(first, /^[a-f0-9]{64}$/u);
assert.equal(providerBindingGeneration(structuredClone(config)), first);

const reordered = {
  operation_policies: config.operation_policies,
  provider_accounts: config.provider_accounts,
};
assert.equal(providerBindingGeneration(reordered), first);

const changed = structuredClone(config);
changed.provider_accounts.aliyun['aliyun-isolated'].regions = ['cn-shanghai'];
assert.notEqual(providerBindingGeneration(changed), first);

const unrelated = structuredClone(config);
unrelated.services = { example: { upstream: 'https://example.invalid' } };
assert.equal(providerBindingGeneration(unrelated), first);

for (const invalid of [null, undefined, [], 'config']) {
  assert.throws(() => providerBindingGeneration(invalid), TypeError);
}

console.log('provider binding generation: stable scoped commitment passed');
