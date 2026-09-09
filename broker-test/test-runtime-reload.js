import assert from 'node:assert/strict';
import { reloadRuntimeAtomically } from '../broker/lib/runtime-reload.js';

await assert.rejects(reloadRuntimeAtomically({}), TypeError);
await assert.rejects(reloadRuntimeAtomically({ prepareConfig: async () => null }), TypeError);
await assert.rejects(reloadRuntimeAtomically({
  prepareConfig: async () => null,
  prepareSecrets: async () => null,
}), TypeError);

const active = { config: 'old-config', secrets: 'old-secrets' };
let commits = 0;
await assert.rejects(
  reloadRuntimeAtomically({
    prepareConfig: async () => 'new-config',
    prepareSecrets: async () => { throw new Error('secret candidate rejected'); },
    commit: ({ config, secrets }) => {
      commits++;
      active.config = config;
      active.secrets = secrets;
    },
  }),
  /secret candidate rejected/,
);
assert.equal(commits, 0);
assert.deepEqual(active, { config: 'old-config', secrets: 'old-secrets' });

let secretPreparationCalls = 0;
await assert.rejects(
  reloadRuntimeAtomically({
    prepareConfig: async () => { throw new Error('config candidate rejected'); },
    prepareSecrets: async () => { secretPreparationCalls++; return 'unused'; },
    commit: () => { commits++; },
  }),
  /config candidate rejected/,
);
assert.equal(secretPreparationCalls, 0);
assert.equal(commits, 0);

const committed = await reloadRuntimeAtomically({
  prepareConfig: async () => 'new-config',
  prepareSecrets: async () => 'new-secrets',
  commit: (candidates) => {
    commits++;
    active.config = candidates.config;
    active.secrets = candidates.secrets;
    return 'committed';
  },
});
assert.equal(committed, 'committed');
assert.equal(commits, 1);
assert.deepEqual(active, { config: 'new-config', secrets: 'new-secrets' });

console.log('runtime reload: candidate preparation and atomic commit boundary passed');
