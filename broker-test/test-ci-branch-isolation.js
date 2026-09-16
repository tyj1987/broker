// Guard development CI routing without granting a production release path.
// No network, credentials, provider operations, or workflow dispatch occurs here.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(new URL('../broker/package.json', import.meta.url));
const { parseDocument } = require('yaml');

function readWorkflow(name) {
  const text = readFileSync(new URL(`../.github/workflows/${name}`, import.meta.url), 'utf8');
  const doc = parseDocument(text, { uniqueKeys: true, strict: true });
  assert.equal(doc.errors.length, 0, `${name}: invalid or duplicate YAML keys`);
  assert.equal(doc.warnings.length, 0, `${name}: unexpected YAML warnings`);
  return doc.toJS();
}

const ci = readWorkflow('ci.yml');
const deploy = readWorkflow('deploy-ecs.yml');
const candidate = readWorkflow('candidate-verification.yml');
const expectedJobs = [
  'secret-scan', 'codeql', 'repository-security', 'broker', 'python-sdk',
  'documentation', 'go-sdk', 'go-core', 'vscode-sdk', 'android', 'ios',
  'browser-helper', 'browser-worker', 'desktop-windows', 'desktop-linux',
  'terraform', 'deployment-config', 'image',
];
const compact = (value) => typeof value === 'string' ? value.replace(/\s+/g, ' ').trim() : '';
const buildGuard = "github.event.workflow_run.conclusion == 'success' && " +
  'github.event.workflow_run.head_repository.full_name == github.repository && ' +
  "github.event.workflow_run.head_branch == 'master'";
const attestGuard = "github.event_name == 'push' && github.ref == 'refs/heads/master'";

function validate(main, production, sourceOnly) {
  assert.equal(main.name, 'CI');
  assert.deepEqual(Object.keys(main.on).sort(), ['pull_request', 'push', 'workflow_dispatch']);
  assert.deepEqual(main.on.push.branches, ['master', 'chatgpt/**']);
  assert.equal(main.on.push['branches-ignore'], undefined);
  assert.equal(main.on.push.tags, undefined);
  assert.equal(main.on.push['tags-ignore'], undefined);
  assert.deepEqual(main.on.pull_request.branches, ['master']);
  assert.deepEqual(main.permissions, { contents: 'read' });
  assert.deepEqual(Object.keys(main.jobs).sort(), [...expectedJobs].sort());
  for (const job of Object.values(main.jobs)) {
    assert.equal(job.environment, undefined, 'CI must not use a production environment');
    assert.equal(job['continue-on-error'], undefined, 'CI jobs must not suppress failures');
    for (const step of job.steps ?? []) {
      assert.equal(step['continue-on-error'], undefined, 'CI steps must not suppress failures');
    }
  }
  assert.deepEqual(main.jobs.codeql.strategy.matrix.language,
    ['actions', 'go', 'javascript-typescript', 'python']);
  assert.ok(main.jobs.broker.steps.some((step) => step.run === 'npm run test:coverage'));
  const imageBuild = main.jobs.image.steps.find((step) => step.uses?.startsWith('docker/build-push-action@'));
  assert.equal(imageBuild?.with?.push, false, 'CI must not publish images');
  const attestations = main.jobs.image.steps.filter((step) => step.uses?.startsWith('actions/attest@'));
  assert.equal(attestations.length, 2);
  for (const step of attestations) assert.equal(compact(step.if), attestGuard);

  assert.deepEqual(Object.keys(production.on), ['workflow_run']);
  assert.deepEqual(production.on.workflow_run, {
    workflows: ['CI'], types: ['completed'], branches: ['master'],
  });
  assert.equal(compact(production.jobs.build.if), buildGuard);
  const checkout = production.jobs.build.steps.find((step) => step.uses?.startsWith('actions/checkout@'));
  assert.equal(checkout?.with?.ref, 'master');
  assert.equal(checkout?.with?.['persist-credentials'], false);
  assert.equal(production.jobs.deploy.needs, 'build');
  assert.equal(production.jobs.deploy.environment, 'production-aliyun');

  assert.deepEqual(Object.keys(sourceOnly.on), ['push']);
  assert.deepEqual(sourceOnly.on.push, { branches: ['chatgpt/**'] });
  assert.deepEqual(sourceOnly.permissions, { contents: 'read' });
  for (const job of Object.values(sourceOnly.jobs)) {
    assert.equal(job.environment, undefined);
    assert.equal(job.permissions, undefined, 'candidate jobs cannot expand permissions');
    assert.ok(Number.isSafeInteger(job['timeout-minutes']) && job['timeout-minutes'] > 0);
  }
  assert.ok(sourceOnly.jobs['broker-regression'].steps.some((step) =>
    step.run === 'node ../broker-test/test-ci-branch-isolation.js'));
}

validate(ci, deploy, candidate);
let cases = 1;
const reject = (name, mutation) => {
  const state = [structuredClone(ci), structuredClone(deploy), structuredClone(candidate)];
  mutation(...state);
  assert.throws(() => validate(...state), { name: 'AssertionError' }, name);
  cases += 1;
};
reject('missing full-CI candidate trigger', (main) => { main.on.push.branches = ['master']; });
reject('wildcard full-CI trigger', (main) => { main.on.push.branches = ['**']; });
reject('tag-triggered full CI', (main) => { main.on.push.tags = ['v*']; });
reject('branch-ignore ambiguity', (main) => { main.on.push['branches-ignore'] = ['master']; });
reject('privileged pull_request_target', (main) => { main.on.pull_request_target = {}; });
reject('expanded CI default permissions', (main) => { main.permissions.contents = 'write'; });
reject('missing Go core', (main) => { delete main.jobs['go-core']; });
reject('missing browser worker', (main) => { delete main.jobs['browser-worker']; });
reject('removed CodeQL language', (main) => { main.jobs.codeql.strategy.matrix.language.pop(); });
reject('removed Node coverage', (main) => {
  main.jobs.broker.steps = main.jobs.broker.steps.filter((step) => step.run !== 'npm run test:coverage');
});
reject('ignored job failure', (main) => { main.jobs.broker['continue-on-error'] = true; });
reject('ignored step failure', (main) => { main.jobs.broker.steps[0]['continue-on-error'] = true; });
reject('CI production environment', (main) => { main.jobs.broker.environment = 'production-aliyun'; });
reject('CI image publication', (main) => {
  main.jobs.image.steps.find((step) => step.uses?.startsWith('docker/build-push-action@')).with.push = true;
});
reject('unconditional attestation', (main) => {
  delete main.jobs.image.steps.find((step) => step.uses?.startsWith('actions/attest@')).if;
});
reject('broad deployment branch filter', (_main, production) => { production.on.workflow_run.branches = ['**']; });
reject('candidate workflow may trigger deployment', (_main, production) => {
  production.on.workflow_run.workflows.push('Broker candidate verification');
});
reject('extra production trigger', (_main, production) => { production.on.push = {}; });
reject('deployment build has no branch guard', (_main, production) => { delete production.jobs.build.if; });
reject('OR bypass in deployment condition', (_main, production) => { production.jobs.build.if += ' || true'; });
reject('dynamic production checkout', (_main, production) => {
  production.jobs.build.steps.find((step) => step.uses?.startsWith('actions/checkout@')).with.ref = '${{ github.ref }}';
});
reject('deployment dependency bypass', (_main, production) => { delete production.jobs.deploy.needs; });
reject('production environment bypass', (_main, production) => { delete production.jobs.deploy.environment; });
reject('candidate default permission expansion', (_main, _production, sourceOnly) => { sourceOnly.permissions.contents = 'write'; });
reject('candidate job permission expansion', (_main, _production, sourceOnly) => { sourceOnly.jobs['broker-regression'].permissions = { contents: 'write' }; });
reject('candidate production environment', (_main, _production, sourceOnly) => { sourceOnly.jobs['broker-regression'].environment = 'production-aliyun'; });
reject('removed candidate timeout', (_main, _production, sourceOnly) => { delete sourceOnly.jobs['broker-regression']['timeout-minutes']; });
console.log(`CI branch isolation: ${cases} positive/negative checks passed; no deployment executed`);
