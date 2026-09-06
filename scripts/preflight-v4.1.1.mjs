#!/usr/bin/env node
// scripts/preflight-v4.1.1.mjs
//
// V4.1.1 release pre-flight check.
// Run this BEFORE tagging v4.1.1 / creating GitHub Release.
// Verifies: version sync, all 4 SDK versions, CHANGELOG entry, RELEASE-NOTES, ROADMAP, STATUS, AWAITING-USER V13.
// Cross-platform (Node 18+); no bash / python dependencies.
//
// Usage:
//   node scripts/preflight-v4.1.1.mjs
//   node scripts/preflight-v4.1.1.mjs --version 4.1.2   # check a different version
//   node scripts/preflight-v4.1.1.mjs --strict         # exit non-zero on any WARNING (default: only on FAIL)
//   node scripts/preflight-v4.1.1.mjs --self-test      # run internal unit tests for branch regex + helpers, then exit
//
// Exit code:
//   0  all checks PASS (or self-test passed)
//   1  one or more FAIL (or self-test failed)
//   2  one or more WARNING (only with --strict)
//
// Output: human-readable; line-by-line status; summary at the end.

import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, '..');

// === Parse args ===
const args = process.argv.slice(2);
let VERSION = '4.1.1';
let STRICT = false;
let SELF_TEST = false;
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--version' && args[i + 1]) {
    VERSION = args[i + 1];
    i++;
  } else if (args[i] === '--strict') {
    STRICT = true;
  } else if (args[i] === '--self-test') {
    SELF_TEST = true;
  } else if (args[i] === '-h' || args[i] === '--help') {
    console.log(readFileSync(__filename, 'utf8').split('\n').slice(1, 25).join('\n'));
    process.exit(0);
  }
}
const TAG = `v${VERSION}`;

// === Output helpers ===
const RED = '\x1b[0;31m', GREEN = '\x1b[0;32m', YELLOW = '\x1b[1;33m', CYAN = '\x1b[0;36m', NC = '\x1b[0m';
const useColor = process.stdout.isTTY;
const color = (c, s) => useColor ? `${c}${s}${NC}` : s;

let passCount = 0, warnCount = 0, failCount = 0;
const results = [];

function record(status, name, detail) {
  const symbol = status === 'PASS' ? color(GREEN, '✓') :
                 status === 'WARN' ? color(YELLOW, '⚠') :
                                      color(RED, '✗');
  console.log(`  ${symbol} ${color(CYAN, name)}: ${detail}`);
  results.push({ status, name, detail });
  if (status === 'PASS') passCount++;
  else if (status === 'WARN') warnCount++;
  else failCount++;
}

function header(label) {
  console.log(`\n${color(CYAN, '═══')} ${label} ${color(CYAN, '═══')}`);
}

function safeRead(p) {
  try { return readFileSync(p, 'utf8'); } catch { return null; }
}

function tryGit(cmd) {
  try {
    return execSync(`git ${cmd}`, { cwd: REPO_ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch { return null; }
}

// === Self-test (regression test for branch regex + helpers) ===
// Run with `node scripts/preflight-v4.1.1.mjs --self-test` to validate
// internal helpers without needing network or full repo state.
function runSelfTest() {
  console.log(`${color(CYAN, 'preflight-v4.1.1 self-test')}\n`);
  let pass = 0, fail = 0;

  function expect(name, actual, expected) {
    const ok = JSON.stringify(actual) === JSON.stringify(expected);
    if (ok) {
      pass++;
      console.log(`  ${color(GREEN, '✓')} ${name}`);
    } else {
      fail++;
      console.log(`  ${color(RED, '✗')} ${name}`);
      console.log(`      expected: ${JSON.stringify(expected)}`);
      console.log(`      actual:   ${JSON.stringify(actual)}`);
    }
  }

  // Branch regex — exact version token v4.1.1, not v4.1.10+
  // (Same logic as origin state check; tested against representative branches)
  const V411_RE = /(?:^|[^.\d])v?4\.1\.1(?:[^.\d]|$)/;
  const shouldMatch = [
    'chore/codeowners-v4.1.1',
    'chore/editorconfig-v4.1.1',
    'docs/sdk-v4.1.1-parity-reference',
    'feat/sdk-cli-errors-v4.1.1',
    'feat/v4.1.1-verify-all-runner',
    'release/v4.1.1',
    'release/v4.1.1-sdk-parity-notes',
  ];
  const shouldNotMatch = [
    'feat/v4.1.2-patch-prep',     // different minor
    'feat/v4.1.10-future',         // v4.1.10 NOT v4.1.1
    'feat/v4.1.11-other',          // v4.1.11 NOT v4.1.1 (digit after)
    'feat/v4.2.0-design-spec',     // different major.minor
    'main',                        // no v4.1.1
    'docs/sdk-v4.1.10-typo',       // false positive guard
    'docs/v4.1.100-future',        // v4.1.100 NOT v4.1.1
  ];
  for (const name of shouldMatch) {
    expect(`regex matches ${name}`, V411_RE.test(name), true);
  }
  for (const name of shouldNotMatch) {
    expect(`regex excludes ${name}`, V411_RE.test(name), false);
  }

  // Origin parsing — extract branch name from `git ls-remote` line
  expect('parse line sha+branch',
    'abc123def\trefs/heads/chore/codeowners-v4.1.1'.match(/refs\/heads\/(.+)$/)?.[1],
    'chore/codeowners-v4.1.1'
  );
  expect('parse line empty', ''.match(/refs\/heads\/(.+)$/)?.[1], undefined);

  // countV411Branches end-to-end (uses same regex)
  function countV411Branches(lsOutput) {
    return lsOutput.split('\n').filter(l => {
      const m = l.match(/refs\/heads\/(.+)$/);
      if (!m) return false;
      return V411_RE.test(m[1]);
    }).length;
  }
  // Simulated 34-branch V4.1.1 state
  const fakeLs = [
    'aaa\trefs/heads/chore/codeowners-v4.1.1',
    'bbb\trefs/heads/feat/sdk-cli-errors-v4.1.1',
    'ccc\trefs/heads/feat/v4.1.1-verify-all-runner',
    'ddd\trefs/heads/release/v4.1.1',
    'eee\trefs/heads/feat/v4.1.2-patch-prep',  // should NOT match
    'fff\trefs/heads/feat/v4.1.10-future',      // should NOT match
  ].join('\n');
  expect('countV411Branches: 4 of 6 match (rest are v4.1.2+ or v4.1.10+)',
    countV411Branches(fakeLs), 4);

  // Record helper semantics
  const before = { pass: passCount, warn: warnCount, fail: failCount };
  record('PASS', 'self-test-extra', 'sanity');
  expect('record PASS increments passCount',
    passCount - before.pass, 1);
  // Roll back so summary isn't disturbed if --self-test falls through
  // (it doesn't, but defensive)
  passCount = before.pass; warnCount = before.warn; failCount = before.fail;
  results.length = 0;

  console.log(`\n  ${pass} passed, ${fail} failed`);
  if (fail > 0) {
    console.log(`\n${color(RED, '✗ self-test FAILED')}`);
    process.exit(1);
  }
  console.log(`\n${color(GREEN, '✓ self-test OK')}`);
}

// === Run self-test if requested ===
// (Defined as a function above; called here so all const helpers are initialized)
if (SELF_TEST) {
  runSelfTest();
  process.exit(0);
}

// === Checks ===
console.log(`${color(CYAN, 'V4.1.1 release pre-flight check')}`);
console.log(`Repo: ${REPO_ROOT}`);
console.log(`Version: ${VERSION}, tag: ${TAG}`);
console.log(`Strict mode: ${STRICT ? 'YES (warnings fail)' : 'NO (warnings OK)'}`);

// 1. Git tag exists (or is staged for creation)
header('Git state');
{
  const exists = tryGit(`rev-parse --verify refs/tags/${TAG}`);
  if (exists) {
    record('PASS', 'git tag', `${TAG} exists at ${exists.slice(0, 12)}`);
  } else {
    const isPlanned = tryGit('status --porcelain') === '';
    if (isPlanned) {
      record('WARN', 'git tag', `${TAG} not yet created (clean working tree, ready for tag)`);
    } else {
      record('WARN', 'git tag', `${TAG} not yet created (working tree has changes — commit first)`);
    }
  }
}

const isOnMaster = tryGit('rev-parse --abbrev-ref HEAD') === 'master';
record(isOnMaster ? 'PASS' : 'WARN', 'git branch', `currently on ${tryGit('rev-parse --abbrev-ref HEAD')}${isOnMaster ? '' : ' (recommended: master)'}`);

const cleanTree = tryGit('status --porcelain') === '';
record(cleanTree ? 'PASS' : 'WARN', 'git working tree', cleanTree ? 'clean' : 'has uncommitted changes (commit or stash before tagging)');

// 2. Broker version files
header('Broker version');
{
  const pkg = JSON.parse(safeRead(join(REPO_ROOT, 'broker/package.json')) || '{}');
  const versionJs = safeRead(join(REPO_ROOT, 'broker/version.js')) || '';
  const pkgOk = pkg.version === VERSION;
  const versionJsOk = new RegExp(`BROKER_VERSION\\s*=\\s*['"]${VERSION.replace(/\./g, '\\.')}['"]`).test(versionJs);
  record(pkgOk ? 'PASS' : 'FAIL', 'broker/package.json', `version: ${pkg.version}${pkgOk ? '' : ` (expected ${VERSION})`}`);
  record(versionJsOk ? 'PASS' : 'FAIL', 'broker/version.js', versionJsOk ? `BROKER_VERSION = '${VERSION}'` : 'not matching');
}

// 3. SDK versions
header('SDK versions');
{
  const checks = [
    { name: 'Python pyproject.toml', file: 'sdk/python/pyproject.toml', regex: new RegExp(`version\\s*=\\s*["']${VERSION.replace(/\./g, '\\.')}["']`) },
    { name: 'Python __init__.py', file: 'sdk/python/secret_broker/__init__.py', regex: new RegExp(`__version__\\s*=\\s*["']${VERSION.replace(/\./g, '\\.')}["']`) },
    { name: 'Go client.go', file: 'sdk/go/broker/client.go', regex: new RegExp(`Version\\s*=\\s*["']${VERSION.replace(/\./g, '\\.')}["']`) },
    { name: 'VSCode package.json', file: 'sdk/vscode/package.json', regex: new RegExp(`"version":\\s*"${VERSION.replace(/\./g, '\\.')}"`) },
    { name: 'VSCode client.ts (User-Agent)', file: 'sdk/vscode/src/client.ts', regex: new RegExp(`secret-broker-vscode/${VERSION.replace(/\./g, '\\.')}`) },
  ];
  for (const c of checks) {
    const content = safeRead(join(REPO_ROOT, c.file));
    if (content === null) {
      record('FAIL', c.name, `${c.file} not found`);
    } else {
      const ok = c.regex.test(content);
      record(ok ? 'PASS' : 'FAIL', c.name, ok ? `version ${VERSION}` : `not at ${VERSION}`);
    }
  }
}

// 4. CHANGELOG entry
header('CHANGELOG.md');
{
  const content = safeRead(join(REPO_ROOT, 'CHANGELOG.md')) || '';
  const hasEntry = new RegExp(`^##\\s*\\[${VERSION.replace(/\./g, '\\.')}\\]`, 'm').test(content);
  const hasSdkSection = /^###\s*SDK V4\.1\.1.*unified error contract/m.test(content);
  record(hasEntry ? 'PASS' : 'FAIL', 'V4.1.1 entry', hasEntry ? `## [${VERSION}] section present` : `## [${VERSION}] section MISSING`);
  record(hasSdkSection ? 'PASS' : 'WARN', 'SDK parity subsection', hasSdkSection ? 'SDK V4.1.1 unified error contract section present' : 'SDK V4.1.1 unified error contract section MISSING');
}

// 5. RELEASE-NOTES
header('RELEASE-NOTES');
{
  const content = safeRead(join(REPO_ROOT, 'RELEASE-NOTES-v4.1.1.md'));
  if (content === null) {
    record('FAIL', 'RELEASE-NOTES-v4.1.1.md', 'file not found');
  } else {
    const hasParity = /^##\s*SDK V4\.1\.1.*unified error contract/m.test(content);
    const hasUpgrade = /##\s*How to upgrade/m.test(content);
    record('PASS', 'RELEASE-NOTES-v4.1.1.md', `exists (${content.length} bytes)`);
    record(hasParity ? 'PASS' : 'WARN', 'RELEASE-NOTES SDK parity section', hasParity ? 'present' : 'MISSING (will appear in V4.1.1 GitHub Release body)');
    record(hasUpgrade ? 'PASS' : 'FAIL', 'RELEASE-NOTES upgrade section', hasUpgrade ? 'present' : 'MISSING (How to upgrade section required)');
  }
}

// 6. ROADMAP + STATUS
header('Plan + status');
{
  const roadmap = safeRead(join(REPO_ROOT, 'ROADMAP-post-1.0.md')) || '';
  const status = safeRead(join(REPO_ROOT, 'STATUS.md')) || '';
  const roadmapHas411 = /V4\.1\.1 patch/i.test(roadmap);
  const statusHas411 = new RegExp(`V4\\.1\\.1.*${VERSION.replace(/\./g, '\\.')}`, 'i').test(status);
  record(roadmapHas411 ? 'PASS' : 'WARN', 'ROADMAP-post-1.0.md', roadmapHas411 ? 'mentions V4.1.1' : 'does not mention V4.1.1');
  record(statusHas411 ? 'PASS' : 'WARN', 'STATUS.md', statusHas411 ? 'mentions V4.1.1' : 'does not mention V4.1.1');
}

// 7. AWAITING-USER
header('AWAITING-USER');
{
  const content = safeRead(join(REPO_ROOT, 'AWAITING-USER.md')) || '';
  const hasVersion = new RegExp(`V${VERSION.replace(/\./g, '\\.')}`).test(content);
  record(hasVersion ? 'PASS' : 'WARN', 'AWAITING-USER.md', hasVersion ? `mentions ${VERSION}` : `does not mention ${VERSION}`);
}

// 8. PR inventory (against origin)
header('Origin state (informational)');
{
  const branches = tryGit('ls-remote --heads origin') || '';
  // Match branch name against exact version token v4.1.1, NOT v4.1.10 / v4.1.100
  // (avoids false positives when future V4.1.1x branches land).
  // Old filter (clauses like /v4.1.1) only matched 18/34 branches because most
  // V4.1.1 branches use `-v4.1.1` (dash) not `/v4.1.1` (slash) in the name.
  const v411Branches = branches.split('\n').filter(l => {
    const m = l.match(/refs\/heads\/(.+)$/);
    if (!m) return false;
    return /(?:^|[^.\d])v?4\.1\.1(?:[^.\d]|$)/.test(m[1]);
  });
  record('PASS', 'origin branches', `${v411Branches.length} V4.1.1-related branches in origin`);
  const aheadCount = tryGit(`rev-list --count master..origin/release/${VERSION}`) || '0';
  record(parseInt(aheadCount, 10) > 0 ? 'PASS' : 'WARN', 'release/v4.1.1 ahead of master', `${aheadCount} commits ahead`);
}

// 9. Local broker (optional — not required for pre-flight, but nice to have)
header('Local broker (optional)');
{
  const certExists = existsSync(join(REPO_ROOT, 'broker/pki/ca.crt'));
  const secretsExists = existsSync(join(REPO_ROOT, 'secrets/secrets-detail.json'));
  record(certExists ? 'PASS' : 'WARN', 'broker/pki/ca.crt', certExists ? 'exists' : 'not found (needed for local smoke)');
  record(secretsExists ? 'PASS' : 'WARN', 'secrets/secrets-detail.json', secretsExists ? 'exists' : 'not found (needed for local smoke)');
}

// === Summary ===
console.log(`\n${color(CYAN, '═══')} Summary ${color(CYAN, '═══')}`);
console.log(`  ${color(GREEN, 'PASS')}: ${passCount}`);
console.log(`  ${color(YELLOW, 'WARN')}: ${warnCount}${STRICT ? ' (strict mode → would fail)' : ''}`);
console.log(`  ${color(RED, 'FAIL')}: ${failCount}`);

const exitCode = failCount > 0 ? 1 : (STRICT && warnCount > 0 ? 2 : 0);
console.log(`\n${color(exitCode === 0 ? GREEN : RED, exitCode === 0 ? '✓ All checks passed.' : `✗ ${failCount + (STRICT ? warnCount : 0)} issue(s) need attention.`) }`);

console.log(`\n${color(CYAN, 'Next steps:')}`);
console.log('  1. Fix any FAIL items above.');
console.log('  2. Review any WARN items (non-blocking but worth checking).');
console.log('  3. After all PASS:');
console.log(`     git checkout master && git pull`);
console.log(`     git tag -a ${TAG} -m "${VERSION} GA — see RELEASE-NOTES-${VERSION}.md"`);
console.log(`     git push origin ${TAG}`);
console.log(`     bash scripts/release/${VERSION}.sh --upload --publish`);
console.log('  4. Smoke: curl -k --cert pki/clients/admin.crt --key pki/clients/admin.key https://broker:8443/health');

process.exit(exitCode);
