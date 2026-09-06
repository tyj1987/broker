#!/usr/bin/env node
// scripts/verify-v4.1.1-release.mjs
//
// V4.1.1 release verify-all runner.
// Runs both preflight-v4.1.1.mjs (broker + versions + docs) and
// verify-sdk-v4.1.1-parity.mjs (4 SDK parity contract), combines
// output, and exits 0 only if both pass.
//
// Usage:
//   node scripts/verify-v4.1.1-release.mjs                # default V4.1.1
//   node scripts/verify-v4.1.1-release.mjs --version 4.1.2
//   node scripts/verify-v4.1.1-release.mjs --strict       # warnings = fail
//   node scripts/verify-v4.1.1-release.mjs --preflight    # only preflight
//   node scripts/verify-v4.1.1-release.mjs --sdk          # only 4-SDK parity
//   node scripts/verify-v4.1.1-release.mjs --self-test   # run child self-tests, then exit
//
// Exit code:
//   0  all checks PASS (broker + 4 SDK parity) (or self-test passed)
//   1  one or more FAIL (or self-test failed)
//   2  one or more WARNING (only with --strict)
//
// This is the single command to run before tagging v4.1.1.
// Replaces the need to run 2 scripts manually.

import { execFileSync, spawnSync } from 'node:child_process';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { existsSync } from 'node:fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const SCRIPT_DIR = __dirname;

// === Parse args ===
const args = process.argv.slice(2);
let VERSION = '4.1.1';
let STRICT = false;
let ONLY_PREFLIGHT = false;
let ONLY_SDK = false;
let SELF_TEST = false;
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--version' && args[i + 1]) {
    VERSION = args[i + 1];
    i++;
  } else if (args[i] === '--strict') {
    STRICT = true;
  } else if (args[i] === '--preflight') {
    ONLY_PREFLIGHT = true;
  } else if (args[i] === '--sdk') {
    ONLY_SDK = true;
  } else if (args[i] === '--self-test') {
    SELF_TEST = true;
  } else if (args[i] === '-h' || args[i] === '--help') {
    console.log(readFileSync(__filename, 'utf8').split('\n').slice(1, 25).join('\n'));
    process.exit(0);
  }
}

if (ONLY_PREFLIGHT && ONLY_SDK) {
  console.error('Cannot use --preflight and --sdk together');
  process.exit(1);
}

// === Self-test (deferred to after helpers are defined) ===
// Set SELF_TEST in args parser above; actual self-test runs after color() is defined.

// === Output helpers ===
const RED = '\x1b[0;31m', GREEN = '\x1b[0;32m', YELLOW = '\x1b[1;33m', CYAN = '\x1b[0;36m', MAGENTA = '\x1b[1;35m', NC = '\x1b[0m';
const useColor = process.stdout.isTTY;
const color = (c, s) => useColor ? `${c}${s}${NC}` : s;

// === Self-test (deferred from args parser; runs after helpers are defined) ===
if (SELF_TEST) {
  console.log(`${color(CYAN, 'verify-v4.1.1-release self-test')}\n`);
  let pass = 0, fail = 0;

  function expect(name, actual, expected) {
    const ok = actual === expected;
    if (ok) { pass++; console.log(`  ${color(GREEN, '✓')} ${name}`); }
    else    { fail++; console.log(`  ${color(RED, '✗')} ${name}: expected ${expected}, got ${actual}`); }
  }

  // Test 1: preflight --self-test passes (validates preflight self-test still works)
  const preflightScript = join(SCRIPT_DIR, 'preflight-v4.1.1.mjs');
  if (existsSync(preflightScript)) {
    const r = spawnSync(process.execPath, [preflightScript, '--self-test'], {
      cwd: SCRIPT_DIR, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true
    });
    expect('preflight-v4.1.1.mjs --self-test exits 0', r.status, 0);
  } else {
    console.log(`  ${color(YELLOW, '⚠')} preflight-v4.1.1.mjs not on this branch (skip)`);
  }

  // Test 2: parity --self-test passes (validates parity self-test still works)
  const parityScript = join(SCRIPT_DIR, 'verify-sdk-v4.1.1-parity.mjs');
  if (existsSync(parityScript)) {
    const r = spawnSync(process.execPath, [parityScript, '--self-test'], {
      cwd: SCRIPT_DIR, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true
    });
    expect('verify-sdk-v4.1.1-parity.mjs --self-test exits 0', r.status, 0);
  } else {
    console.log(`  ${color(YELLOW, '⚠')} verify-sdk-v4.1.1-parity.mjs not on this branch (skip)`);
  }

  // Test 3: --preflight + --sdk conflict detection (re-invoke with both flags, expect exit 1)
  // Use a temp file in repo root (path is same as import.meta.url resolved)
  const thisScript = fileURLToPath(import.meta.url);
  const conflictR = spawnSync(process.execPath, [thisScript, '--preflight', '--sdk'], {
    cwd: SCRIPT_DIR, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true
  });
  expect('--preflight + --sdk exits 1 (conflict detected)', conflictR.status, 1);

  // Test 4: preflight --self-test is version-independent (smoke check with bogus --version)
  if (existsSync(preflightScript)) {
    const versionR = spawnSync(process.execPath, [preflightScript, '--version=9.9.9', '--self-test'], {
      cwd: SCRIPT_DIR, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true
    });
    expect('preflight --self-test ignores --version override', versionR.status, 0);
  }

  console.log(`\n  ${pass} passed, ${fail} failed`);
  if (fail > 0) {
    console.log(`\n${color(RED, '✗ self-test FAILED')}`);
    process.exit(1);
  }
  console.log(`\n${color(GREEN, '✓ self-test OK')}`);
  process.exit(0);
}

console.log(`${color(MAGENTA, '╔══════════════════════════════════════════════════════════╗')}`);
console.log(`${color(MAGENTA, '║')}  ${color(CYAN, 'V4.1.1 Release Verify-All Runner')}                        ${color(MAGENTA, '║')}`);
console.log(`${color(MAGENTA, '║')}  ${color(CYAN, 'Broker + 4 SDK parity + docs + tooling')}                 ${color(MAGENTA, '║')}`);
console.log(`${color(MAGENTA, '╚══════════════════════════════════════════════════════════╝')}`);
console.log(`Version: ${VERSION}`);
console.log(`Strict: ${STRICT ? 'YES (warnings fail)' : 'NO (warnings OK)'}`);
console.log(`Mode: ${ONLY_PREFLIGHT ? 'preflight only' : ONLY_SDK ? '4-SDK parity only' : 'both'}`);

async function runScript(scriptName, label) {
  const scriptPath = join(SCRIPT_DIR, scriptName);

  // Check file exists first (scripts may not be merged to master yet).
  if (!existsSync(scriptPath)) {
    console.log(`\n${color(MAGENTA, '━━━')} ${color(CYAN, label)} ${color(MAGENTA, '━━━')}`);
    console.log(`${color(RED, '✗ ' + scriptName + ': not found at')} ${color(CYAN, scriptPath)}`);
    console.log(`\n${color(YELLOW, 'This script depends on:')}`);
    if (scriptName.includes('preflight')) {
      console.log(`  feat/release-preflight-check (PR ${color(CYAN, 'origin/feat/release-preflight-check')}) — commit 10faca4`);
    } else if (scriptName.includes('verify-sdk')) {
      console.log(`  feat/verify-sdk-v4.1.1-parity (PR ${color(CYAN, 'origin/feat/verify-sdk-v4.1.1-parity')}) — commit 1a92da5`);
    }
    console.log(`\n${color(YELLOW, 'To use this runner, first merge the parent PR:')}`);
    console.log(`  ${color(CYAN, 'git fetch origin')}`);
    console.log(`  ${color(CYAN, 'git checkout origin/<branch> -- scripts/' + scriptName)}`);
    console.log(`  ${color(CYAN, 'git commit -m "import ' + scriptName + ' from <branch>"')}`);
    return { scriptName, code: 1, missing: true };
  }

  const args = [`--version=${VERSION}`];
  if (STRICT) args.push('--strict');

  console.log(`\n${color(MAGENTA, '━━━')} ${color(CYAN, label)} ${color(MAGENTA, '━━━')}`);
  console.log(`Running: ${color(CYAN, `node ${scriptName} ${args.join(' ')}`)}\n`);

  try {
    const result = spawnSync(process.execPath, [scriptPath, ...args], {
      cwd: SCRIPT_DIR,
      stdio: 'inherit',
      windowsHide: true,
    });
    return { scriptName, code: result.status ?? 1 };
  } catch (e) {
    console.error(`${color(RED, '✗ Failed to run ' + scriptName + ':')} ${e.message}`);
    return { scriptName, code: 1 };
  }
}

const tasks = [];
if (!ONLY_SDK) {
  tasks.push(runScript('preflight-v4.1.1.mjs', '1/2 Preflight: broker + versions + docs'));
}
if (!ONLY_PREFLIGHT) {
  tasks.push(runScript('verify-sdk-v4.1.1-parity.mjs', `${ONLY_PREFLIGHT ? '1/1' : '2/2'} 4-SDK parity: BrokerError contract + retry`));
}

const results = [];
for (const t of tasks) {
  results.push(await t);
}

// === Summary ===
console.log(`\n${color(MAGENTA, '╔══════════════════════════════════════════════════════════╗')}`);
console.log(`${color(MAGENTA, '║')}  ${color(CYAN, 'Summary')}                                                ${color(MAGENTA, '║')}`);
console.log(`${color(MAGENTA, '╚══════════════════════════════════════════════════════════╝')}`);

for (const r of results) {
  let symbol, label;
  if (r.missing) {
    symbol = color(YELLOW, '⚠');
    label = 'NOT MERGED';
  } else if (r.code === 0) {
    symbol = color(GREEN, '✓');
    label = 'PASS';
  } else {
    symbol = color(RED, '✗');
    label = `FAIL (exit ${r.code})`;
  }
  console.log(`  ${symbol} ${color(CYAN, r.scriptName)}: ${label}`);
}

const allPass = results.every(r => r.code === 0);
const anyFail = results.some(r => r.code === 1);

// Exit code:
//   0  all pass
//   1  one or more FAIL
//   2  one or more WARNING (only with --strict; can't easily detect this since scripts inherit exit codes)
//     We only get 1 (FAIL) or 0 (PASS) since child scripts exit non-zero on FAIL.
//     For WARNING-without-strict, scripts exit 0. So exit 0 = OK.

let exitCode;
if (anyFail) {
  exitCode = 1;
} else if (allPass) {
  exitCode = 0;
} else {
  exitCode = 1;
}

console.log(`\n${color(exitCode === 0 ? GREEN : RED, exitCode === 0 ? '✓ V4.1.1 release is ready to tag and ship.' : '✗ V4.1.1 release is NOT ready. Fix issues above.')}`);

if (exitCode === 0) {
  console.log(`\n${color(CYAN, 'Next steps:')}`);
  console.log(`  1. Tag v4.1.1:  ${color(CYAN, 'git tag -a v4.1.1 -m "V4.1.1 GA"')}`);
  console.log(`  2. Push tag:    ${color(CYAN, 'git push origin v4.1.1')}`);
  console.log(`  3. Build:       ${color(CYAN, 'bash scripts/release/v4.1.1.sh')}`);
  console.log(`  4. Upload:      ${color(CYAN, 'bash scripts/release/v4.1.1.sh --upload --publish')}`);
  console.log(`  5. Smoke:       ${color(CYAN, 'curl -k --cert pki/clients/admin.crt --key pki/clients/admin.key https://broker:8443/health')}`);
  console.log(`  6. (Optional) 52trz.com upgrade: ${color(CYAN, 'see DEPLOY-52TRZ.md')}`);
} else {
  console.log(`\n${color(CYAN, 'Troubleshooting:')}`);
  console.log(`  - Broker / version FAIL → check release/v4.1.1 branch merge`);
  console.log(`  - Docs FAIL → merge SDK-REFERENCE / SDK-UPGRADE-GUIDE / ERROR-CODES / ROADMAP PRs`);
  console.log(`  - 4 SDK parity FAIL → merge 4 feat/sdk-*-errors-v4.1.1 PRs`);
  console.log(`  - See AWAITING-USER.md V13 for recommended merge order`);
}

process.exit(exitCode);
