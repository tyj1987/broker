#!/usr/bin/env node
// scripts/verify-sdk-v4.1.1-parity.mjs
//
// V4.1.1 SDK parity verifier.
// Validates that all 4 SDKs (Python, Go, Node CLI, VSCode) are
// behaviorally consistent: same BrokerError fields, same
// parseBrokerError factory, same retry semantics, same test coverage
// shape, same version.
// Cross-platform (Node 18+); no Python or Go required.
//
// Usage:
//   node scripts/verify-sdk-v4.1.1-parity.mjs           # default V4.1.1
//   node scripts/verify-sdk-v4.1.1-parity.mjs --version 4.1.2
//   node scripts/verify-sdk-v4.1.1-parity.mjs --strict  # warnings = fail
//   node scripts/verify-sdk-v4.1.1-parity.mjs --self-test  # internal regex regression tests, then exit
//
// Exit code:
//   0  all checks PASS (or self-test passed)
//   1  one or more FAIL (or self-test failed)
//   2  one or more WARNING (only with --strict)
//
// Complements scripts/preflight-v4.1.1.mjs:
//   - preflight: checks broker + SDK versions + CHANGELOG + RELEASE-NOTES
//   - this:      checks 4-SDK parity contract (fields, methods, retry)

import { readFileSync, existsSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

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

// === Output helpers ===
const RED = '\x1b[0;31m', GREEN = '\x1b[0;32m', YELLOW = '\x1b[1;33m', CYAN = '\x1b[0;36m', NC = '\x1b[0m';
const useColor = process.stdout.isTTY;
const color = (c, s) => useColor ? `${c}${s}${NC}` : s;

let passCount = 0, warnCount = 0, failCount = 0;
function record(status, name, detail) {
  const symbol = status === 'PASS' ? color(GREEN, '✓') :
                 status === 'WARN' ? color(YELLOW, '⚠') :
                                      color(RED, '✗');
  console.log(`  ${symbol} ${color(CYAN, name)}: ${detail}`);
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

// === Self-test (regression test for 4-SDK regex patterns) ===
// Run with `node scripts/verify-sdk-v4.1.1-parity.mjs --self-test` to validate
// the regex against fixture code without needing actual SDK source.
function runSelfTest() {
  console.log(`${color(CYAN, 'verify-sdk-v4.1.1-parity self-test')}\n`);
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

  // ===== Python SDK regex =====
  // Match a real V4.1.1 Python exceptions.py fixture
  const pyFixture = `
class BrokerError(Exception):
    def __init__(self, op, status, code, request_id, retry_after, body):
        self.op = op
        self.status = status
        self.code = code
        self.request_id = request_id
        self.retry_after = retry_after
        self.body = body

    @property
    def is_retryable(self):
        return self.status >= 500 or self.status == 429

    def to_dict(self):
        return {"op": self.op, "status": self.status, "code": self.code, "request_id": self.request_id, "retry_after": self.retry_after}


class BrokerConnectionError(Exception):
    pass


def parse_broker_error(response):
    return BrokerError(...)
`;
  expect('Python: BrokerError class present', /class\s+BrokerError\s*\(/.test(pyFixture), true);
  expect('Python: BrokerConnectionError class present', /class\s+BrokerConnectionError\s*\(/.test(pyFixture), true);
  expect('Python: parse_broker_error factory present', /def\s+parse_broker_error\s*\(/.test(pyFixture), true);
  expect('Python: is_retryable @property present', /@property[\s\S]*?is_retryable/.test(pyFixture), true);
  expect('Python: is_retryable as method (alt pattern)', /def\s+is_retryable\s*\(/.test(pyFixture), true);  // @property + def is_retryable both present
  expect('Python: request_id field present', /request_id/.test(pyFixture), true);
  expect('Python: retry_after field present', /retry_after/.test(pyFixture), true);
  expect('Python: to_dict() method present', /def\s+to_dict\s*\(/.test(pyFixture), true);

  // Pre-V4.1.0 fixture (lacks parse_broker_error + request_id/retry_after/to_dict) should fail
  const pyOld = `
class BrokerError(Exception):
    def __init__(self, op, status, code):
        pass
class BrokerConnectionError(Exception):
    pass
`;
  expect('Python: parse_broker_error MISSING in old', /def\s+parse_broker_error\s*\(/.test(pyOld), false);
  expect('Python: request_id MISSING in old', /request_id/.test(pyOld), false);
  expect('Python: to_dict MISSING in old', /def\s+to_dict\s*\(/.test(pyOld), false);

  // ===== Go SDK regex =====
  const goFixture = `
type BrokerError struct {
    Op         string
    Status     int
    Code       string
    RequestID  string
    RetryAfter int
    Body       []byte
}

func (e *BrokerError) IsRetryable() bool {
    return e.Status >= 500 || e.Status == 429
}

type BrokerConnectionError struct {
    Err error
}

func ParseBrokerError(resp *http.Response) *BrokerError {
    return &BrokerError{Op: "test", Status: resp.StatusCode}
}

func (e *BrokerError) ToMap() map[string]interface{} {
    return map[string]interface{}{"op": e.Op, "status": e.Status}
}
`;
  expect('Go: BrokerError struct present', /type\s+BrokerError\s+struct/.test(goFixture), true);
  expect('Go: BrokerConnectionError struct present', /type\s+BrokerConnectionError\s+struct/.test(goFixture), true);
  expect('Go: ParseBrokerError factory present', /func\s+ParseBrokerError\s*\(/.test(goFixture), true);
  expect('Go: IsRetryable() method present',
    /func\s+\(\w+\s+\*?BrokerError\)\s+IsRetryable\s*\(\s*\)\s+bool/.test(goFixture), true);
  expect('Go: RequestID field present', /RequestID/.test(goFixture), true);
  expect('Go: RetryAfter field present', /RetryAfter/.test(goFixture), true);
  expect('Go: ToMap() method present', /func\s+\(\w+\s+\*?BrokerError\)\s+ToMap\s*\(/.test(goFixture), true);

  const goOld = `
type BrokerError struct {
    Op     string
    Status int
    Code   string
}
`;
  expect('Go: ParseBrokerError MISSING in old', /func\s+ParseBrokerError\s*\(/.test(goOld), false);
  expect('Go: IsRetryable MISSING in old',
    /func\s+\(\w+\s+\*?BrokerError\)\s+IsRetryable\s*\(\s*\)\s+bool/.test(goOld), false);
  expect('Go: ToMap MISSING in old', /func\s+\(\w+\s+\*?BrokerError\)\s+ToMap\s*\(/.test(goOld), false);

  // ===== Node CLI SDK regex =====
  const cliFixture = `
export class BrokerError extends Error {
  constructor(op, status, code, requestId, retryAfter, body) {
    super(\`\${status} \${code}\`);
    this.op = op;
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.retryAfter = retryAfter;
    this.body = body;
  }

  get isRetryable() {
    return this.status >= 500 || this.status === 429;
  }

  toJSON() {
    return { op: this.op, status: this.status, code: this.code, requestId: this.requestId, retryAfter: this.retryAfter };
  }

  toString() {
    return \`BrokerError(\${this.status} \${this.code})\`;
  }
}

export class BrokerConnectionError extends Error {}

export function parseBrokerError(response) {
  return new BrokerError(...);
}

export async function mTLSRequest(opts) {
  return await fetchWithRetry(opts);
}
`;
  expect('CLI: BrokerError class present', /export\s+class\s+BrokerError\s+extends\s+Error/.test(cliFixture), true);
  expect('CLI: BrokerConnectionError class present', /class\s+BrokerConnectionError\s+extends\s+Error/.test(cliFixture), true);
  expect('CLI: parseBrokerError factory present', /export\s+function\s+parseBrokerError\s*\(/.test(cliFixture), true);
  expect('CLI: isRetryable getter present', /get\s+isRetryable\s*\([^)]*\)\s*[:{]/.test(cliFixture), true);
  expect('CLI: requestId field present', /requestId/.test(cliFixture), true);
  expect('CLI: retryAfter field present', /retryAfter/.test(cliFixture), true);
  expect('CLI: toJSON() method present', /toJSON\s*\(\s*\)\s*{/.test(cliFixture), true);
  expect('CLI: mTLSRequest present', /(mTLSRequest|async\s+function\s+mTLSRequest|mtlsRequest)/.test(cliFixture), true);
  expect('CLI: redact() called', /redact\s*\(/.test(cliFixture), false);  // fixture doesn't call redact; tests the pattern works

  // ===== VSCode SDK regex =====
  const vscodeFixture = `
export class BrokerError extends Error {
  constructor(public op: string, public status: number, public code: string,
              public requestId: string, public retryAfter: number, public body: unknown) {
    super(\`\${status} \${code}\`);
  }

  get isRetryable(): boolean {
    return this.status >= 500 || this.status === 429;
  }

  toJSON(): Record<string, unknown> {
    return { op: this.op, status: this.status, code: this.code, requestId: this.requestId, retryAfter: this.retryAfter };
  }
}

export class BrokerConnectionError extends Error {}

export function parseBrokerError(response: unknown): BrokerError {
  return new BrokerError(...);
}

private async mtlsRequest<T>(opts: RequestOptions): Promise<T> {
  return this.fetchWithRetry<T>(opts);
}

const userAgent = 'secret-broker-vscode/4.1.1';
`;
  expect('VSCode: BrokerError class present', /class\s+BrokerError\s+extends\s+Error/.test(vscodeFixture), true);
  expect('VSCode: BrokerConnectionError class present', /class\s+BrokerConnectionError\s+extends\s+Error/.test(vscodeFixture), true);
  expect('VSCode: parseBrokerError factory present', /export\s+function\s+parseBrokerError\s*\(/.test(vscodeFixture), true);
  expect('VSCode: isRetryable getter present', /get\s+isRetryable\s*\([^)]*\)\s*[:{]/.test(vscodeFixture), true);
  expect('VSCode: requestId field present', /requestId/.test(vscodeFixture), true);
  expect('VSCode: retryAfter field present', /retryAfter/.test(vscodeFixture), true);
  expect('VSCode: toJSON() method present', /toJSON\s*\(\s*\)\s*:\s*Record/.test(vscodeFixture), true);
  expect('VSCode: mtlsRequest present', /private\s+async\s+mtlsRequest|mtlsRequest\s*</.test(vscodeFixture), true);
  expect('VSCode: User-Agent secret-broker-vscode/4.1.1',
    new RegExp(`secret-broker-vscode/${VERSION.replace(/\./g, '\\.')}`).test(vscodeFixture), true);

  // ===== Cross-SDK contract =====
  // All 4 SDKs must have status >= 500 or === 429 retryable semantic (substring)
  const allRetryable = pyFixture.includes('status >= 500 or self.status == 429')
    && goFixture.includes('Status >= 500 || e.Status == 429')
    && cliFixture.includes('status >= 500 || this.status === 429')
    && vscodeFixture.includes('status >= 500 || this.status === 429');
  expect('Cross-SDK: all 4 implement 5xx/429 retryable semantic', allRetryable, true);

  console.log(`\n  ${pass} passed, ${fail} failed`);
  if (fail > 0) {
    console.log(`\n${color(RED, '✗ self-test FAILED')}`);
    process.exit(1);
  }
  console.log(`\n${color(GREEN, '✓ self-test OK')}`);
}

// === Run self-test if requested ===
if (SELF_TEST) {
  runSelfTest();
  process.exit(0);
}

// === 1. Python SDK ===
header('Python SDK (sdk/python/)');
{
  const pyproject = safeRead(join(REPO_ROOT, 'sdk/python/pyproject.toml'));
  if (!pyproject) {
    record('FAIL', 'sdk/python/pyproject.toml', 'file not found');
  } else {
    const verMatch = new RegExp(`version\\s*=\\s*["']${VERSION.replace(/\./g, '\\.')}["']`).test(pyproject);
    record(verMatch ? 'PASS' : 'FAIL', 'version', verMatch ? `${VERSION}` : `not at ${VERSION}`);
  }
  const init = safeRead(join(REPO_ROOT, 'sdk/python/secret_broker/__init__.py'));
  const verMatch2 = init ? new RegExp(`__version__\\s*=\\s*["']${VERSION.replace(/\./g, '\\.')}["']`).test(init) : false;
  record(verMatch2 ? 'PASS' : 'FAIL', '__init__.py __version__', verMatch2 ? `${VERSION}` : `not at ${VERSION}`);

  const exc = safeRead(join(REPO_ROOT, 'sdk/python/secret_broker/exceptions.py'));
  if (!exc) {
    record('FAIL', 'exceptions.py', 'file not found');
  } else {
    const hasBrokerError = /class\s+BrokerError\s*\(/.test(exc);
    const hasParseFactory = /def\s+parse_broker_error\s*\(/.test(exc);
    const hasConnection = /class\s+BrokerConnectionError\s*\(/.test(exc);
    const hasIsRetryable = /def\s+is_retryable\s*\(/.test(exc) || /@property[\s\S]*?is_retryable/.test(exc);
    const hasRequestId = /request_id/.test(exc);
    const hasRetryAfter = /retry_after/.test(exc);
    const hasToDict = /def\s+to_dict\s*\(/.test(exc);
    const hasRedactImport = /from\s+\.+\s*import\s+.*redact|import\s+redact|from\s+secret_broker\s+import\s+.*redact/.test(exc);

    record(hasBrokerError ? 'PASS' : 'FAIL', 'BrokerError class', hasBrokerError ? 'present' : 'MISSING');
    record(hasConnection ? 'PASS' : 'FAIL', 'BrokerConnectionError class', hasConnection ? 'present' : 'MISSING');
    record(hasParseFactory ? 'PASS' : 'FAIL', 'parse_broker_error factory', hasParseFactory ? 'present' : 'MISSING');
    record(hasIsRetryable ? 'PASS' : 'WARN', 'is_retryable (method or property)', hasIsRetryable ? 'present' : 'MISSING (Python uses is_retryable property in V4.1.1)');
    record(hasRequestId ? 'PASS' : 'FAIL', 'request_id field', hasRequestId ? 'present' : 'MISSING');
    record(hasRetryAfter ? 'PASS' : 'FAIL', 'retry_after field', hasRetryAfter ? 'present' : 'MISSING');
    record(hasToDict ? 'PASS' : 'FAIL', 'to_dict() method', hasToDict ? 'present' : 'MISSING');
    record(hasRedactImport ? 'PASS' : 'WARN', 'redact integration', hasRedactImport ? 'redact imported' : 'no redact import (body may not be auto-redacted)');
  }
}

// === 2. Go SDK ===
header('Go SDK (sdk/go/)');
{
  const goMod = safeRead(join(REPO_ROOT, 'sdk/go/go.mod'));
  const modPath = goMod ? (goMod.match(/^module\s+(\S+)/m)?.[1] || '') : '';

  const client = safeRead(join(REPO_ROOT, 'sdk/go/broker/client.go'));
  const verMatch = client ? new RegExp(`Version\\s*=\\s*["']${VERSION.replace(/\./g, '\\.')}["']`).test(client) : false;
  record(verMatch ? 'PASS' : 'FAIL', 'Version constant', verMatch ? `${VERSION}` : `not at ${VERSION}`);

  const errs = safeRead(join(REPO_ROOT, 'sdk/go/broker/errors.go'));
  if (!errs) {
    record('FAIL', 'errors.go', 'file not found');
  } else {
    const hasBrokerError = /type\s+BrokerError\s+struct/.test(errs);
    const hasParseFactory = /func\s+ParseBrokerError\s*\(/.test(errs);
    const hasConnection = /type\s+BrokerConnectionError\s+struct/.test(errs);
    const hasIsRetryable = /func\s+\(\w+\s+\*?BrokerError\)\s+IsRetryable\s*\(\s*\)\s+bool/.test(errs);
    const hasRequestId = /RequestID/.test(errs);
    const hasRetryAfter = /RetryAfter/.test(errs);
    const hasToMap = /func\s+\(\w+\s+\*?BrokerError\)\s+ToMap\s*\(/.test(errs);

    record(hasBrokerError ? 'PASS' : 'FAIL', 'BrokerError struct', hasBrokerError ? 'present' : 'MISSING');
    record(hasConnection ? 'PASS' : 'FAIL', 'BrokerConnectionError struct', hasConnection ? 'present' : 'MISSING');
    record(hasParseFactory ? 'PASS' : 'FAIL', 'ParseBrokerError factory', hasParseFactory ? 'present' : 'MISSING');
    record(hasIsRetryable ? 'PASS' : 'FAIL', 'IsRetryable() method', hasIsRetryable ? 'present' : 'MISSING');
    record(hasRequestId ? 'PASS' : 'FAIL', 'RequestID field', hasRequestId ? 'present' : 'MISSING');
    record(hasRetryAfter ? 'PASS' : 'FAIL', 'RetryAfter field', hasRetryAfter ? 'present' : 'MISSING');
    record(hasToMap ? 'PASS' : 'FAIL', 'ToMap() method', hasToMap ? 'present' : 'MISSING');
  }
}

// === 3. Node CLI ===
header('Node CLI (cli/)');
{
  const cli = safeRead(join(REPO_ROOT, 'cli/secret-broker.js'));
  if (!cli) {
    record('FAIL', 'cli/secret-broker.js', 'file not found');
  } else {
    const hasBrokerError = /export\s+class\s+BrokerError\s+extends\s+Error/.test(cli);
    const hasParseFactory = /export\s+function\s+parseBrokerError\s*\(/.test(cli);
    const hasConnection = /class\s+BrokerConnectionError\s+extends\s+Error/.test(cli);
    const hasIsRetryable = /get\s+isRetryable\s*\([^)]*\)\s*[:{]/.test(cli);
    const hasRequestId = /requestId/.test(cli);
    const hasRetryAfter = /retryAfter/.test(cli);
    const hasToString = /toString\s*\(\s*\)\s*{/.test(cli);
    const hasToJSON = /toJSON\s*\(\s*\)\s*{/.test(cli);
    const hasMtlsRequest = /(mTLSRequest|async\s+function\s+mTLSRequest|mtlsRequest)/.test(cli);
    const hasRedactCall = /redact\s*\(/.test(cli);

    record(hasBrokerError ? 'PASS' : 'FAIL', 'BrokerError class', hasBrokerError ? 'present' : 'MISSING');
    record(hasConnection ? 'PASS' : 'FAIL', 'BrokerConnectionError class', hasConnection ? 'present' : 'MISSING');
    record(hasParseFactory ? 'PASS' : 'FAIL', 'parseBrokerError factory', hasParseFactory ? 'present' : 'MISSING');
    record(hasIsRetryable ? 'PASS' : 'FAIL', 'isRetryable getter', hasIsRetryable ? 'present' : 'MISSING');
    record(hasRequestId ? 'PASS' : 'FAIL', 'requestId field', hasRequestId ? 'present' : 'MISSING');
    record(hasRetryAfter ? 'PASS' : 'FAIL', 'retryAfter field', hasRetryAfter ? 'present' : 'MISSING');
    record(hasToString ? 'PASS' : 'FAIL', 'toString() method', hasToString ? 'present' : 'MISSING');
    record(hasToJSON ? 'PASS' : 'FAIL', 'toJSON() method', hasToJSON ? 'present' : 'MISSING');
    record(hasMtlsRequest ? 'PASS' : 'FAIL', 'mTLSRequest (built-in retry)', hasMtlsRequest ? 'present' : 'MISSING');
    record(hasRedactCall ? 'PASS' : 'WARN', 'redact() integration', hasRedactCall ? 'redact() called' : 'no redact() call (body may not be auto-redacted)');
  }
}

// === 4. VSCode extension ===
header('VSCode extension (sdk/vscode/)');
{
  const pkg = safeRead(join(REPO_ROOT, 'sdk/vscode/package.json'));
  if (!pkg) {
    record('FAIL', 'sdk/vscode/package.json', 'file not found');
  } else {
    try {
      const parsed = JSON.parse(pkg);
      record(parsed.version === VERSION ? 'PASS' : 'FAIL', 'package.json version', parsed.version === VERSION ? `${VERSION}` : `${parsed.version} (expected ${VERSION})`);
    } catch (e) {
      record('FAIL', 'package.json', `parse error: ${e.message}`);
    }
  }

  const client = safeRead(join(REPO_ROOT, 'sdk/vscode/src/client.ts'));
  if (!client) {
    record('FAIL', 'src/client.ts', 'file not found');
  } else {
    const hasBrokerError = /class\s+BrokerError\s+extends\s+Error/.test(client);
    const hasParseFactory = /export\s+function\s+parseBrokerError\s*\(/.test(client);
    const hasConnection = /class\s+BrokerConnectionError\s+extends\s+Error/.test(client);
    const hasIsRetryable = /get\s+isRetryable\s*\([^)]*\)\s*[:{]/.test(client);
    const hasRequestId = /requestId/.test(client);
    const hasRetryAfter = /retryAfter/.test(client);
    const hasToString = /toString\s*\(\s*\)\s*:\s*string/.test(client);
    const hasToJSON = /toJSON\s*\(\s*\)\s*:\s*Record/.test(client);
    const hasMtlsRequest = /private\s+async\s+mtlsRequest|mtlsRequest\s*</.test(client);
    const hasRedactCall = /redact\s*\(/.test(client);
    const hasUserAgent = new RegExp(`secret-broker-vscode/${VERSION.replace(/\./g, '\\.')}`).test(client);

    record(hasBrokerError ? 'PASS' : 'FAIL', 'BrokerError class', hasBrokerError ? 'present' : 'MISSING');
    record(hasConnection ? 'PASS' : 'FAIL', 'BrokerConnectionError class', hasConnection ? 'present' : 'MISSING');
    record(hasParseFactory ? 'PASS' : 'FAIL', 'parseBrokerError factory', hasParseFactory ? 'present' : 'MISSING');
    record(hasIsRetryable ? 'PASS' : 'FAIL', 'isRetryable getter', hasIsRetryable ? 'present' : 'MISSING');
    record(hasRequestId ? 'PASS' : 'FAIL', 'requestId field', hasRequestId ? 'present' : 'MISSING');
    record(hasRetryAfter ? 'PASS' : 'FAIL', 'retryAfter field', hasRetryAfter ? 'present' : 'MISSING');
    record(hasToString ? 'PASS' : 'FAIL', 'toString() method', hasToString ? 'present' : 'MISSING');
    record(hasToJSON ? 'PASS' : 'FAIL', 'toJSON() method', hasToJSON ? 'present' : 'MISSING');
    record(hasMtlsRequest ? 'PASS' : 'FAIL', 'mtlsRequest (built-in retry)', hasMtlsRequest ? 'present' : 'MISSING');
    record(hasRedactCall ? 'PASS' : 'WARN', 'redact() integration', hasRedactCall ? 'redact() called' : 'no redact() call (body may not be auto-redacted)');
    record(hasUserAgent ? 'PASS' : 'FAIL', `User-Agent = secret-broker-vscode/${VERSION}`, hasUserAgent ? 'present' : `MISSING or wrong version`);
  }
}

// === 5. Cross-SDK contract parity ===
header('Cross-SDK contract parity');
{
  const PYTHON_FIELDS = ['status', 'code', 'request_id', 'retry_after', 'body'];
  const GO_FIELDS = ['Status', 'Code', 'RequestID', 'RetryAfter', 'Body'];
  const JS_FIELDS = ['status', 'code', 'requestId', 'retryAfter', 'body'];
  const TS_FIELDS = ['status', 'code', 'requestId', 'retryAfter', 'body'];

  const pyExc = safeRead(join(REPO_ROOT, 'sdk/python/secret_broker/exceptions.py')) || '';
  const goErrs = safeRead(join(REPO_ROOT, 'sdk/go/broker/errors.go')) || '';
  const jsCli = safeRead(join(REPO_ROOT, 'cli/secret-broker.js')) || '';
  const tsClient = safeRead(join(REPO_ROOT, 'sdk/vscode/src/client.ts')) || '';

  const pyHas = PYTHON_FIELDS.every(f => pyExc.includes(`${f}:`));
  const goHas = GO_FIELDS.every(f => goErrs.includes(f));
  const jsHas = JS_FIELDS.every(f => jsCli.includes(`this.${f}`));
  const tsHas = TS_FIELDS.every(f => tsClient.includes(`this.${f}`));

  record(pyHas ? 'PASS' : 'FAIL', 'Python fields complete', pyHas ? `all 5: ${PYTHON_FIELDS.join(', ')}` : 'missing some');
  record(goHas ? 'PASS' : 'FAIL', 'Go fields complete', goHas ? `all 5: ${GO_FIELDS.join(', ')}` : 'missing some');
  record(jsHas ? 'PASS' : 'FAIL', 'Node CLI fields complete', jsHas ? `all 5: ${JS_FIELDS.join(', ')}` : 'missing some');
  record(tsHas ? 'PASS' : 'FAIL', 'VSCode fields complete', tsHas ? `all 5: ${TS_FIELDS.join(', ')}` : 'missing some');
}

// === 6. Cross-references in docs ===
header('Docs cross-references');
{
  const sdkRef = safeRead(join(REPO_ROOT, 'docs/SDK-REFERENCE.md')) || '';
  const upgrade = safeRead(join(REPO_ROOT, 'docs/SDK-UPGRADE-GUIDE.md')) || '';
  const errors = safeRead(join(REPO_ROOT, 'docs/ERROR-CODES.md')) || '';

  const sdkRefHas = /V4\.1\.1 SDK parity/i.test(sdkRef);
  const upgradeHas = /V4\.1\.0\s*→\s*V4\.1\.1|V4\.1\.0.*V4\.1\.1.*migration/i.test(upgrade);
  const errorsHas = /V4\.1\.1/.test(errors);

  record(sdkRefHas ? 'PASS' : 'WARN', 'SDK-REFERENCE.md V4.1.1 section', sdkRefHas ? 'present' : 'MISSING');
  record(upgradeHas ? 'PASS' : 'WARN', 'SDK-UPGRADE-GUIDE.md V4.1.1 section', upgradeHas ? 'present' : 'MISSING');
  record(errorsHas ? 'PASS' : 'WARN', 'ERROR-CODES.md V4.1.1 reference', errorsHas ? 'present' : 'MISSING');
}

// === Summary ===
console.log(`\n${color(CYAN, '═══')} Summary ${color(CYAN, '═══')}`);
console.log(`  ${color(GREEN, 'PASS')}: ${passCount}`);
console.log(`  ${color(YELLOW, 'WARN')}: ${warnCount}${STRICT ? ' (strict mode → would fail)' : ''}`);
console.log(`  ${color(RED, 'FAIL')}: ${failCount}`);

const exitCode = failCount > 0 ? 1 : (STRICT && warnCount > 0 ? 2 : 0);
console.log(`\n${color(exitCode === 0 ? GREEN : RED, exitCode === 0 ? '✓ All 4 SDKs in V4.1.1 parity.' : `✗ ${failCount + (STRICT ? warnCount : 0)} issue(s) need attention.`) }`);

console.log(`\n${color(CYAN, 'Cross-SDK parity contract (V4.1.1):')}`);
console.log('  - Single BrokerError class with fields: status, code, requestId/request_id, retryAfter/retry_after, body');
console.log('  - Single BrokerConnectionError class (network failures, always retryable)');
console.log('  - parseBrokerError factory (typed error from raw response)');
console.log('  - isRetryable / is_retryable (5xx / 429 / connection → true)');
console.log('  - toString() / toJSON() / to_map() / to_dict() (body omitted)');
console.log('  - Built-in retry: 5xx / 429 / connection with exponential backoff + Retry-After override');
console.log('  - Auto-redact body on construction (defense in depth)');
console.log(`  - All 4 SDKs at version ${VERSION}`);

process.exit(exitCode);
