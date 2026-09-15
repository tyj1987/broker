// broker-test/test-redact.js — V4 secret value redaction
// Run: node broker-test/test-redact.js
import {
  redact,
  redactDeep,
  redactJson,
  hasLikelySecret,
  SUPPORTED_PATTERNS,
} from '../broker/lib/redact.js';

let pass = 0, fail = 0;
function ok(name, cond) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}`); }
}
function section(t) { console.log(`\n[${t}]`); }

// === GitHub ===
section('GitHub tokens');
ok('ghp_ redacted', !redact('pat=ghp_1234567890ABCDEFGHIJabcdefghij').includes('ghp_1234567890'));
ok('github_pat_ redacted', !redact('Bearer github_pat_abc_DEF_123_ghi_456jklmno_789pqrstu_vwx_yzABC_DEF').includes('github_pat_abc_DEF_123'));
ok('ghu_ (App user) redacted', !redact('token=ghu_AAAAAAAAAAAAAAAAAAAA').includes('ghu_AAAA'));

// === Secret Broker ===
section('Secret Broker API keys');
const liveBrokerKey = 'mb_live_' + 'A'.repeat(32);
const testBrokerKey = 'mb_test_' + 'b'.repeat(32);
ok('mb_live_ redacted', redact(`token=${liveBrokerKey}`) === 'token=mb_live_***');
ok('mb_test_ redacted', redact(`Bearer ${testBrokerKey}`) === 'Bearer mb_test_***');
ok('Broker key heuristic', hasLikelySecret(`key=${liveBrokerKey}`));

// === OpenAI / Anthropic / Google ===
section('AI provider keys');
ok('sk- redacted', !redact('sk-' + 'A'.repeat(40)).includes('A'.repeat(40)));
ok('sk-proj- redacted', !redact('sk-proj-' + 'B'.repeat(50)).includes('B'.repeat(50)));
ok('sk-ant- redacted', !redact('sk-ant-api03-' + 'C'.repeat(40)).includes('C'.repeat(40)));
ok('AIza redacted', !redact('AIza' + 'D'.repeat(35)).includes('D'.repeat(35)));

// === Aliyun / Tencent / AWS / Azure ===
section('Cloud provider keys');
ok('LTAI redacted', !redact('LTAI1234567890ABCDEFG').includes('LTAI1234567890'));
ok('AKID redacted', !redact('AKID1234567890ABCDEFG').includes('AKID1234567890'));
ok('AKIA long-term redacted', !redact('AKIAIOSFODNN7EXAMPLE').includes('AKIAIOSFODNN7EXAMPLE'));
ok('ASIA STS redacted', !redact('ASIAJBBLPLV4ABCDEFG').includes('ASIAJBBLPLV4ABCDEFG'));
// Azure tenant id 32 hex chars (16 hex without dashes matches)
ok('Azure tenant uuid redacted', !redact('tenant: 12345678-1234-1234-1234-123456789012').includes('12345678-1234-1234'));

// === Slack / Stripe / Docker ===
section('Other provider tokens');
ok('xoxb- redacted', !redact('xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx').includes('AbCdEfGhIjKl'));
ok('xoxp- redacted', !redact('xoxp-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx').includes('AbCdEfGhIjKl'));
ok('sk_live_ redacted', !redact('sk_live_' + 'a'.repeat(30)).includes('a'.repeat(30)));
ok('docker_ registry redacted', !redact('auth: docker_' + 'f'.repeat(40)).includes('f'.repeat(40)));

// === Headers ===
section('HTTP headers');
ok('Bearer header redacted', !redact('Authorization: Bearer abcDEF123_-.' + 'X'.repeat(30)).includes('X'.repeat(30)));
ok('Basic auth redacted', !redact('Authorization: Basic dXNlcjpwYXNz').includes('dXNlcjpwYXNz'));
const labelled = redact('upstream failed: password=ordinary-value api_key:another-value');
ok('labelled password redacted', !labelled.includes('ordinary-value'));
ok('labelled api key redacted', !labelled.includes('another-value'));
ok('connection URL password redacted', !redact('postgres://broker:db-password@example.invalid:5432/app').includes('db-password'));
ok('signed URL token redacted', !redact('https://example.invalid/callback?token=one-time-secret&next=ok').includes('one-time-secret'));
ok('signed URL signature redacted', !redact('https://example.invalid/callback?X-Amz-Signature=signature-canary').includes('signature-canary'));
ok('labelled token redacted', !redact('worker failure token=short-token').includes('short-token'));

// === PEM keys ===
section('PEM private keys');
const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAabcd\n-----END RSA PRIVATE KEY-----';
const r = redact(pem);
ok('PEM start marker preserved', r.includes('-----BEGIN PRIVATE KEY-----'));
ok('PEM end marker preserved', r.includes('-----END PRIVATE KEY-----'));
ok('PEM key body not leaked', !r.includes('MIIEowIBAAKCAQEAabcd'));

const openssh = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----';
const r2 = redact(openssh);
ok('OpenSSH PEM start preserved', r2.includes('-----BEGIN PRIVATE KEY-----'));
ok('OpenSSH PEM body redacted', !r2.includes('b3BlbnNzaC1rZXktdjEAAAAA'));

// === JWT ===
section('JWT');
const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
const r3 = redact('Token: ' + jwt);
ok('JWT signature redacted', !r3.includes('SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'));

// === hasLikelySecret ===
section('heuristic');
ok('has ghp_', hasLikelySecret('token=ghp_1234567890ABCDEFGHIJ'));
ok('has AIza', hasLikelySecret('key=AIza' + 'a'.repeat(35)));
ok('no for plain text', !hasLikelySecret('hello world this is just text'));
ok('no for short string', !hasLikelySecret('a'));

// === redactDeep ===
section('deep redact');
const nested = {
  user: 'tyj',
  pat: 'ghp_1234567890ABCDEFGHIJabcdefghij',
  secrets: {
    aws: 'AKIAIOSFODNN7EXAMPLE',
    nested: { ok: 'public', leak: 'sk-' + 'A'.repeat(40) },
  },
  list: [
    { x: 1, y: 'github_pat_abc_DEF_123_ghi_456jklmno_789pqrstu_vwx_yzABC_DEF' },
    'plain text',
  ],
  broker: liveBrokerKey,
};
const safe = redactDeep(nested);
ok('user not redacted', safe.user === 'tyj');
ok('top-level PAT redacted', !safe.pat.includes('ghp_1234567890'));
ok('aws key redacted in nested', !safe.secrets.aws.includes('AKIAIOSFODNN7'));
ok('plain text not redacted', safe.list[0] !== null && safe.list[1] === 'plain text');
ok('array object redacted', !safe.list[0].y.includes('abc_DEF_123_ghi_456'));
ok('array object has placeholder', safe.list[0].y.includes('***'));
ok('nested ok public kept', safe.secrets.nested.ok === 'public');
ok('array sk redacted', !safe.secrets.nested.leak.includes('A'.repeat(40)));
ok('Broker key redacted in nested output', safe.broker === 'mb_live_***');

const keyBound = redactDeep({
  password: 'ordinary-text',
  Authorization: 'short-value',
  private_key: { material: 'not-pattern-shaped' },
  access_key_id: 'ordinary-identifier',
  app_secret: 'short-secret',
  signing_key: 'short-signing-key',
  encryption_key: 'short-encryption-key',
  master_key: 'short-master-key',
  kms_key: 'short-kms-key',
  totp_secret: 'short-seed',
  recovery_codes: ['alpha', 'bravo'],
  secret: 'human-readable-value',
  secret_name: 'deployment-key',
  credential_id: 'public-identifier',
});
ok('password key always redacted', keyBound.password === '[REDACTED]');
ok('authorization key always redacted', keyBound.Authorization === '[REDACTED]');
ok('private key object always redacted', keyBound.private_key === '[REDACTED]');
ok('access key id always redacted', keyBound.access_key_id === '[REDACTED]');
ok('app secret always redacted', keyBound.app_secret === '[REDACTED]');
ok('signing key always redacted', keyBound.signing_key === '[REDACTED]');
ok('encryption key always redacted', keyBound.encryption_key === '[REDACTED]');
ok('master key always redacted', keyBound.master_key === '[REDACTED]');
ok('kms key always redacted', keyBound.kms_key === '[REDACTED]');
ok('totp secret always redacted', keyBound.totp_secret === '[REDACTED]');
ok('recovery code array always redacted', keyBound.recovery_codes === '[REDACTED]');
ok('bare secret key always redacted', keyBound.secret === '[REDACTED]');
ok('secret name remains observable', keyBound.secret_name === 'deployment-key');
ok('credential id remains observable', keyBound.credential_id === 'public-identifier');

const cyclic = { password: 'plain-password' };
cyclic.self = cyclic;
const safeCycle = redactDeep(cyclic);
ok('cyclic secret is redacted', safeCycle.password === '[REDACTED]');
ok('cyclic reference cannot reintroduce input', safeCycle.self === '[CIRCULAR]');

// === redactJson ===
section('json output');
const j = redactJson({ a: 'ghp_1234567890ABCDEFGHIJ', b: 42 });
ok('JSON has no ghp_', !j.includes('ghp_1234567890'));
ok('JSON has 42', j.includes('42'));

// === safety ===
section('safety');
ok('null safe', redact(null) === null);
ok('undefined safe', redact(undefined) === undefined);
ok('number safe', redact(42) === 42);
ok('empty string safe', redact('') === '');
ok('non-secret unchanged', redact('hello world this is benign content') === 'hello world this is benign content');

// === supported patterns ===
section('meta');
ok('SUPPORTED_PATTERNS non-empty', Array.isArray(SUPPORTED_PATTERNS) && SUPPORTED_PATTERNS.length >= 15);
ok('all patterns have unique names', new Set(SUPPORTED_PATTERNS).size === SUPPORTED_PATTERNS.length);


// === Short labelled credentials and prefix fallthrough ===
section('labelled credential boundary regressions');
for (const label of ['sig', 'token', 'cookie', 'session', 'password', 'api_key']) {
  for (const separator of ['=', ':']) {
    const input = `${label}${separator}x`;
    ok(`${label} ${separator} short value reaches redaction`, hasLikelySecret(input));
    ok(`${label} ${separator} short value is removed`, redact(input) === `${label}${separator}***`);
  }
}

// These are intentionally synthetic, invalid short values, not provider credentials.
const shortProviderValues = [
  'mb_live_x', 'mb_test_x', 'ghp_x', 'github_pat_x', 'gho_x', 'ghu_x',
  'ghs_x', 'ghr_x', 'sk-x', 'sk-proj-x', 'sk-ant-x', 'sk_live_x',
  'rk_test_x', 'AIzaX', 'LTAIx', 'STS.x', 'AKIDx', 'AKIAx', 'ASIAx',
  'xoxb-x', 'xoxp-x', 'docker_x',
];
for (const value of shortProviderValues) {
  ok(`label overrides incomplete ${value.split(/[-_]/)[0]} prefix`,
    redact(`password=${value}`) === 'password=***');
}
ok('mixed-case label is still binding', redact('PaSsWoRd=SK-short') === 'PaSsWoRd=***');
ok('spaced label is still binding', redact('password :  sk-short') === 'password :  ***');
ok('placeholder-looking value with suffix is not trusted',
  redact('password=sk-***suffix-canary') === 'password=***');
ok('placeholder-looking value with dot is not trusted',
  redact('password=mb_live_***.suffix-canary') === 'password=***');
ok('partially matched provider value cannot retain a tail',
  redact('password=sk-' + 'A'.repeat(24) + '.suffix-canary') === 'password=***');
ok('bare provider name is not treated as a credential', redact('gho_') === 'gho_');

// === OAuth access tokens ===
section('GitHub OAuth access token regressions');
const oauthCanary = 'gho_' + 'A'.repeat(36);
ok('OAuth pattern is registered', SUPPORTED_PATTERNS.includes('github_oauth_gho'));
ok('bare OAuth value is redacted', redact(oauthCanary) === 'gho_***');
ok('OAuth value in error message is redacted',
  redact(`upstream rejected ${oauthCanary}; retry=false`) === 'upstream rejected gho_***; retry=false');
ok('OAuth value under a public object key is redacted', redactDeep({ message: oauthCanary }).message === 'gho_***');
ok('OAuth value in a JSON array is redacted', redactJson([oauthCanary]) === '["gho_***"]');
ok('multiple OAuth values are all redacted', redact(`${oauthCanary},${oauthCanary}`) === 'gho_***,gho_***');

// === Quoted free-form error values ===
section('quoted labelled credential regressions');
const quotedCases = [
  ['double quoted spaces', 'password="alpha beta gamma" status=ok', 'password=*** status=ok'],
  ['single quoted spaces', "password='alpha beta gamma' status=ok", 'password=*** status=ok'],
  ['quoted delimiters', 'password="alpha,beta;gamma" status=ok', 'password=*** status=ok'],
  ['escaped double quote', 'password="alpha\\" beta" status=ok', 'password=*** status=ok'],
  ['escaped single quote', "password='alpha\\' beta' status=ok", 'password=*** status=ok'],
  ['quoted backslash', 'password="alpha\\\\ beta" status=ok', 'password=*** status=ok'],
  ['empty double quotes', 'password="" status=ok', 'password=*** status=ok'],
  ['empty single quotes', "password='' status=ok", 'password=*** status=ok'],
  ['unclosed double quote', 'password="alpha beta gamma', 'password=***'],
  ['unclosed single quote', "password='alpha beta gamma", 'password=***'],
  ['trailing escape in double quote', 'password="alpha beta\\', 'password=***'],
  ['trailing escape in single quote', "password='alpha beta\\", 'password=***'],
  ['multiline quoted input', 'password="alpha\nbeta" status=ok', 'password=*** status=ok'],
  ['quoted prefixed credential', 'password="sk-short alpha beta" status=ok', 'password=*** status=ok'],
  ['adjacent labelled fields', 'password="alpha beta" token=x status=ok', 'password=*** token=*** status=ok'],
];
for (const [name, input, expected] of quotedCases) ok(name, redact(input) === expected);

// Preserve existing provider-specific placeholders without trusting arbitrary tails.
section('placeholder stability');
const stablePlaceholders = [
  'mb_live_***', 'mb_test_***', 'ghp_***', 'github_pat_***', 'gho_***',
  'ghu_***', 'ghs_***', 'ghr_***', 'sk-***', 'sk-proj-***', 'sk-ant-***',
  'sk_live_***', 'sk_test_***', 'rk_live_***', 'rk_test_***', 'AIza***',
  'LTAI***', 'STS.***', 'AKID***', 'AKIA***', 'ASIA***', 'xoxb-***',
  'xoxp-***', 'docker_***',
];
for (const placeholder of stablePlaceholders) {
  ok(`exact ${placeholder} placeholder is stable`, redact(`token=${placeholder}`) === `token=${placeholder}`);
}

// Deterministic matrix: no random flakiness, network, real keys, or external libraries.
section('redaction regression matrix');
let matrixCases = 0;
let matrixPassed = true;
const labels = ['sig', 'TOKEN', 'password', 'api-key', 'client_secret', 'signing-key'];
const values = ['x', 'sk-short', 'mb_live_x', 'sk-***suffix', 'ordinary-value', oauthCanary];
for (const label of labels) {
  for (const separator of ['=', ':', ' : ']) {
    for (const value of values) {
      for (const quote of ['', '"', "'"]) {
        const input = `${label}${separator}${quote}${value}${quote}`;
        const output = redact(input);
        const expected = !quote && value === oauthCanary ? `${label}${separator}gho_***` : `${label}${separator}***`;
        const deep = redactDeep({ message: input, list: [input], status: 'public' });
        matrixPassed = matrixPassed && output === expected && redact(output) === output &&
          deep.message === expected && deep.list[0] === expected && deep.status === 'public' &&
          redactJson({ message: input }) === JSON.stringify({ message: expected });
        matrixCases++;
      }
    }
  }
}
ok('324 string/deep/JSON/idempotence matrix cases pass', matrixPassed && matrixCases === 324);
console.log(`  Matrix inputs checked: ${matrixCases}`);

section('non-secret and type regressions');
for (const value of ['', 'a', 'ok', 'status=ok', 'gho_', 'ordinary public text']) {
  ok('public text remains unchanged', redact(value) === value);
}
ok('heuristic handles null', hasLikelySecret(null) === false);
ok('heuristic handles numbers', hasLikelySecret(42) === false);
ok('deep redaction handles null', redactDeep(null) === null);
ok('deep redaction handles undefined', redactDeep(undefined) === undefined);
ok('deep redaction preserves numeric fields', redactDeep({ status: 200 }).status === 200);
ok('JSON serialization failure uses safe fallback', redactJson({ count: 1n }) === '[unserializable]');
const inputObject = { message: 'token=x', nested: { password: 'sk-short' } };
const inputBefore = JSON.stringify(inputObject);
redactDeep(inputObject);
ok('redaction does not mutate input', JSON.stringify(inputObject) === inputBefore);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail > 0 ? 1 : 0);
