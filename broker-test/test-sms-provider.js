// broker-test/test-sms-provider.js — V4 SMS provider interface
// Run: node broker-test/test-sms-provider.js
import {
  SmsRegistry,
  stubSmsProvider,
  makeWebhookSmsProvider,
  generateSmsCode,
} from '../broker/lib/index.js';

let pass = 0, fail = 0;
function ok(name, cond) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}`); }
}
function section(t) { console.log(`\n[${t}]`); }

// === stubSmsProvider ===
section('stub provider');
{
  const r = await stubSmsProvider.send('+8613800000000', '123456');
  ok('returns message_id', typeof r.message_id === 'string' && r.message_id.length > 0);
  ok('provider = stub', r.provider === 'stub');
}

// === generateSmsCode ===
section('generateSmsCode');
for (let n = 4; n <= 10; n++) {
  const code = generateSmsCode(n);
  ok(`length ${n} = ${code.length}`, code.length === n);
  ok(`length ${n} numeric`, /^\d+$/.test(code));
}
{
  let threw = false;
  try { generateSmsCode(3); } catch (_e) { threw = true; }
  ok('length 3 throws', threw);
}
{
  let threw = false;
  try { generateSmsCode(11); } catch (_e) { threw = true; }
  ok('length 11 throws', threw);
}
{
  // Unbiasedness sanity: 1000 calls of 6-digit should give ~uniform distribution
  const counts = new Map();
  for (let i = 0; i < 1000; i++) {
    const c = generateSmsCode(6);
    counts.set(c, (counts.get(c) || 0) + 1);
  }
  ok('1000 codes produce many unique values', counts.size > 900);
}

// === makeWebhookSmsProvider ===
section('webhook provider');
{
  let threw = false;
  try { makeWebhookSmsProvider({}); } catch (_e) { threw = true; }
  ok('missing url throws', threw);
}
{
  let received = null;
  const fetchImpl = async (url, request) => {
    received = { url, ...request };
    return {
      ok: true,
      status: 200,
      statusText: 'OK',
      async json() { return { message_id: 'msg-123', cost: 1 }; },
    };
  };
  const provider = makeWebhookSmsProvider(
    { url: 'https://sms.example.com/send' },
    { fetchImpl },
  );
  const r = await provider.send('+8613800000000', '654321', { ttl_seconds: 300 });
  ok('webhook returns message_id from upstream', r.message_id === 'msg-123');
  ok('webhook returns cost from upstream', r.cost === 1);
  ok('webhook posted phone+code', received && received.body.includes('+8613800000000') && received.body.includes('654321'));
  ok('webhook method=POST', received.method === 'POST');
  ok('webhook redirects are disabled', received.redirect === 'manual');

  // test failure path
  let cancelled = false;
  const provider2 = makeWebhookSmsProvider(
    { url: 'https://sms.example.com/send' },
    { fetchImpl: async () => ({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
      body: { async cancel() { cancelled = true; } },
    }) },
  );
  let err = null;
  try { await provider2.send('+86138', '111'); } catch (e) { err = e; }
  ok('webhook 500 throws', err && /500/.test(err.message));
  ok('webhook error response body is cancelled', cancelled);
}
{
  let err = null;
  try { makeWebhookSmsProvider({ url: 'http://sms.example.com/send' }); } catch (e) { err = e; }
  ok('insecure webhook is denied by default', !!err && /HTTPS/.test(err.message));
}
{
  let err = null;
  try { makeWebhookSmsProvider({ url: 'https://sms.example.com/send', headers: { Host: 'evil.example' } }); } catch (e) { err = e; }
  ok('authority header override is denied', !!err && /not allowed/.test(err.message));
}
{
  const provider = makeWebhookSmsProvider(
    { url: 'https://sms.example.com/send' },
    { fetchImpl: async () => ({ ok: false, status: 307, statusText: 'Temporary Redirect' }) },
  );
  let err = null;
  try { await provider.send('+86138', '111111'); } catch (e) { err = e; }
  ok('webhook redirect is denied', !!err);
}

// === SmsRegistry ===
section('SmsRegistry');
{
  const reg = SmsRegistry.fromConfig(null);
  ok('fromConfig(null) has stub default', reg.defaultName === 'stub');
  ok('fromConfig(null) has stub provider', !!reg.providers.stub);
}
{
  const reg = SmsRegistry.fromConfig({
    default: 'webhook',
    providers: { webhook: { type: 'webhook', url: 'http://example.com/sms', allow_insecure: true } },
  });
  ok('fromConfig uses default', reg.defaultName === 'webhook');
  ok('fromConfig has webhook', !!reg.providers.webhook);
}
{
  const previous = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  let missing = null;
  let insecure = null;
  let stub = null;
  try { SmsRegistry.fromConfig(null); } catch (e) { missing = e; }
  try {
    SmsRegistry.fromConfig({
      default: 'webhook',
      providers: { webhook: { type: 'webhook', url: 'http://sms.example.com/send', allow_insecure: true } },
    });
  } catch (e) { insecure = e; }
  try { SmsRegistry.fromConfig({ default: 'stub', providers: { stub: { type: 'stub' } } }); } catch (e) { stub = e; }
  if (previous === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = previous;
  ok('production requires SMS configuration', !!missing && /configured/.test(missing.message));
  ok('production rejects insecure webhook', !!insecure && /HTTPS/.test(insecure.message));
  ok('production rejects stub provider', !!stub && /unsupported/.test(stub.message));
}
{
  // empty providers -> still has stub
  const reg = SmsRegistry.fromConfig({ providers: {} });
  ok('empty providers falls back to stub', !!reg.providers.stub);
  ok('empty providers default is stub', reg.defaultName === 'stub');
}
{
  // send via registry default
  const reg = SmsRegistry.fromConfig(null);
  const r = await reg.send('+8613800000000', '123456');
  ok('registry.send uses stub', r.provider === 'stub');
}
{
  // unknown providers fail closed
  const reg = SmsRegistry.fromConfig(null);
  let err = null;
  try { await reg.send('+8613800000000', '123', { provider: 'nonexistent' }); } catch (e) { err = e; }
  ok('unknown provider throws', !!err && /not configured/.test(err.message));
}
{
  // direct construction
  const reg = new SmsRegistry({ custom: stubSmsProvider }, 'custom');
  ok('direct construction', reg.defaultName === 'custom');
  const r = await reg.send('+86138', '111', { provider: 'custom' });
  ok('direct send', r.provider === 'stub');  // stub's own name
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail > 0 ? 1 : 0);
