import {
  relayConfig, shouldRelay, applyRelay, RELAY_SECRET_HEADER,
} from '../broker/lib/outbound-relay.js';
import { AI_HEALTHCHECK } from '../broker/healthcheck.js';
import worker from '../workers/cf-api-relay/src/index.js';

let passed = 0, failed = 0;
function assert(c, m) {
  if (c) { passed++; console.log('  OK  ', m); }
  else { failed++; console.error('  FAIL', m); }
}

console.log('=== AI_HEALTHCHECK hosts ===');
assert(AI_HEALTHCHECK.deepseek_key.host === 'api.deepseek.com', 'deepseek host');
assert(AI_HEALTHCHECK.deepseek_key.path === '/v1/models', 'deepseek path');
assert(AI_HEALTHCHECK.openai_key.host === 'api.openai.com', 'openai host unchanged');
assert(AI_HEALTHCHECK.anthropic_key.host === 'api.anthropic.com', 'anthropic host');

console.log('=== relayConfig / applyRelay ===');
{
  const off = relayConfig({ CF_RELAY_URL: '', CF_RELAY_SECRET: '' });
  assert(off.enabled === false, 'disabled without url+secret');
  assert(shouldRelay('api.cloudflare.com', off) === false, 'no relay when disabled');

  const on = relayConfig({
    CF_RELAY_URL: 'https://relay.example.workers.dev',
    CF_RELAY_SECRET: 's3cret',
  });
  assert(on.enabled === true, 'enabled');
  assert(shouldRelay('api.cloudflare.com', on) === true, 'cf host relays');
  assert(shouldRelay('api.github.com', on) === false, 'github does not');

  const applied = applyRelay(new URL('https://api.cloudflare.com/client/v4/user/tokens/verify'), {
    Authorization: 'Bearer tok',
  }, on);
  assert(applied.relayed === true, 'relayed');
  assert(applied.url.hostname === 'relay.example.workers.dev', 'relay host');
  assert(applied.url.pathname === '/client/v4/user/tokens/verify', 'path kept');
  assert(applied.headers.Host === 'relay.example.workers.dev', 'Host is relay');
  assert(applied.headers[RELAY_SECRET_HEADER] === 's3cret', 'secret header');
  assert(applied.headers.Authorization === 'Bearer tok', 'auth kept');
  assert(applied.originalHost === 'api.cloudflare.com', 'originalHost');
}

console.log('=== cf-api-relay worker ===');
{
  const origFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init = {}) => {
    const headers = {};
    if (init.headers && typeof init.headers.forEach === 'function') {
      init.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    } else if (init.headers) {
      for (const [k, v] of Object.entries(init.headers)) headers[k.toLowerCase()] = v;
    }
    calls.push({ url: String(url), method: init.method, headers });
    return new Response(JSON.stringify({ success: true, result: { status: 'active' } }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
  try {
    const env = { RELAY_SECRET: 's3cret' };
    const unauth = await worker.fetch(new Request('https://relay/client/v4/user/tokens/verify'), env);
    assert(unauth.status === 401, 'missing secret → 401');

    const badPath = await worker.fetch(new Request('https://relay/', {
      headers: { 'X-Broker-Relay-Secret': 's3cret' },
    }), env);
    assert(badPath.status === 403, 'root path → 403');

    const ok = await worker.fetch(new Request('https://relay/client/v4/user/tokens/verify', {
      headers: {
        'X-Broker-Relay-Secret': 's3cret',
        Authorization: 'Bearer tok',
      },
    }), env);
    assert(ok.status === 200, 'verify forwarded 200');
    const body = await ok.json();
    assert(body.result?.status === 'active', 'upstream body passed through');
    assert(calls.length === 1, 'one origin fetch');
    assert(calls[0].url === 'https://api.cloudflare.com/client/v4/user/tokens/verify', 'origin URL');
    assert(calls[0].headers.authorization === 'Bearer tok', 'Authorization forwarded');
    assert(!calls[0].headers['x-broker-relay-secret'], 'relay secret stripped');
  } finally {
    globalThis.fetch = origFetch;
  }
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
