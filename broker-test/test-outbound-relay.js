import {
  relayConfig, shouldRelay, applyRelay, RELAY_SECRET_HEADER,
} from '../broker/lib/outbound-relay.js';
import { AI_HEALTHCHECK } from '../broker/healthcheck.js';

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
  const short = applyRelay(new URL('https://api.cloudflare.com/user/tokens/verify'), {}, on);
  assert(short.url.pathname === '/client/v4/user/tokens/verify', 'prefix /client/v4 when action path is root-relative');
  assert(applied.headers.Host === 'relay.example.workers.dev', 'Host is relay');
  assert(applied.headers[RELAY_SECRET_HEADER] === 's3cret', 'secret header');
  assert(applied.headers.Authorization === 'Bearer tok', 'auth kept');
  assert(applied.headers['X-Broker-Upstream-Authorization'] === 'Bearer tok', 'auth duplicated for FC');
  assert(applied.originalHost === 'api.cloudflare.com', 'originalHost');
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
