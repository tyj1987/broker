import { createHash } from 'node:crypto';

import { canonicalJson } from './operations-v2.js';

const PROVIDERS = Object.freeze(['github', 'aliyun']);

function selectedProviderMap(source) {
  return Object.fromEntries(PROVIDERS.map((provider) => [provider, source?.[provider] ?? null]));
}

export function providerBindingGeneration(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    throw new TypeError('Provider binding configuration is unavailable');
  }
  const binding = {
    version: 1,
    operation_policies: selectedProviderMap(config.operation_policies),
    provider_accounts: selectedProviderMap(config.provider_accounts),
  };
  return createHash('sha256').update(canonicalJson(binding), 'utf8').digest('hex');
}

export const PROVIDER_BINDING_GENERATION_CONTRACT = Object.freeze({
  version: 1,
  providers: PROVIDERS,
});
