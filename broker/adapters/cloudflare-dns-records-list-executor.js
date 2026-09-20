import { createPinnedHttpsRequest } from '../lib/pinned-https-request.js';
import { createCloudflareDnsRecordsListAdapter } from './cloudflare-dns-records-list.js';

export function createCloudflareDnsRecordsListExecutor({
  tokenProvider,
  resolveHost,
  requestImpl,
  timeoutMs,
} = {}) {
  return createCloudflareDnsRecordsListAdapter({
    request: createPinnedHttpsRequest({ resolveHost, requestImpl, timeoutMs }),
    tokenProvider,
  });
}
