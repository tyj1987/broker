import { createPinnedHttpsRequest } from '../lib/pinned-https-request.js';
import { createCloudflareZonesListAdapter } from './cloudflare-zones-list.js';

export function createCloudflareZonesListExecutor({
  tokenProvider,
  resolveHost,
  requestImpl,
  timeoutMs,
} = {}) {
  return createCloudflareZonesListAdapter({
    request: createPinnedHttpsRequest({ resolveHost, requestImpl, timeoutMs }),
    tokenProvider,
  });
}
