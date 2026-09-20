import { createPinnedHttpsRequest } from '../lib/pinned-https-request.js';
import { createDeepSeekModelsListAdapter } from './deepseek-models-list.js';

export function createDeepSeekModelsListExecutor({
  tokenProvider,
  resolveHost,
  requestImpl,
  timeoutMs,
  now,
} = {}) {
  return createDeepSeekModelsListAdapter({
    request: createPinnedHttpsRequest({ resolveHost, requestImpl, timeoutMs }),
    tokenProvider,
    now,
  });
}
