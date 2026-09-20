import { createPinnedHttpsRequest } from '../lib/pinned-https-request.js';
import { createOpenAIModelsListAdapter } from './openai-models-list.js';

export function createOpenAIModelsListExecutor({
  tokenProvider,
  resolveHost,
  requestImpl,
  timeoutMs,
  now,
} = {}) {
  return createOpenAIModelsListAdapter({
    request: createPinnedHttpsRequest({ resolveHost, requestImpl, timeoutMs }),
    tokenProvider,
    now,
  });
}
