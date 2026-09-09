import { createPinnedHttpsRequest } from '../lib/pinned-https-request.js';
import { createDockerRepositoryTagsListAdapter } from './docker-repository-tags-list.js';

export function createDockerRepositoryTagsListExecutor({
  tokenProvider,
  resolveHost,
  requestImpl,
  timeoutMs,
  now,
} = {}) {
  return createDockerRepositoryTagsListAdapter({
    request: createPinnedHttpsRequest({ resolveHost, requestImpl, timeoutMs }),
    tokenProvider,
    now,
  });
}
