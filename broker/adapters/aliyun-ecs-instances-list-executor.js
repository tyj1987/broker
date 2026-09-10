import { createPinnedHttpsRequest } from '../lib/pinned-https-request.js';
import { createAliyunEcsInstancesListAdapter } from './aliyun-ecs-instances-list.js';

export function createAliyunEcsInstancesListExecutor({
  signRequest,
  resolveHost,
  requestImpl,
  timeoutMs,
  now,
} = {}) {
  return createAliyunEcsInstancesListAdapter({
    request: createPinnedHttpsRequest({ resolveHost, requestImpl, timeoutMs }),
    signRequest,
    now,
  });
}
