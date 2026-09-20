import { createPinnedHttpsRequest } from '../lib/pinned-https-request.js';
import { createTencentCvmInstancesListAdapter } from './tencent-cvm-instances-list.js';

export function createTencentCvmInstancesListExecutor({
  signRequest,
  resolveHost,
  requestImpl,
  timeoutMs,
  now,
} = {}) {
  return createTencentCvmInstancesListAdapter({
    request: createPinnedHttpsRequest({ resolveHost, requestImpl, timeoutMs }),
    signRequest,
    now,
  });
}
