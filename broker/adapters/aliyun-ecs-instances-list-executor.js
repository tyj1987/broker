import { createPinnedHttpsRequest } from '../lib/pinned-https-request.js';
import { createAliyunCallerAuthorityProvider } from './aliyun-caller-authority.js';
import {
  createAliyunEcsInstancesListAdapter,
  validateAliyunEcsInstancesListParameters,
} from './aliyun-ecs-instances-list.js';

export function createAliyunEcsInstancesListExecutor({
  signRequest,
  resolveHost,
  requestImpl,
  timeoutMs,
  now,
} = {}) {
  const request = createPinnedHttpsRequest({ resolveHost, requestImpl, timeoutMs });
  const authorityProvider = createAliyunCallerAuthorityProvider({ request, signRequest, now });
  const instancesList = createAliyunEcsInstancesListAdapter({
    request,
    signRequest,
    now,
  });
  return async function aliyunEcsInstancesListWithAuthority(parameters, context = {}) {
    validateAliyunEcsInstancesListParameters(parameters);
    const evidence = await authorityProvider({
      account_ref: context.accountRef,
      environment: context.environment,
      tool: context.execution?.tool,
      target: context.execution?.target,
      execution_environment: context.execution?.environment,
      resource_ref: parameters?.resource_ref,
      region_id: parameters?.region_id,
      execution_id: context.execution?.execution_id,
      request_binding: context.execution?.request_binding,
      signal: context.signal,
    });
    const result = await instancesList(parameters, {
      ...context,
      providerCredentialBinding: evidence.credential_binding,
    });
    return { ...result, authority: evidence.authority };
  };
}
