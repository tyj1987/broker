import { createPinnedHttpsRequest } from '../lib/pinned-https-request.js';
import { createGitHubAppInstallationTokenProvider } from './github-app-token-provider.js';
import { createGitHubInstallationAuthorityProvider } from './github-installation-authority.js';
import { createGitHubRepositoryReadAdapter } from './github-repository-read.js';

export function createGitHubRepositoryReadExecutor({
  signer,
  accountResolver,
  resolveHost,
  requestImpl,
  now,
  timeoutMs,
} = {}) {
  const request = createPinnedHttpsRequest({ resolveHost, requestImpl, timeoutMs });
  const authorityProvider = createGitHubInstallationAuthorityProvider({
    request,
    signer,
    accountResolver,
    now,
  });
  return async function githubRepositoryReadWithAuthority(parameters, context = {}) {
    const repository = `${parameters?.owner}/${parameters?.repo}`;
    const evidence = await authorityProvider({
      account_ref: context.accountRef,
      environment: context.environment,
      tool: context.execution?.tool,
      target: context.execution?.target,
      execution_environment: context.execution?.environment,
      resource_ref: parameters?.resource_ref,
      repository,
      execution_id: context.execution?.execution_id,
      request_binding: context.execution?.request_binding,
      signal: context.signal,
    });
    const tokenProvider = createGitHubAppInstallationTokenProvider({
      request,
      signer,
      accountResolver: async () => evidence.binding,
      now,
    });
    const repositoryRead = createGitHubRepositoryReadAdapter({ request, tokenProvider, now });
    return { ...(await repositoryRead(parameters, context)), authority: evidence.authority };
  };
}
