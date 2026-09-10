import { createPinnedHttpsRequest } from '../lib/pinned-https-request.js';
import { createGitHubAppInstallationTokenProvider } from './github-app-token-provider.js';
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
  const tokenProvider = createGitHubAppInstallationTokenProvider({
    request,
    signer,
    accountResolver,
    now,
  });
  return createGitHubRepositoryReadAdapter({ request, tokenProvider, now });
}
