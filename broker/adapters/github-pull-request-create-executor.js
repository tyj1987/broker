import { createPinnedHttpsRequest } from '../lib/pinned-https-request.js';
import { createGitHubAppInstallationTokenProvider } from './github-app-token-provider.js';
import { createGitHubPullRequestCreateAdapter } from './github-pull-request-create.js';

export function createGitHubPullRequestCreateExecutor({
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
    permissions: { pull_requests: 'write' },
  });
  return createGitHubPullRequestCreateAdapter({ request, tokenProvider, now });
}
