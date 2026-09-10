import { createPinnedHttpsRequest } from '../lib/pinned-https-request.js';
import { createGitHubAppInstallationTokenProvider } from './github-app-token-provider.js';
import { createGitHubBranchesListAdapter } from './github-branches-list.js';

export function createGitHubBranchesListExecutor({
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
    permissions: { contents: 'read' },
  });
  return createGitHubBranchesListAdapter({ request, tokenProvider, now });
}
