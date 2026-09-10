import { createPinnedHttpsRequest } from '../lib/pinned-https-request.js';
import { createGitHubAppInstallationTokenProvider } from './github-app-token-provider.js';
import { createGitHubIssuesListAdapter } from './github-issues-list.js';

export function createGitHubIssuesListExecutor({
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
    permissions: { issues: 'read' },
  });
  return createGitHubIssuesListAdapter({ request, tokenProvider, now });
}
