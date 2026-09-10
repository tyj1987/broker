import { createPinnedHttpsRequest } from '../lib/pinned-https-request.js';
import { createGitHubAppInstallationTokenProvider } from './github-app-token-provider.js';
import { createGitHubWorkflowRunsListAdapter } from './github-workflow-runs-list.js';

export function createGitHubWorkflowRunsListExecutor({
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
    permissions: { actions: 'read' },
  });
  return createGitHubWorkflowRunsListAdapter({ request, tokenProvider, now });
}
