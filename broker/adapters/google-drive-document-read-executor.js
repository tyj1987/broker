import { createPinnedHttpsRequest } from '../lib/pinned-https-request.js';
import { createGoogleDriveDocumentReadAdapter } from './google-drive-document-read.js';

export function createGoogleDriveDocumentReadExecutor({
  tokenProvider,
  contentFilter,
  resolveHost,
  requestImpl,
  timeoutMs,
  now,
} = {}) {
  return createGoogleDriveDocumentReadAdapter({
    request: createPinnedHttpsRequest({ resolveHost, requestImpl, timeoutMs }),
    tokenProvider,
    contentFilter,
    now,
  });
}
