// Safe bounded preview for upstream responses shown in operator diagnostics.
// Never expose credential-shaped values or sensitive JSON fields.

import { redact, redactDeep } from './redact.js';

export function safeUpstreamPreview(body, maxLength = 500) {
  if (body === null || body === undefined) return '';
  const text = Buffer.isBuffer(body) ? body.toString('utf8') : String(body);
  try {
    const parsed = JSON.parse(text);
    return JSON.stringify(redactDeep(parsed)).slice(0, maxLength);
  } catch {
    return redact(text).slice(0, maxLength);
  }
}
