import { timingSafeEqual } from 'node:crypto';

export function isReloadTokenValid(headers, expectedToken) {
  const supplied = headers?.['x-reload-token'];
  if (typeof supplied !== 'string' || typeof expectedToken !== 'string'
    || supplied.length === 0 || expectedToken.length === 0) return false;
  const suppliedBytes = Buffer.from(supplied, 'utf8');
  const expectedBytes = Buffer.from(expectedToken, 'utf8');
  return suppliedBytes.length === expectedBytes.length
    && timingSafeEqual(suppliedBytes, expectedBytes);
}
