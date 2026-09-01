// broker/signing/cloudflare.js — V4 Cloudflare API token
// Trivial Bearer token. Mainly here for consistent interface — other providers
// can call signCloudflare(secret) and get a header object back.

export function signCloudflare(secret) {
  if (!secret || !secret.api_token) {
    throw new Error('Cloudflare sign: secret.api_token required');
  }
  return {
    'Authorization': `Bearer ${secret.api_token}`,
    'Content-Type': 'application/json',
  };
}

export default { signCloudflare };
