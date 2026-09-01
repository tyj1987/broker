// broker/signing/gcp-jwt.js — V4 GCP Service Account JWT (self-signed) + token exchange
// Reference: https://cloud.google.com/iam/docs/creating-short-lived-service-account-credentials
//
// Two-step:
//   1. Build a JWT signed with the Service Account private key (RS256)
//   2. POST to https://oauth2.googleapis.com/token to exchange for OAuth2 access token
//
// Caches the access token in memory until 5 min before expiry.

import { createSign } from 'node:crypto';

const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const TOKEN_CACHE = new Map();  // key = saEmail -> { access_token, expires_at }
const SAFETY_MARGIN_MS = 5 * 60 * 1000;

function base64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

/**
 * Build a self-signed JWT for the given SA and scopes.
 * @param {string} saEmail
 * @param {string|Buffer} privateKeyPem
 * @param {string|string[]} scopes
 * @param {number} lifetimeSec
 */
export function buildServiceAccountJwt(saEmail, privateKeyPem, scopes, lifetimeSec = 3600) {
  const now = Math.floor(Date.now() / 1000);
  const scopeStr = Array.isArray(scopes) ? scopes.join(' ') : scopes;
  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iss: saEmail,
    scope: scopeStr,
    aud: GOOGLE_TOKEN_URL,
    iat: now,
    exp: now + (lifetimeSec || 3600),
  };
  const headerB64 = base64url(JSON.stringify(header));
  const payloadB64 = base64url(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signer = createSign('RSA-SHA256');
  signer.update(signingInput);
  const sig = signer.sign(privateKeyPem);
  return `${signingInput}.${base64url(sig)}`;
}

/**
 * Exchange JWT for OAuth2 access token.
 * @param {string} jwt
 * @returns {Promise<{access_token: string, expires_in: number, token_type: string}>}
 */
export async function exchangeJwtForToken(jwt) {
  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: jwt,
  });
  const res = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  if (!res.ok) {
    const t = await res.text();
    throw new Error(`GCP token exchange failed: ${res.status} ${t}`);
  }
  return res.json();
}

/**
 * Get a cached access token or build+exchange a new one.
 * @param {object} sa
 *   sa.email, sa.private_key (PEM string), sa.scopes
 * @returns {Promise<string>} access_token
 */
export async function getAccessToken(sa) {
  const key = sa.email || 'default';
  const cached = TOKEN_CACHE.get(key);
  if (cached && cached.expires_at - Date.now() > SAFETY_MARGIN_MS) {
    return cached.access_token;
  }
  const jwt = buildServiceAccountJwt(sa.email, sa.private_key, sa.scopes || ['https://www.googleapis.com/auth/cloud-platform']);
  const tok = await exchangeJwtForToken(jwt);
  TOKEN_CACHE.set(key, {
    access_token: tok.access_token,
    expires_at: Date.now() + (tok.expires_in * 1000),
  });
  return tok.access_token;
}

/**
 * Compute the Authorization header (Bearer) for a given SA.
 */
export async function signGcpJwt(args) {
  const token = await getAccessToken(args);
  return {
    'Authorization': `Bearer ${token}`,
  };
}

export function clearGcpCache(saEmail) {
  if (saEmail) TOKEN_CACHE.delete(saEmail);
  else TOKEN_CACHE.clear();
}

export default { buildServiceAccountJwt, exchangeJwtForToken, getAccessToken, signGcpJwt, clearGcpCache };
