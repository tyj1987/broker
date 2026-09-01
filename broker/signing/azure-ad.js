// broker/signing/azure-ad.js — V4 Azure AD OAuth2 client_credentials flow
// Reference: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow
//
// Step: POST to https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
//       body: grant_type=client_credentials&client_id=...&client_secret=...&scope=...
//
// Caches the access token in memory.

const TOKEN_CACHE = new Map();
const SAFETY_MARGIN_MS = 5 * 60 * 1000;

export async function getAzureToken({ tenant_id, client_id, client_secret, scope }) {
  const key = `${tenant_id}/${client_id}/${scope || 'default'}`;
  const cached = TOKEN_CACHE.get(key);
  if (cached && cached.expires_at - Date.now() > SAFETY_MARGIN_MS) {
    return cached.access_token;
  }
  const url = `https://login.microsoftonline.com/${encodeURIComponent(tenant_id)}/oauth2/v2.0/token`;
  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id,
    client_secret,
    scope: scope || 'https://graph.microsoft.com/.default',
  });
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  if (!res.ok) {
    const t = await res.text();
    throw new Error(`Azure AD token request failed: ${res.status} ${t}`);
  }
  const tok = await res.json();
  TOKEN_CACHE.set(key, {
    access_token: tok.access_token,
    expires_at: Date.now() + (tok.expires_in * 1000),
  });
  return tok.access_token;
}

export async function signAzureAd(args) {
  const token = await getAzureToken(args);
  return { 'Authorization': `Bearer ${token}` };
}

export function clearAzureCache() { TOKEN_CACHE.clear(); }

export default { getAzureToken, signAzureAd, clearAzureCache };
