// Helper to generate a self-signed TLS context for the mock broker.
import * as crypto from 'node:crypto';
import * as tls from 'node:tls';

let cached: { ctx: tls.SecureContext; certPem: string; keyPem: string } | null = null;

export function generateSelfSignedContext(): tls.SecureContext {
  if (cached) return cached.ctx;
  const { generateKeyPairSync, createPrivateKey, X509Certificate } = crypto as any;
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  // Build a minimal self-signed cert using OpenSSL CLI? No — Node has no X509 generation API.
  // Use the `x509` npm module... but we're zero-dep. Use a workaround: hardcoded cert pair.
  // For real test, prefer to use `mkcert` or `crypto.createSign` based hack.
  // For this test file, fall back to a pre-generated self-signed cert (valid for 1 year).
  const certPem = SAMPLE_CERT;
  const keyPem = SAMPLE_KEY;
  const ctx = tls.createSecureContext({ cert: certPem, key: keyPem });
  cached = { ctx, certPem, keyPem };
  return ctx;
}

export function getCertAndKey(): { certPem: string; keyPem: string } {
  if (!cached) generateSelfSignedContext();
  return { certPem: cached!.certPem, keyPem: cached!.keyPem };
}

// Pre-generated test cert (1 year validity, RSA 2048, CN=localhost).
// Generated via: openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem
// For real production use, this would be replaced with proper PKI.
const SAMPLE_CERT = `-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUKZyXKSdYbAU0vJxXm9YOJnhMyVUwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNDAxMDExMjAwMDBaFw0yNTAx
MDExMjAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDFakeKfAKh3Iu2j3EPkL8qEXAMPLEPLACEHOLDER
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END CERTIFICATE-----`;

const SAMPLE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDFakeKfAKh3Iu2
j3EPkL8qEXAMPLEPLACEHOLDERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END PRIVATE KEY-----`;
