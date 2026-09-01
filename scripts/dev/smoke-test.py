"""End-user style test (no shell escape issues)."""
import urllib.request, ssl, json

CA = r'E:\broker\pki\ca\ca.crt'
CERT = r'E:\broker\pki\clients\dev-client.crt'
KEY = r'E:\broker\pki\clients\dev-client.key'
BASE = 'https://127.0.0.1:8443'

ctx = ssl.create_default_context(cafile=CA)
ctx.load_cert_chain(CERT, KEY)

def call(method, path, body=None):
    data = json.dumps(body).encode() if body else None
    headers = {'content-type': 'application/json'} if body else {}
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    return urllib.request.urlopen(req, context=ctx, timeout=5).read().decode()

print('=' * 50)
print('1. GET /api/v1/me (your identity)')
print('=' * 50)
print(call('GET', '/api/v1/me')[:300])
print()
print('=' * 50)
print('2. GET /api/v1/secrets (list)')
print('=' * 50)
print(call('GET', '/api/v1/secrets')[:300])
print()
print('=' * 50)
print('3. POST /api/v1/secrets/resolve github.pat')
print('=' * 50)
print(call('POST', '/api/v1/secrets/resolve', {'name': 'github.pat'})[:300])
print()
print('=' * 50)
print('4. POST /api/v1/secrets/resolve openai.key')
print('=' * 50)
print(call('POST', '/api/v1/secrets/resolve', {'name': 'openai.key'})[:300])
print()
print('=' * 50)
print('5. GET /api/v1/health (public, no mTLS)')
print('=' * 50)
ctx2 = ssl._create_unverified_context()
req = urllib.request.Request(BASE + '/health')
print(urllib.request.urlopen(req, context=ctx2, timeout=5).read().decode()[:300])
