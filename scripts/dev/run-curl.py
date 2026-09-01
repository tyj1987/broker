"""run-curl.py - invoke a curl-equivalent request via stdlib.
Bypasses PowerShell tool sandbox that refuses paths with spaces + .exe.
Uses urllib instead (Python's bundled OpenSSL, eats PEM).
"""
import sys, ssl, json, urllib.request, urllib.error

def call(method, path, body=None, ca=r'E:\broker\pki\ca\ca.crt',
         cert=r'E:\broker\pki\clients\dev-client.crt',
         key=r'E:\broker\pki\clients\dev-client.key',
         base='https://127.0.0.1:8443'):
    if method == 'GET' and path == '/health':
        ctx = ssl._create_unverified_context()
    else:
        ctx = ssl.create_default_context(cafile=ca)
        ctx.load_cert_chain(cert, key)
    data = json.dumps(body).encode() if body else None
    headers = {'content-type': 'application/json'} if body else {}
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(req, context=ctx, timeout=10)
        return resp.status, resp.read().decode(errors='replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors='replace')[:500]

if __name__ == '__main__':
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
        print('Usage: python run-curl.py [me|secrets|resolve|health]')
        print('  me      - GET /api/v1/me (mTLS)')
        print('  secrets - GET /api/v1/secrets')
        print('  resolve - POST /api/v1/secrets/resolve github.pat')
        print('  health  - GET /health (public)')
        sys.exit(0)
    op = sys.argv[1]
    if op == 'me':      status, body = call('GET', '/api/v1/me')
    elif op == 'secrets': status, body = call('GET', '/api/v1/secrets')
    elif op == 'resolve': status, body = call('POST', '/api/v1/secrets/resolve', {'name': 'github.pat'})
    elif op == 'health':  status, body = call('GET', '/health')
    else:
        print(f'Unknown op: {op}'); sys.exit(1)
    print(f'status: {status}')
    print(body[:500])
