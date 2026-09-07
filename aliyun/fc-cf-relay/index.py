# Aliyun FC 3.0 HTTP trigger → api.cloudflare.com
# Auth: X-Broker-Relay-Secret == RELAY_SECRET
# Allowlist: /client/v4 and /client/v4/*

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request

UPSTREAM = 'https://api.cloudflare.com'
ALLOW = '/client/v4'
HOP = {'host', 'connection', 'transfer-encoding', 'keep-alive', 'content-length',
       'x-broker-relay-secret', 'x-broker-upstream-authorization',
       'cf-connecting-ip', 'cf-ray', 'cdn-loop'}


def _json(status, obj):
    return {
        'statusCode': status,
        'headers': {'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store'},
        'isBase64Encoded': False,
        'body': json.dumps(obj, ensure_ascii=False),
    }


def handler(event, context):
    if isinstance(event, (bytes, bytearray)):
        event = event.decode('utf-8')
    if isinstance(event, str):
        try:
            evt = json.loads(event)
        except Exception:
            return _json(400, {'error': 'bad event'})
    else:
        evt = event or {}

    secret = os.environ.get('RELAY_SECRET') or ''
    headers_in = {str(k).lower(): v for k, v in (evt.get('headers') or {}).items()}
    if not secret or headers_in.get('x-broker-relay-secret') != secret:
        return _json(401, {'error': 'unauthorized'})

    path = evt.get('rawPath') or evt.get('path') or '/'
    if '?' in path:
        path, qs_from_path = path.split('?', 1)
    else:
        qs_from_path = ''
    if path != ALLOW and not path.startswith(ALLOW + '/'):
        path = ALLOW + (path if path.startswith('/') else '/' + path)
    if path != ALLOW and not path.startswith(ALLOW + '/'):
        return _json(403, {'error': 'path not allowed'})

    q = evt.get('queryParameters') or {}
    if isinstance(q, dict) and q:
        query = urllib.parse.urlencode(q, doseq=True)
    else:
        query = qs_from_path or (evt.get('queryString') or '')
    url = UPSTREAM + path + (('?' + query) if query else '')

    http = (evt.get('requestContext') or {}).get('http') or {}
    method = (http.get('method') or evt.get('httpMethod') or 'GET').upper()
    body = evt.get('body') or b''
    if evt.get('isBase64Encoded') and body:
        body = base64.b64decode(body)
    elif isinstance(body, str):
        body = body.encode('utf-8')

    out_headers = {'Host': 'api.cloudflare.com', 'User-Agent': 'secret-broker-fc-relay'}
    for k, v in (evt.get('headers') or {}).items():
        if str(k).lower() in HOP:
            continue
        out_headers[k] = v
    auth = headers_in.get('authorization') or headers_in.get('x-broker-upstream-authorization')
    if auth:
        out_headers['Authorization'] = auth

    data = None if method in ('GET', 'HEAD') else body
    req = urllib.request.Request(url, data=data, method=method, headers=out_headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
            status = resp.status
            rh = {k: v for k, v in resp.headers.items() if k.lower() not in HOP}
    except urllib.error.HTTPError as e:
        raw = e.read()
        status = e.code
        rh = {'content-type': e.headers.get('content-type', 'application/json')}
    except Exception as e:
        return _json(502, {'error': 'upstream: %s' % str(e)[:160]})

    return {
        'statusCode': status,
        'headers': rh,
        'isBase64Encoded': True,
        'body': base64.b64encode(raw).decode('ascii'),
    }
