#!/bin/bash
# Deploy Aliyun FC 3.0 HTTP relay for Cloudflare API, then point broker.env at it.
# Run on the ECS host (aliyun CLI profile + UDP/53 blocked → DoH into /etc/hosts).
set -euo pipefail

REGION="${FC_REGION:-cn-hongkong}"
FN="${FC_FUNCTION_NAME:-secret-broker-cf-relay}"
ENV_FILE="${BROKER_ENV:-/opt/secret-broker/broker.env}"
SOPS_DETAIL="${SOPS_DETAIL:-/opt/secret-broker/secrets/secrets-detail.json}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC="$ROOT/aliyun/fc-cf-relay/index.py"
if [ ! -f "$SRC" ]; then
  SRC="/opt/secret-broker/aliyun/fc-cf-relay/index.py"
fi
test -f "$SRC"
test -f "$ENV_FILE"
# shellcheck disable=SC1090
set -a
# grep secret without sourcing whole file into xtrace
RELAY_SECRET="$(awk -F= '/^CF_RELAY_SECRET=/{print substr($0, index($0,"=")+1); exit}' "$ENV_FILE")"
test -n "$RELAY_SECRET"
export SOPS_AGE_KEY_FILE="${SOPS_AGE_KEY_FILE:-/opt/secret-broker/age/key.txt}"
eval "$(python3 - "$SOPS_DETAIL" <<'PY'
import json, os, subprocess, sys
path = sys.argv[1]
data = json.loads(subprocess.check_output(['sops', '-d', path]))
if 'secrets' in data:
    data = data['secrets']
f = data['ALIYUN_ACCESS_KEY']['fields']
ak, sk = f['access_key_id'], f['access_key_secret']
# quoted for eval
import shlex
print('export ALIBABA_CLOUD_ACCESS_KEY_ID=' + shlex.quote(ak))
print('export ALIBABA_CLOUD_ACCESS_KEY_SECRET=' + shlex.quote(sk))
print('export ALIBABA_CLOUD_ACCESS_KEY_REGION=' + shlex.quote(os.environ.get('FC_REGION', 'cn-hongkong')))
PY
)"
test -n "${ALIBABA_CLOUD_ACCESS_KEY_ID:-}"
export ALICLOUD_ACCESS_KEY="$ALIBABA_CLOUD_ACCESS_KEY_ID"
export ALICLOUD_SECRET_KEY="$ALIBABA_CLOUD_ACCESS_KEY_SECRET"
export ALIBABA_CLOUD_REGION="$REGION"
ALIYUN=(aliyun --mode AK --access-key-id "$ALIBABA_CLOUD_ACCESS_KEY_ID" --access-key-secret "$ALIBABA_CLOUD_ACCESS_KEY_SECRET")

doh() {
  python3 - "$1" <<'PY'
import json, ssl, socket, http.client, urllib.parse, sys
name = sys.argv[1]
class SniHttps(http.client.HTTPSConnection):
    def __init__(self, hostname, ip, timeout=8):
        super().__init__(hostname, timeout=timeout, context=ssl.create_default_context())
        self._ip = ip
    def connect(self):
        sock = socket.create_connection((self._ip, 443), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
conn = SniHttps('dns.alidns.com', '223.5.5.5')
conn.request('GET', '/resolve?name=%s&type=A' % urllib.parse.quote(name),
             headers={'Host': 'dns.alidns.com', 'Accept': 'application/dns-json'})
j = json.loads(conn.getresponse().read().decode())
conn.close()
ans = [a['data'] for a in (j.get('Answer') or []) if a.get('type') == 1]
if not ans:
    raise SystemExit('DoH empty for %s' % name)
print(ans[0])
PY
}

FC_HOST="fcv3.${REGION}.aliyuncs.com"
FC_IP="$(doh "$FC_HOST")"
echo "FC endpoint $FC_HOST -> $FC_IP"
# UDP/53 is blocked; pin the FC OpenAPI host so aliyun CLI can connect.
if ! grep -q "[[:space:]]$FC_HOST\$" /etc/hosts 2>/dev/null; then
  echo "$FC_IP $FC_HOST" >> /etc/hosts
else
  sed -i "s/^[0-9.]*[[:space:]]$FC_HOST\$/$FC_IP $FC_HOST/" /etc/hosts
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
cp "$SRC" "$WORKDIR/index.py"
python3 - "$WORKDIR" <<'PY'
import os, sys, zipfile, base64
wd = sys.argv[1]
zpath = os.path.join(wd, 'code.zip')
with zipfile.ZipFile(zpath, 'w', zipfile.ZIP_DEFLATED) as z:
    z.write(os.path.join(wd, 'index.py'), 'index.py')
open(os.path.join(wd, 'code.b64'), 'w').write(base64.b64encode(open(zpath, 'rb').read()).decode())
PY
B64="$(cat "$WORKDIR/code.b64")"

BODY="$WORKDIR/create.json"
python3 - "$FN" "$RELAY_SECRET" "$B64" "$BODY" <<'PY'
import json, sys
fn, secret, b64, path = sys.argv[1:5]
json.dump({
    'functionName': fn,
    'description': 'Secret Broker Cloudflare API outbound relay',
    'runtime': 'python3.10',
    'handler': 'index.handler',
    'timeout': 30,
    'memorySize': 256,
    'internetAccess': True,
    'environmentVariables': {'RELAY_SECRET': secret},
    'code': {'zipFile': b64},
}, open(path, 'w'))
PY

echo "CreateFunction $FN in $REGION ..."
CREATE_OUT="$("${ALIYUN[@]}" fc CreateFunction --region "$REGION" --body "$(cat "$BODY")" 2>&1)" || true
echo "$CREATE_OUT" | python3 -c 'import sys,re; t=sys.stdin.read(); t=re.sub(r"(RELAY_SECRET\":\s*\")[^\"]+","\\1***",t); print(t[:800])'
if echo "$CREATE_OUT" | grep -qiE 'already exists|FunctionAlreadyExists|Conflict'; then
  echo "Function exists, UpdateFunction ..."
  python3 - "$FN" "$RELAY_SECRET" "$B64" "$WORKDIR/update.json" <<'PY'
import json, sys
fn, secret, b64, path = sys.argv[1:5]
json.dump({
    'description': 'Secret Broker Cloudflare API outbound relay',
    'runtime': 'python3.10',
    'handler': 'index.handler',
    'timeout': 30,
    'memorySize': 256,
    'environmentVariables': {'RELAY_SECRET': secret},
    'code': {'zipFile': b64},
}, open(path, 'w'))
PY
  "${ALIYUN[@]}" fc UpdateFunction --region "$REGION" --functionName "$FN" --body "$(cat "$WORKDIR/update.json")" | python3 -c 'import sys; print(sys.stdin.read()[:600])'
fi

echo "Ensure HTTP trigger ..."
TRIG_BODY="$WORKDIR/trig.json"
cat > "$TRIG_BODY" <<EOF
{"triggerName":"http","triggerType":"http","description":"public HTTPS","triggerConfig":"{\\"authType\\":\\"anonymous\\",\\"methods\\":[\\"GET\\",\\"POST\\",\\"PUT\\",\\"DELETE\\",\\"HEAD\\",\\"PATCH\\"],\\"disableURLInternet\\":false}"}
EOF
TRIG_OUT="$("${ALIYUN[@]}" fc CreateTrigger --region "$REGION" --functionName "$FN" --body "$(cat "$TRIG_BODY")" 2>&1)" || true
echo "$TRIG_OUT" | python3 -c 'import sys; print(sys.stdin.read()[:800])'

echo "Resolve URL ..."
GET="$("${ALIYUN[@]}" fc GetFunction --region "$REGION" --functionName "$FN" 2>&1)" || true
LISTT="$("${ALIYUN[@]}" fc ListTriggers --region "$REGION" --functionName "$FN" 2>&1)" || true
URL="$(printf '%s\n%s\n' "$GET" "$LISTT" | python3 -c '
import sys, json, re
t = sys.stdin.read()
urls = re.findall(r"https://[A-Za-z0-9._-]+\.fcapp\.run[^\s\"]*", t)
if not urls:
    urls = re.findall(r"https://[A-Za-z0-9._/-]+fc\.aliyuncs\.com[^\s\"]*", t)
print(urls[0].rstrip("/") if urls else "")
print("---raw---", file=sys.stderr)
print(t[:2000], file=sys.stderr)
')"
test -n "$URL"
echo "FC_URL=$URL"

umask 077
tmp="$(mktemp)"
grep -vE '^(CF_RELAY_URL)=' "$ENV_FILE" > "$tmp"
printf 'CF_RELAY_URL=%s\n' "$URL" >> "$tmp"
chmod 600 "$tmp"
mv "$tmp" "$ENV_FILE"
systemctl restart secret-broker
sleep 3
systemctl is-active secret-broker
echo "OK CF_RELAY_URL=$URL"
