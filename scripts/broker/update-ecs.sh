#!/bin/bash
# update-ecs.sh — 在 ECS 上更新 Secret Broker（幂等）
# 前提：新代码已放在 /tmp/broker-new/（server.js + dashboard/），
#       patch-broker-config.js 已放在 /tmp/。
# 用法：bash /tmp/update-ecs.sh
set -euo pipefail

BROKER=/opt/secret-broker
SRC=/tmp/broker-new
export SOPS_AGE_KEY_FILE=$BROKER/age/key.txt

echo "=== [1/6] sanity check ==="
[ -f "$SRC/server.js" ] || { echo "ERROR: $SRC/server.js missing"; exit 1; }
[ -f /tmp/patch-broker-config.js ] || { echo "ERROR: /tmp/patch-broker-config.js missing"; exit 1; }

echo "=== [2/6] install new broker code ==="
if [ -f "$BROKER/broker/server.js" ]; then
  cp "$BROKER/broker/server.js" "$BROKER/broker/server.js.bak.$(date +%s)"
  echo "backed up old server.js"
fi
cp "$SRC/server.js" "$BROKER/broker/server.js"
mkdir -p "$BROKER/broker/dashboard"
cp "$SRC/dashboard/"* "$BROKER/broker/dashboard/"
node --check "$BROKER/broker/server.js"
echo "new server.js installed + syntax OK"

echo "=== [3/6] patch broker.yaml (dashboard metadata) ==="
cd "$BROKER/secrets"
WORK=/tmp/broker.working.yaml
if sops --decrypt broker.yaml > "$WORK" 2>/dev/null; then
  echo "broker.yaml was encrypted -> decrypt, patch, re-encrypt"
  node /tmp/patch-broker-config.js "$WORK"
  sops --encrypt --in-place "$WORK"
  cp "$WORK" broker.yaml
else
  echo "broker.yaml is plaintext -> patch in place, then encrypt"
  node /tmp/patch-broker-config.js broker.yaml
  sops --encrypt --in-place broker.yaml
fi
chmod 600 "$WORK" 2>/dev/null || true
echo "broker.yaml re-encrypted"

echo "=== [4/6] verify decrypt ==="
sops --decrypt broker.yaml | grep -c "dashboard_actions" || echo "0"

echo "=== [5/6] restart service ==="
systemctl restart secret-broker
sleep 2
systemctl is-active secret-broker

echo "=== [6/6] verify endpoints ==="
curl -sk https://127.0.0.1:8443/health
echo
curl -sk -o /dev/null -w "GET / -> %{http_code} (%{content_type})\n" https://127.0.0.1:8443/
curl -sk -o /dev/null -w "GET /app.js -> %{http_code} (%{content_type})\n" https://127.0.0.1:8443/app.js
curl -sk -o /dev/null -w "GET /style.css -> %{http_code} (%{content_type})\n" https://127.0.0.1:8443/style.css
echo
echo "DONE. 如需新 dashboard 密码：cat /opt/secret-broker/.dashboard-password"
