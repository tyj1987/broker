#!/bin/bash
# update-from-github.sh — 在 broker server 上从 GitHub 拉最新代码并重启
# 假设:
#   - broker 已通过 install-ecs.sh 装到 /opt/secret-broker
#   - systemd 服务名: secret-broker
#   - 公网可访问 https://github.com/tyj1987/broker
#   - 当前是 SSH 到 server 跑（不是本地 Windows）
#
# 用法 (在 server 上):
#   sudo bash /opt/secret-broker/scripts/broker/update-from-github.sh
#   # 或者首次拉代码:
#   cd /opt && sudo git clone https://github.com/tyj1987/broker.git secret-broker
#   cd secret-broker && sudo git checkout v4.1.0
#   sudo bash scripts/broker/update-from-github.sh
#
# 这个脚本做 4 件事:
#   1. git fetch + reset --hard 到 origin/master (或指定 tag)
#   2. npm install --omit=dev (如果有新依赖)
#   3. node --check broker/server.js 语法验证
#   4. systemctl restart secret-broker
set -euo pipefail

BROKER=/opt/secret-broker
REF="${BROKER_REF:-origin/master}"
echo "=== [1/4] git fetch + reset to $REF ==="
cd "$BROKER"
if [ ! -d .git ]; then
  echo "ERROR: $BROKER 不是 git 仓库. 先:"
  echo "  cd /opt && sudo git clone https://github.com/tyj1987/broker.git secret-broker"
  echo "  cd secret-broker && sudo git checkout v4.1.0"
  exit 1
fi
git fetch --tags --prune origin
OLD=$(git rev-parse --short HEAD)
git reset --hard "$REF"
NEW=$(git rev-parse --short HEAD)
echo "  $OLD -> $NEW"

echo "=== [2/4] npm install --omit=dev (broker/) ==="
cd "$BROKER/broker"
npm install --omit=dev --no-audit --no-fund 2>&1 | tail -3

echo "=== [3/4] syntax check ==="
node --check server.js
echo "  server.js OK"

echo "=== [4/4] restart secret-broker ==="
systemctl restart secret-broker
sleep 2
systemctl is-active secret-broker
echo
echo "=== verify ==="
curl -sk -o /dev/null -w "GET /health -> %{http_code}\n" https://127.0.0.1:8443/health
curl -sk -o /dev/null -w "GET /api/v1/me (no cert) -> %{http_code}\n" https://127.0.0.1:8443/api/v1/me
echo
echo "DONE. $OLD -> $NEW"
echo "  release notes: https://github.com/tyj1987/broker/releases/tag/$NEW"
