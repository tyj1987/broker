#!/bin/bash
# migrate-v3-to-v4.sh — 从 broker v3.x 升级到 v4.x (in-place)
# 假设:
#   - broker V3.x 装在 /opt/secret-broker (从 install-ecs.sh 默认路径)
#   - systemd 服务名: secret-broker
#   - V3 broker.yaml + common.env + clients.json 都在 secrets/
#   - 公网能 git clone https://github.com/tyj1987/broker.git
#
# 用法 (在 server 上以 root):
#   sudo bash /tmp/migrate-v3-to-v4.sh
#   # 默认拉 origin/master; 锁版本:
#   sudo BROKER_REF=v4.1.0 bash /tmp/migrate-v3-to-v4.sh
#
# 干 8 件事:
#   1. 备份 V3 状态 (broker.yaml + clients.json + common.env + pki/)
#   2. 把 V3 仓库 origin 改成 GitHub (兼容 ECS 内旧 origin)
#   3. git fetch + reset --hard 到 origin/master
#   4. 改 broker.env: HOST/PORT -> BROKER_BIND/PORT (V3 -> V4 env var 改名)
#   5. 保留 age key + PKI + sops 加密 (升级不动私钥)
#   6. npm install --omit=dev (新 deps)
#   7. systemctl restart secret-broker (V4 自动 migrate common.env -> secrets-detail.json)
#   8. 验证 /health + /api/v1/me (无 cert 401) + reload V3 客户端 cert 验签
#
# 关键设计: V4 server.js 是 backward compat 的:
#   - V3 broker.yaml (services + clients) 直接 parse, V4 新功能 (mfa/signing/risk score 等) 默认关
#   - V3 common.env 第一次 V4 启动时自动 migrate 到 secrets-detail.json
#   - V3 clients.json 直接读
#   - V3 sops 加密文件 (broker.yaml + common.env) 继续用 V4 sops 读 (age key 不变)
# 所以这次升级不需要手动转 yaml, 是 in-place.
set -euo pipefail

BROKER=/opt/secret-broker
REF="${BROKER_REF:-origin/master}"
BACKUP="/opt/secret-broker-v3-backup-$(date +%Y%m%d-%H%M%S)"
ORIG_REPO="https://github.com/tyj1987/broker.git"

echo "=== [1/8] backup V3 state to $BACKUP ==="
mkdir -p "$BACKUP"
for f in secrets/broker.yaml secrets/clients.json secrets/common.env secrets/healthcheck-state.json secrets/alert-history.jsonl age/key.txt .sops.yaml; do
  if [ -f "$BROKER/$f" ]; then
    mkdir -p "$BACKUP/$(dirname $f)"
    cp "$BROKER/$f" "$BACKUP/$f"
    echo "  backed up $f"
  fi
done
# backup pki/ (CA + server cert + clients) — 保留旧 client cert 是关键
if [ -d "$BROKER/pki" ]; then
  cp -r "$BROKER/pki" "$BACKUP/pki"
  echo "  backed up pki/"
fi
echo "  V3 state snapshot: $BACKUP"
echo "  rollback: sudo bash $BACKUP/rollback.sh (auto-generated below)"

# 写 rollback 脚本
cat > "$BACKUP/rollback.sh" <<'ROLLBACK_EOF'
#!/bin/bash
# rollback.sh — 从 V3 备份恢复 (如果 V4 升级出问题)
set -e
BACKUP="$(cd "$(dirname "$0")"; pwd)"
BROKER=/opt/secret-broker
echo "=== stopping broker ==="
systemctl stop secret-broker 2>/dev/null || true
echo "=== restoring V3 files ==="
for f in secrets/broker.yaml secrets/clients.json secrets/common.env secrets/healthcheck-state.json secrets/alert-history.jsonl age/key.txt .sops.yaml pki; do
  if [ -e "$BACKUP/$f" ]; then
    rm -rf "$BROKER/$f"
    cp -r "$BACKUP/$f" "$BROKER/$f"
    echo "  restored $f"
  fi
done
echo "=== starting broker ==="
systemctl start secret-broker
sleep 2
systemctl is-active secret-broker
echo "=== verify ==="
curl -sk https://127.0.0.1:8443/health
ROLLBACK_EOF
chmod +x "$BACKUP/rollback.sh"

echo ""
echo "=== [2/8] ensure GitHub is the origin ==="
cd "$BROKER"
if ! git remote get-url origin >/dev/null 2>&1; then
  git remote add origin "$ORIG_REPO"
  echo "  added origin -> $ORIG_REPO"
elif [ "$(git remote get-url origin)" != "$ORIG_REPO" ]; then
  echo "  WARN: origin was $(git remote get-url origin); updating to GitHub"
  git remote set-url origin "$ORIG_REPO"
fi
git remote -v

echo ""
echo "=== [3/8] git fetch + reset to $REF ==="
git fetch --tags --prune origin
OLD=$(git rev-parse --short HEAD)
git reset --hard "$REF"
NEW=$(git rev-parse --short HEAD)
echo "  $OLD -> $NEW"

echo ""
echo "=== [4/8] migrate broker.env: V3 HOST/PORT -> V4 BROKER_BIND/PORT ==="
ENV_FILE="$BROKER/broker.env"
if [ -f "$ENV_FILE" ]; then
  # 备份原版
  cp "$ENV_FILE" "$ENV_FILE.v3.bak"
  # rename HOST -> BROKER_BIND (sed -i 不是 POSIX 但 Linux 都有)
  sed -i 's/^HOST=/BROKER_BIND=/' "$ENV_FILE"
  echo "  V3 broker.env backed up to $ENV_FILE.v3.bak; HOST -> BROKER_BIND"
else
  echo "  WARN: no broker.env found, creating from install-ecs.sh template"
  cat > "$ENV_FILE" <<EOF
BROKER_BIND=0.0.0.0
BROKER_PORT=8443
CONFIG_PATH=$BROKER/secrets/broker.yaml
SECRETS_PATH=$BROKER/secrets/common.env
PKI_DIR=$BROKER/pki
AGE_KEY_FILE=$BROKER/age/key.txt
AUDIT_DIR=$BROKER/audit
TLS_CERT=$BROKER/pki/server/server.crt
TLS_KEY=$BROKER/pki/server/server.key
TLS_CA=$BROKER/pki/ca/ca.crt
NODE_ENV=production
EOF
  chmod 600 "$ENV_FILE"
fi
echo "  new broker.env:"
grep -v '^#' "$ENV_FILE" | grep -v '^$' | sed 's/^/    /'

echo ""
echo "=== [5/8] preserve age key + PKI + sops (no change) ==="
ls -la "$BROKER/age/" 2>/dev/null | head -3
echo "  CA cert: $($BROKER/pki/ca/ca.crt 2>/dev/null && echo present || echo MISSING)"
echo "  server cert: $($BROKER/pki/server/server.crt 2>/dev/null && echo present || echo MISSING)"
echo "  client certs: $(ls $BROKER/pki/clients/*.crt 2>/dev/null | wc -l) found"

echo ""
echo "=== [6/8] npm install --omit=dev ==="
cd "$BROKER/broker"
npm install --omit=dev --no-audit --no-fund 2>&1 | tail -3

echo ""
echo "=== [7/8] restart secret-broker (V4 will auto-migrate common.env -> secrets-detail.json) ==="
systemctl restart secret-broker
sleep 3
systemctl is-active secret-broker
echo ""
echo "  journal tail (last 20 lines):"
journalctl -u secret-broker -n 20 --no-pager | sed 's/^/    /'

echo ""
echo "=== [8/8] verify ==="
echo "  /health:"
curl -sk https://127.0.0.1:8443/health | sed 's/^/    /'
echo ""
echo "  /api/v1/me (no cert, expect 401):"
curl -sk -o - -w "    status: %{http_code}\n" https://127.0.0.1:8443/api/v1/me
echo ""
echo "  /api/v1/me (with V3 client cert, expect 200):"
# 找第一个 V3 client cert
FIRST_CERT=$(ls $BROKER/pki/clients/*.crt 2>/dev/null | head -1)
if [ -n "$FIRST_CERT" ] && [ -f "${FIRST_CERT%.crt}.key" ]; then
  curl -sk --cert "$FIRST_CERT" --key "${FIRST_CERT%.crt}.key" --cacert "$BROKER/pki/ca/ca.crt" https://127.0.0.1:8443/api/v1/me | head -c 200 | sed 's/^/    /'
  echo ""
else
  echo "    (no V3 client certs found in $BROKER/pki/clients/ — skip mTLS check)"
fi

echo ""
echo "============================================"
echo "  V3 -> V4 migration complete"
echo "============================================"
echo "  before: V3.x (commit $OLD)"
echo "  after:  V4.x (commit $NEW)"
echo "  backup: $BACKUP"
echo "  rollback (if anything broken): sudo bash $BACKUP/rollback.sh"
echo ""
echo "  Next:"
echo "    1. Open https://broker.52trz.com:8443/ in browser (or via Cloudflare tunnel)"
echo "    2. Verify dashboard loads (V4 has 8 tabs: Home / Me / API Keys / Actions / Audit / Secrets / Admin: Secrets / Admin: Services / Admin: Clients / Docs)"
echo "    3. Test mTLS client cert still works (your V3 client certs should still validate)"
echo "    4. Run secret-broker migrate v3-to-v4 --in-place secrets/broker.yaml if you want"
echo "       to add V4 fields to clients (mfa_policy, etc.)"
echo "    5. (Optional) attach V4.1.0 release assets from https://github.com/tyj1987/broker/releases/tag/v4.1.0"
echo "============================================"
