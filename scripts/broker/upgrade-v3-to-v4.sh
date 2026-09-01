#!/bin/bash
# upgrade-v3-to-v4.sh — V3 -> V4 upgrade orchestrator (4 methods)
# 干 3 件:
#   1. 拿到 V4.1.0 source (4 种方法按顺序试, 第一个成功就停)
#   2. 跑 preflight (dry-run)
#   3. preflight pass -> 跑 migrate
#
# 用法 (3 种, 选 1):
#
# A. /opt/secret-broker 已是 git repo (旧 V3):
#    cd /opt/secret-broker
#    sudo git fetch --tags --prune origin
#    sudo git reset --hard v4.1.0   # 现在有 V4 source 了
#    sudo bash scripts/broker/upgrade-v3-to-v4.sh --local
#
# B. server 上有 GitHub auth (SSH key 或 ~/.netrc 或 git credential helper):
#    sudo bash <(curl -fsSL https://github.com/tyj1987/broker/releases/download/v4.1.0/upgrade-v3-to-v4-remote.sh)
#    # OR
#    git clone --depth 1 --branch v4.1.0 https://github.com/tyj1987/broker.git /tmp/broker-v4
#    sudo bash /tmp/broker-v4/scripts/broker/upgrade-v3-to-v4.sh --local
#
# C. scp scripts from local machine (most reliable for private repos):
#    scp scripts/broker/preflight-v3-to-v4.sh \
#        scripts/broker/migrate-v3-to-v4.sh \
#        scripts/broker/upgrade-v3-to-v4.sh \
#        user@broker.52trz.com:/tmp/
#    ssh user@broker.52trz.com "sudo bash /tmp/upgrade-v3-to-v4.sh --local"
#
# 本脚本默认 --local (从当前目录的 scripts/broker/ 找 2 个子脚本)
# --remote 会先 git clone (需要 server 上有 GitHub auth)
#
# 退出码:
#   0  成功
#   1  preflight 失败
#   2  migrate 失败 (auto-rollback)
#   3  无法获取 V4 source
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODE="${1:---local}"

echo "============================================"
echo "  broker V3.x -> V4.x upgrade orchestrator"
echo "============================================"
echo "  mode: $MODE"
echo ""

WORKDIR=""

if [ "$MODE" = "--local" ]; then
  # Use scripts from current dir (already in V4 source via git pull / scp / clone)
  PREFLIGHT="$SCRIPT_DIR/preflight-v3-to-v4.sh"
  MIGRATE="$SCRIPT_DIR/migrate-v3-to-v4.sh"
  if [ ! -f "$PREFLIGHT" ] || [ ! -f "$MIGRATE" ]; then
    echo "  ❌ expected $PREFLIGHT and $MIGRATE to exist"
    echo "  run from /opt/secret-broker (V4 source) or pass --remote with GitHub auth"
    exit 3
  fi
  echo "  [local] preflight: $PREFLIGHT"
  echo "  [local] migrate:   $MIGRATE"

elif [ "$MODE" = "--remote" ]; then
  # Try git clone (needs server's GitHub auth: SSH key, PAT, or netrc)
  WORKDIR=$(mktemp -d)
  echo "  [remote] git clone --depth 1 --branch v4.1.0 https://github.com/tyj1987/broker.git $WORKDIR"
  if ! git clone --depth 1 --branch v4.1.0 https://github.com/tyj1987/broker.git "$WORKDIR" 2>&1 | sed 's/^/    /'; then
    echo ""
    echo "  ❌ git clone failed (no GitHub auth on this server)"
    echo ""
    echo "  fix one of these:"
    echo "    1. add GitHub SSH key: ssh-add ~/.ssh/id_ed25519_github"
    echo "    2. add PAT to ~/.netrc:"
    echo "         echo 'machine github.com login tyj1987 password ghp_xxx' > ~/.netrc"
    echo "         chmod 600 ~/.netrc"
    echo "    3. use --local mode: scp scripts from your local machine instead"
    rm -rf "$WORKDIR"
    exit 3
  fi
  PREFLIGHT="$WORKDIR/scripts/broker/preflight-v3-to-v4.sh"
  MIGRATE="$WORKDIR/scripts/broker/migrate-v3-to-v4.sh"
  chmod +x "$PREFLIGHT" "$MIGRATE"
  echo "  [remote] scripts ready"
fi

echo ""
echo "[1/3] running preflight (dry-run, no changes)"
echo "--------------------------------------------"
if bash "$PREFLIGHT"; then
  echo ""
  echo "[1/3] ✅ preflight passed"
else
  RC=$?
  echo ""
  echo "[1/3] ❌ preflight FAILED (exit $RC)"
  echo "  do NOT proceed with migration. Fix the failures shown above."
  exit 1
fi

echo ""
echo "[2/3] running migrate (8-step upgrade + auto-rollback)"
echo "--------------------------------------------"
if bash "$MIGRATE"; then
  echo ""
  echo "[2/3] ✅ migrate succeeded"
else
  RC=$?
  echo ""
  echo "[2/3] ❌ migrate FAILED (exit $RC)"
  echo "  V3 state auto-backed up to /opt/secret-broker-v3-backup-*/"
  echo "  rollback if needed: sudo bash /opt/secret-broker-v3-backup-*/rollback.sh"
  exit 2
fi

echo ""
echo "[3/3] post-migration cleanup"
if [ -n "$WORKDIR" ]; then
  rm -rf "$WORKDIR"
  echo "  removed temp clone: $WORKDIR"
fi
echo "  ✅ done"
echo ""
echo "============================================"
echo "  verify on broker.52trz.com:"
echo "    curl -sk https://broker.52trz.com:8443/health"
echo "    # expect: {\"version\":\"4.1.0\",...}"
echo ""
echo "  attach v4.1.0 release assets (if you haven't):"
echo "    https://github.com/tyj1987/broker/releases/tag/v4.1.0"
echo "============================================"
exit 0
