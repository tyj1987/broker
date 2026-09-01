#!/bin/bash
# upgrade-v3-to-v4.sh — 一行升级 wrapper: preflight check, then migrate
# 干 3 件:
#   1. 把 preflight + migrate 脚本 download 到 /tmp
#   2. 跑 preflight (dry-run, exit 0 / 1 决定是否继续)
#   3. preflight pass -> 跑 migrate
#
# 用法 (one-liner):
#   curl -fsSL https://raw.githubusercontent.com/tyj1987/broker/v4.1.0/scripts/broker/upgrade-v3-to-v4.sh | sudo bash
#
# 退出码:
#   0  preflight + migrate 都成功
#   1  preflight failed (不会跑 migrate)
#   2  preflight passed 但 migrate 失败 (rollback 自动)
#   3  download failed
set -uo pipefail

REPO_URL="https://raw.githubusercontent.com/tyj1987/broker/v4.1.0/scripts/broker"
TMPDIR=$(mktemp -d)
PREFLIGHT="$TMPDIR/preflight-v3-to-v4.sh"
MIGRATE="$TMPDIR/migrate-v3-to-v4.sh"
trap "rm -rf $TMPDIR" EXIT

echo "============================================"
echo "  broker V3.x -> V4.x one-liner upgrade"
echo "============================================"
echo "  download from: $REPO_URL"
echo "  tmpdir:        $TMPDIR"
echo ""

echo "[1/3] download preflight + migrate scripts"
for script in preflight-v3-to-v4.sh migrate-v3-to-v4.sh; do
  if curl -fsSL "$REPO_URL/$script" -o "$TMPDIR/$script"; then
    chmod +x "$TMPDIR/$script"
    echo "  ✅ $script downloaded"
  else
    echo "  ❌ failed to download $script"
    echo "     check network: curl -I https://raw.githubusercontent.com"
    exit 3
  fi
done

echo ""
echo "[2/3] running preflight (dry-run, no changes)"
echo "--------------------------------------------"
if bash "$PREFLIGHT"; then
  echo ""
  echo "[2/3] ✅ preflight passed"
else
  RC=$?
  echo ""
  echo "[2/3] ❌ preflight FAILED (exit $RC)"
  echo "  do NOT proceed with migration. Fix the failures shown above."
  echo "  re-run preflight standalone: sudo bash $PREFLIGHT"
  exit 1
fi

echo ""
echo "[3/3] running migrate (8-step upgrade + auto-rollback)"
echo "--------------------------------------------"
if bash "$MIGRATE"; then
  echo ""
  echo "============================================"
  echo "  ✅ V3 -> V4 upgrade complete"
  echo "============================================"
  echo "  next steps:"
  echo "    1. verify dashboard: https://broker.52trz.com:8443/"
  echo "    2. test mTLS with a V3 client cert (should still validate)"
  echo "    3. (optional) add V4 features: mfa_policy / signing / workload identity"
  echo "    4. (optional) attach v4.1.0 release assets:"
  echo "         https://github.com/tyj1987/broker/releases/tag/v4.1.0"
  exit 0
else
  RC=$?
  echo ""
  echo "============================================"
  echo "  ❌ migrate FAILED (exit $RC)"
  echo "============================================"
  echo "  V3 state is preserved (auto-backup before migrate)."
  echo "  rollback (if V4 broker is now running broken):"
  echo "    sudo bash /opt/secret-broker-v3-backup-*/rollback.sh"
  echo ""
  echo "  diagnosis:"
  echo "    journalctl -u secret-broker -n 100 --no-pager"
  echo "    cat /opt/secret-broker/audit/broker-stderr.log"
  exit 2
fi
