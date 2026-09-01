#!/bin/bash
# preflight-v3-to-v4.sh — 在跑 migrate-v3-to-v4.sh 之前验证环境 + 干跑检查
# 干 7 件 dry-run 检查 (不动任何文件):
#   1. 是 root 吗
#   2. /opt/secret-broker 存在且是 git repo
#   3. 当前 commit (V3 era? V4 era?)
#   4. broker 进程在跑 + /health 返回 version 3.x
#   5. age key 存在且可读
#   6. sops 安装且能 decrypt broker.yaml
#   7. PKI 完整 (CA + server cert + ≥1 client cert)
# 输出 OK / WARN / FAIL, 任意 FAIL 阻止 migrate.
#
# 用法:
#   sudo bash /tmp/preflight-v3-to-v4.sh
set -uo pipefail

BROKER=/opt/secret-broker
PASS=0
WARN=0
FAIL=0

ok()   { echo "  ✅ $1"; PASS=$((PASS+1)); }
warn() { echo "  ⚠️  $1"; WARN=$((WARN+1)); }
fail() { echo "  ❌ $1"; FAIL=$((FAIL+1)); }

echo "============================================"
echo "  V3 -> V4 migration preflight"
echo "============================================"

echo ""
echo "[1/7] root required"
if [ "$(id -u)" = "0" ]; then ok "running as root"; else fail "not root (rerun with sudo)"; fi

echo ""
echo "[2/7] /opt/secret-broker exists + is git repo"
if [ -d "$BROKER" ]; then ok "$BROKER exists"; else fail "$BROKER missing (run install-ecs.sh first)"; fi
if [ -d "$BROKER/.git" ]; then ok "$BROKER is a git repo"; else warn "$BROKER is NOT a git repo (migrate-v3-to-v4.sh will git init and add origin)"; fi

echo ""
echo "[3/7] detect current broker version"
if [ -d "$BROKER/.git" ]; then
  COMMIT=$(cd "$BROKER" && git rev-parse --short HEAD 2>/dev/null)
  COMMIT_MSG=$(cd "$BROKER" && git log -1 --pretty=%s 2>/dev/null)
  echo "     HEAD: $COMMIT  '$COMMIT_MSG'"
  if echo "$COMMIT_MSG" | grep -qiE "v[34]\.|version [34]|broker v[34]"; then
    if echo "$COMMIT_MSG" | grep -qE "v3\."; then
      ok "detected V3.x at HEAD (will upgrade to V4.x)"
    else
      ok "HEAD looks like V4 already (no upgrade needed?)"
    fi
  else
    warn "HEAD commit message doesn't obviously identify V3 or V4: $COMMIT_MSG"
  fi
else
  warn "no git, cannot detect version from history"
fi
# 备查: systemd unit 检查
if [ -f /etc/systemd/system/secret-broker.service ]; then
  ok "systemd unit /etc/systemd/system/secret-broker.service exists"
else
  fail "systemd unit missing (broker not installed via install-ecs.sh?)"
fi

echo ""
echo "[4/7] broker process running + /health"
if systemctl is-active --quiet secret-broker 2>/dev/null; then
  ok "secret-broker service is active"
else
  fail "secret-broker service NOT active (systemctl status secret-broker)"
fi
if command -v curl >/dev/null; then
  HEALTH=$(curl -sk --max-time 5 https://127.0.0.1:8443/health 2>/dev/null)
  if [ -n "$HEALTH" ]; then
    echo "     $HEALTH"
    VERSION=$(echo "$HEALTH" | grep -oE '"version":"[^"]+"' | cut -d'"' -f4)
    if [ -n "$VERSION" ]; then
      case "$VERSION" in
        3.*) ok "/health reports V3.x (version=$VERSION) - upgrade target confirmed" ;;
        4.*) warn "/health reports V4.x (version=$VERSION) - already up to date, skip migrate" ;;
        *)   warn "/health reports unknown version=$VERSION" ;;
      esac
    else
      warn "could not extract version from /health"
    fi
  else
    fail "/health returned empty (broker not responding on 8443)"
  fi
else
  warn "curl not installed, skip /health check"
fi

echo ""
echo "[5/7] age key readable"
if [ -f "$BROKER/age/key.txt" ]; then
  if [ -r "$BROKER/age/key.txt" ]; then
    AGE_PUB=$(grep '^# public key:' "$BROKER/age/key.txt" | sed 's/.*: *//')
    if [ -n "$AGE_PUB" ]; then
      ok "age key readable, public key: $AGE_PUB"
    else
      fail "age/key.txt exists but no public key line"
    fi
  else
    fail "age/key.txt not readable by current user (chmod 600 + chown root)"
  fi
else
  fail "$BROKER/age/key.txt missing (broker cannot decrypt secrets without it)"
fi

echo ""
echo "[6/7] sops installed + can decrypt broker.yaml"
if command -v sops >/dev/null; then
  SOPS_VER=$(sops --version 2>&1 | head -1)
  ok "sops installed: $SOPS_VER"
  if [ -f "$BROKER/secrets/broker.yaml" ] && [ -n "${AGE_PUB:-}" ]; then
    if export SOPS_AGE_KEY_FILE="$BROKER/age/key.txt" && sops --decrypt "$BROKER/secrets/broker.yaml" 2>/dev/null | head -1 > /dev/null; then
      ok "sops can decrypt secrets/broker.yaml (age key matches sops file)"
    else
      fail "sops CANNOT decrypt secrets/broker.yaml (age key mismatch? file corrupted?)"
    fi
  else
    warn "no secrets/broker.yaml to test decrypt (skip)"
  fi
else
  fail "sops not installed (install via install-ecs.sh or apt/dnf)"
fi

echo ""
echo "[7/7] PKI complete (CA + server cert + client certs)"
if [ -f "$BROKER/pki/ca/ca.crt" ]; then ok "CA cert present"; else fail "CA cert missing"; fi
if [ -f "$BROKER/pki/server/server.crt" ]; then ok "server cert present"; else fail "server cert missing"; fi
CLIENT_CERTS=$(ls "$BROKER/pki/clients/"*.crt 2>/dev/null | wc -l)
if [ "$CLIENT_CERTS" -gt 0 ]; then ok "$CLIENT_CERTS client cert(s) present"; else warn "no client certs (mTLS clients will be unable to connect post-upgrade)"; fi
# check SAN on server cert
if [ -f "$BROKER/pki/server/server.crt" ]; then
  SERVER_SAN=$(openssl x509 -in "$BROKER/pki/server/server.crt" -noout -text 2>/dev/null | grep -A1 'Subject Alternative Name' | tail -1 | tr -d ' ' | tr ',' '\n' | grep -E 'DNS|IP')
  if echo "$SERVER_SAN" | grep -q "broker.52trz.com"; then
    ok "server cert SAN includes broker.52trz.com (Cloudflare passthrough OK)"
  elif echo "$SERVER_SAN" | grep -q "localhost\|127.0.0.1"; then
    warn "server cert SAN only has localhost / 127.0.0.1 (works for direct, may break if accessed by FQDN)"
  fi
fi

echo ""
echo "============================================"
echo "  preflight summary: $PASS pass, $WARN warn, $FAIL fail"
echo "============================================"
if [ "$FAIL" -gt 0 ]; then
  echo ""
  echo "  ❌ $FAIL critical check(s) failed. DO NOT run migrate-v3-to-v4.sh yet."
  echo "  Fix the failures above first (e.g. install sops, restore age key, etc.)"
  exit 1
elif [ "$WARN" -gt 0 ]; then
  echo ""
  echo "  ⚠️  $WARN warning(s). Review above, then proceed if acceptable."
  echo "  Run: sudo bash /tmp/migrate-v3-to-v4.sh"
  exit 0
else
  echo ""
  echo "  ✅ All checks passed. Ready to upgrade."
  echo "  Run: sudo bash /tmp/migrate-v3-to-v4.sh"
  exit 0
fi
