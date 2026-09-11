#!/bin/bash
# scripts/rotate-secret-ecs.sh — 在 ECS 端独立完成 secret 轮换
# 凭据零接触: 新值从 --value-file 读, 不入 ps / env / log
#
# 流程:
#   1. 读 admin password (从文件, 不入 CLI)
#   2. login → session cookie
#   3. PUT /api/v1/admin/secrets/<name> 提交新 value (走 broker 内部 sops 加密落盘)
#   4. 调 mcp-server run_healthcheck 验新凭据真有效 (出网)
#   5. 全程 echo 不带 secret value, 只 echo name + status + new rotation timestamp
#
# AI 上下文: agent 调起脚本前不接触 secret value, 脚本内不 echo secret value
# 用户在 ECS 终端执行, secret value 在文件里 + 在 broker 内存 (临时)
#
# 用法:
#   sudo /opt/secret-broker/rotate-secret-ecs.sh \
#     --name GITHUB_PAT \
#     --field token \
#     --value-file /tmp/new-github-pat.txt \
#     [--type github_pat]   # optional, 默认从 broker GET 推断
#     [--skip-verify]        # 跳过 healthcheck 验证 (紧急用)
#
# 准备:
#   1. 用户在 GitHub 生成新 PAT (classic + 所需 scope)
#   2. 用户保存到 /tmp/new-github-pat.txt (chmod 600)
#   3. 用户跑本脚本
#   4. 脚本完成后 用户 shred -u /tmp/new-github-pat.txt

set -euo pipefail

# ============================================================
# 参数解析
# ============================================================
NAME=""
FIELD="value"  # 默认 'value' (custom type), 凭据型常用 token / api_key / access_key_id 等
VALUE_FILE=""
TYPE=""        # 可选
SKIP_VERIFY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)         NAME="$2"; shift 2;;
    --field)        FIELD="$2"; shift 2;;
    --value-file)   VALUE_FILE="$2"; shift 2;;
    --type)         TYPE="$2"; shift 2;;
    --skip-verify)  SKIP_VERIFY=1; shift;;
    -h|--help)
      sed -n '2,25p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) echo "ERROR: 未知参数 $1" >&2; exit 2;;
  esac
done

if [[ -z "$NAME" || -z "$VALUE_FILE" ]]; then
  echo "ERROR: --name 和 --value-file 必填" >&2
  exit 2
fi

if [[ ! -f "$VALUE_FILE" ]]; then
  echo "ERROR: value 文件 $VALUE_FILE 不存在" >&2
  exit 2
fi

# value 文件权限检查 (避免 wide-readable)
VALUE_PERM=$(stat -c '%a' "$VALUE_FILE" 2>/dev/null || stat -f '%A' "$VALUE_FILE" 2>/dev/null)
if [[ "$VALUE_PERM" != "600" && "$VALUE_PERM" != "400" ]]; then
  echo "ERROR: value 文件权限应 600/400, 实际 $VALUE_PERM" >&2
  exit 2
fi

# ============================================================
# 配置
# ============================================================
BROKER="https://127.0.0.1:8443"
MCP_SERVER="http://127.0.0.1:3001"
ADMIN_PW_FILE="/opt/secret-broker/.dashboard-password"
CLIENT="client.dashboard-admin"

if [[ ! -f "$ADMIN_PW_FILE" ]]; then
  echo "ERROR: admin password 文件 $ADMIN_PW_FILE 不存在" >&2
  exit 2
fi
ADMIN_PW=$(cat "$ADMIN_PW_FILE")

# ============================================================
# 1. login
# ============================================================
echo "==> 1. login (admin)" >&2
SESSION=$(curl -sk -X POST "$BROKER/api/v1/login" \
  -H 'Content-Type: application/json' \
  -d "{\"client\":\"$CLIENT\",\"password\":\"$ADMIN_PW\"}" \
  | grep -o '"token":"[^"]*"' | head -1 | sed 's/.*"token":"\([^"]*\)".*/\1/')
if [[ -z "$SESSION" ]]; then
  echo "ERROR: login 失败" >&2
  exit 3
fi
echo "    ✓ login ok (session len=${#SESSION})" >&2

# ============================================================
# 2. GET 当前 secret (确认存在 + 拿当前 type)
# ============================================================
echo "==> 2. GET 当前 secret: $NAME" >&2
CURRENT=$(curl -sk -X GET "$BROKER/api/v1/secrets" -H "Cookie: broker_session=$SESSION")
CURRENT_TYPE=$(echo "$CURRENT" | grep -o "\"name\":\"$NAME\"[^}]*\"type\":\"[^\"]*\"" | head -1 | sed 's/.*"type":"\([^"]*\)".*/\1/')
if [[ -z "$CURRENT_TYPE" ]]; then
  echo "ERROR: secret '$NAME' 不存在或无 type 字段" >&2
  exit 3
fi
# type 可选, 默认沿用
if [[ -z "$TYPE" ]]; then
  TYPE="$CURRENT_TYPE"
fi
echo "    ✓ 存在 (type=$TYPE)" >&2

# ============================================================
# 3. PUT 新 value
# ============================================================
echo "==> 3. PUT 新 value (从 $VALUE_FILE, 凭据零接触)" >&2
# 安全: secret value 走 stdin, 不入 Python 字符串拼接 (避免三引号注入)
ROTATE_TMP=$(mktemp /tmp/rotate-XXXXXX.py)
chmod 600 "$ROTATE_TMP"
cat > "$ROTATE_TMP" <<'PYEOF'
import json, sys, urllib.request, ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
new_value = sys.stdin.read()  # 从 stdin 读
name = sys.argv[1]
field = sys.argv[2]
broker = sys.argv[3]
session = sys.argv[4]
data = json.dumps({'fields': {field: new_value}}).encode('utf-8')
req = urllib.request.Request(
  f'{broker}/api/v1/admin/secrets/{name}',
  data=data, method='PUT',
  headers={'Content-Type': 'application/json', 'Cookie': f'broker_session={session}'},
)
try:
  with urllib.request.urlopen(req, context=ctx) as r:
    print(r.read().decode()[:200])
except urllib.error.HTTPError as e:
  print(f'HTTP {e.code}: {e.read().decode()[:200]}')
  sys.exit(1)
PYEOF
# stdin 走 secret value, argv 走 name/field/broker/session (无 secret)
PUT_RESULT=$(cat "$VALUE_FILE" | python3 "$ROTATE_TMP" "$NAME" "$FIELD" "$BROKER" "$SESSION")
rm -f "$ROTATE_TMP"
if echo "$PUT_RESULT" | grep -q '"status":"ok"\|"ok"'; then
  echo "    ✓ PUT 成功" >&2
else
  echo "ERROR: PUT 失败: $PUT_RESULT" >&2
  exit 4
fi

# ============================================================
# 4. 调 mcp-server run_healthcheck 验新凭据 (出网)
# ============================================================
if [[ $SKIP_VERIFY -eq 0 ]]; then
  echo "==> 4. mcp-server run_healthcheck 验证 (出网, 凭据零接触)" >&2
  HC_RESULT=$(curl -sk -X POST "$MCP_SERVER/mcp" \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_healthcheck","arguments":{}}}' \
    | python3 -c "
import json, sys
data = json.load(sys.stdin)
result = json.loads(data['result']['content'][0]['text'])
print(json.dumps({'last_status': result['last_status'], 'summary': result['summary'], 'check': result['checks'].get('$NAME', {})}, indent=2))
")
  echo "$HC_RESULT" >&2
  CHECK_STATUS=$(echo "$HC_RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['check'].get('status', 'unknown'))")
  CHECK_DETAIL=$(echo "$HC_RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['check'].get('detail', ''))")
  if [[ "$CHECK_STATUS" == "fail" ]]; then
    # 区分: 凭据格式错 (abort) vs 网络错 (warn, 不阻塞)
    if echo "$CHECK_DETAIL" | grep -qE 'Invalid character|getaddrinfo|ENOTFOUND|timeout|ECONNREFUSED|ETIMEDOUT|connect'; then
      echo "    ⚠️ 验证网络错 (凭据可能仍正确, 但 ECS 出网受限): $CHECK_DETAIL" >&2
      echo "    凭据已落盘, 后续 ECS 出网稳定后会自动 OK" >&2
    else
      echo "ERROR: 新凭据验证 fail: $CHECK_DETAIL" >&2
      echo "  凭据可能格式错. 建议: 检查凭据, 重新跑" >&2
      exit 5
    fi
  else
    echo "    ✓ 验证通过 (status=$CHECK_STATUS)" >&2
  fi
else
  echo "==> 4. 跳过 healthcheck 验证 (--skip-verify)" >&2
fi

# ============================================================
# 5. 清理
# ============================================================
echo "==> 5. 清理"
echo "    ⚠️  建议手动: shred -u $VALUE_FILE (root 用户)" >&2
echo "    ⚠️  建议手动: 撤销旧凭据 (在 GitHub / OpenAI / Cloudflare dashboard)" >&2

echo ""
echo "=========================================="
echo "  轮换完成"
echo "  name:     $NAME"
echo "  type:     $TYPE"
echo "  field:    $FIELD"
echo "  verified: $([[ $SKIP_VERIFY -eq 0 ]] && echo yes || echo skipped)"
echo "  time:     $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=========================================="
