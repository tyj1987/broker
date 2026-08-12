#!/bin/bash
# scripts/broker/inject-aliyun-ak.sh
# 在 ECS 上跑 — 把新的 aliyun 子用户 AK 注入到 broker（不经过任何 AI 工具对话）
#
# 用法：
#   1. 用户在阿里云 RAM 控制台创建/rotate 新的 ecsread 子用户 AK
#   2. SSH 到 ECS
#   3. 编辑此脚本的 AK 值（不粘贴到任何 AI 工具）
#   4. 跑:  bash inject-aliyun-ak.sh
#
# 脚本做的事：
#   1. 用 age 密钥 + sops 加密新的 common.env（替换占位）
#   2. 重启 broker

set -e
cd /opt/secret-broker

# ===== 在这里填新 AK（直接编辑本文件）=====
ALIYUN_ACCESS_KEY="LTAI5tXXXXXXXXXXXXXX"
ALIYUN_ACCESS_SECRET="your_new_secret_here_XXXXX"
# =========================================

# 1. 读现有 common.env，替换两个 aliyun 行
export SOPS_AGE_KEY_FILE="/opt/secret-broker/age/key.txt"
sops --decrypt secrets/common.env > /tmp/common.env.plain || {
  echo "ERR: failed to decrypt existing common.env" >&2; exit 1;
}

# 2. 替换 ALIYUN_* 行（保留其他行如 GITHUB_PAT）
awk -v ak="$ALIYUN_ACCESS_KEY" -v sk="$ALIYUN_ACCESS_SECRET" '
  /^ALIYUN_ACCESS_KEY=/  { print "ALIYUN_ACCESS_KEY=" ak; next }
  /^ALIYUN_ACCESS_SECRET=/ { print "ALIYUN_ACCESS_SECRET=" sk; next }
  { print }
' /tmp/common.env.plain > /tmp/common.env.new

# 3. 严格权限（避免 plain 在磁盘上保留太久）
chmod 600 /tmp/common.env.new /tmp/common.env.plain
shred -u /tmp/common.env.plain 2>/dev/null || mv /tmp/common.env.plain /tmp/common.env.plain.removed

# 4. SOPS 加密新文件
sops --encrypt --in-place /tmp/common.env.new
mv /tmp/common.env.new secrets/common.env
chmod 600 secrets/common.env

# 5. 重启 broker
systemctl restart secret-broker
sleep 2
systemctl status secret-broker --no-pager | head -5

echo
echo "=== verify ==="
sops --decrypt secrets/common.env | grep -E "ALIYUN"
echo
echo "=== test aliyun_v2 proxy (from your laptop, via SSH tunnel) ==="
echo "  BROKER_CONFIG=~/.broker/config.json \\"
echo "    node cli/secret-broker.js proxy aliyun_ecs GET /?Action=DescribeRegions"
