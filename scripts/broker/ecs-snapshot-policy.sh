#!/bin/bash
# ecs-snapshot-policy.sh — ECS 自动快照策略（每日 1 次，保留 7 天）
#
# 用法 (Usage):
#   bash ecs-snapshot-policy.sh install
#   bash ecs-snapshot-policy.sh status
#   bash ecs-snapshot-policy.sh uninstall
#
# 行为 (Behavior):
#   - 创建一个 systemd timer，每天 03:00 触发快照
#   - 通过 broker proxy 调用阿里云 ECS CreateSnapshot（AK 不经 AI 对话）
#   - 同时清理 >7 天的旧快照
#   - 全部操作通过 broker，所以 audit log 完整记录谁、什么时候、调了什么

set -euo pipefail

ACTION="${1:-install}"
BROKER_URL="${BROKER_URL:-https://127.0.0.1:8443}"
SERVICE_NAME="aliyun_ecs"
INSTANCE_ID="${ECS_INSTANCE_ID:-$(curl -s http://100.100.100.200/latest/meta-data/instance-id 2>/dev/null || echo i-z2ze8f5ni6c3bod1lxl22Z)}"
REGION="cn-hangzhou"
RETENTION_DAYS="${RETENTION_DAYS:-7}"
INSTALL_PATH="/opt/secret-broker/scripts"

# ---- install ----
install() {
  echo "==> Installing ECS snapshot policy"
  echo "    Broker:   $BROKER_URL"
  echo "    Service:  $SERVICE_NAME"
  echo "    Instance: $INSTANCE_ID"
  echo "    Region:   $REGION"
  echo "    Retain:   $RETENTION_DAYS days"

  # 1. Snapshot script
  cat > "$INSTALL_PATH/ecs-snapshot-once.sh" <<'SNAP_EOF'
#!/bin/bash
# ecs-snapshot-once.sh — run by timer, called via broker
set -euo pipefail
BROKER_URL="${BROKER_URL:-https://127.0.0.1:8443}"
INSTANCE_ID=$(curl -s http://100.100.100.200/latest/meta-data/instance-id)
REGION="cn-hangzhou"
RETENTION_DAYS="${RETENTION_DAYS:-7}"
TS=$(date -u +%Y%m%dT%H%M%SZ)

# 1. Create snapshot via broker
echo "[$(date)] Creating snapshot for $INSTANCE_ID"
RESP=$(curl -sk -X POST \
  -H "Content-Type: application/json" \
  -d "{\"action\":\"CreateSnapshot\",\"instance_id\":\"$INSTANCE_ID\",\"region\":\"$REGION\",\"snapshot_name\":\"auto-$TS\"}" \
  "$BROKER_URL/api/v1/services/aliyun_ecs/proxy")
SNAP_ID=$(echo "$RESP" | grep -oE '"SnapshotId":"[^"]+"' | head -1 | cut -d'"' -f4)
if [ -z "$SNAP_ID" ]; then
  echo "[$(date)] ERROR: failed to create snapshot: $RESP" >&2
  exit 1
fi
echo "[$(date)] Created snapshot: $SNAP_ID"

# 2. Cleanup old snapshots (>RETENTION_DAYS)
CUTOFF=$(date -u -d "$RETENTION_DAYS days ago" +%Y-%m-%dT%H:%M:%SZ)
echo "[$(date)] Cleaning snapshots older than $CUTOFF"
LIST=$(curl -sk -X POST \
  -H "Content-Type: application/json" \
  -d "{\"action\":\"DescribeSnapshots\",\"region\":\"$REGION\",\"instance_id\":\"$INSTANCE_ID\"}" \
  "$BROKER_URL/api/v1/services/aliyun_ecs/proxy")
echo "$LIST" | grep -oE '"SnapshotId":"[^"]+","CreationTime":"[^"]+"' | while read -r line; do
  SID=$(echo "$line" | grep -oE '"SnapshotId":"[^"]+"' | cut -d'"' -f4)
  CTIME=$(echo "$line" | grep -oE '"CreationTime":"[^"]+"' | cut -d'"' -f4)
  if [ "$CTIME" \< "$CUTOFF" ] && [[ "$SID" == auto-* ]]; then
    echo "[$(date)] Deleting old snapshot: $SID (created $CTIME)"
    curl -sk -X POST \
      -H "Content-Type: application/json" \
      -d "{\"action\":\"DeleteSnapshot\",\"snapshot_id\":\"$SID\",\"region\":\"$REGION\"}" \
      "$BROKER_URL/api/v1/services/aliyun_ecs/proxy" > /dev/null
  fi
done
echo "[$(date)] Done"
SNAP_EOF
  chmod +x "$INSTALL_PATH/ecs-snapshot-once.sh"
  echo "    Wrote: $INSTALL_PATH/ecs-snapshot-once.sh"

  # 2. systemd service
  cat > /etc/systemd/system/ecs-snapshot.service <<'SVC_EOF'
[Unit]
Description=ECS snapshot via broker (daily)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/secret-broker/scripts/ecs-snapshot-once.sh
Environment="RETENTION_DAYS=7"
Nice=10
SVC_EOF

  # 3. systemd timer (daily 03:00)
  cat > /etc/systemd/system/ecs-snapshot.timer <<'TIMER_EOF'
[Unit]
Description=Run ECS snapshot daily

[Timer]
OnCalendar=*-*-* 03:00:00
Persistent=true
RandomizedDelaySec=600

[Install]
WantedBy=timers.target
TIMER_EOF

  systemctl daemon-reload
  systemctl enable --now ecs-snapshot.timer
  echo "    Installed: ecs-snapshot.timer (daily 03:00 ±10min)"

  # 4. Verify
  systemctl list-timers --no-pager | grep ecs-snapshot || true
  echo "==> Done. Run 'bash $0 status' to verify."
}

# ---- status ----
status() {
  echo "=== ECS snapshot policy status ==="
  echo "--- Timer ---"
  systemctl status ecs-snapshot.timer --no-pager || echo "NOT INSTALLED"
  echo "--- Last run (if any) ---"
  systemctl status ecs-snapshot.service --no-pager 2>&1 | head -20 || true
  echo "--- Recent snapshots (via broker) ---"
  curl -sk -X POST -H "Content-Type: application/json" \
    -d "{\"action\":\"DescribeSnapshots\",\"region\":\"$REGION\",\"instance_id\":\"$INSTANCE_ID\"}" \
    "$BROKER_URL/api/v1/services/$SERVICE_NAME/proxy" 2>/dev/null | head -c 500
  echo
}

# ---- uninstall ----
uninstall() {
  echo "==> Uninstalling ECS snapshot policy"
  systemctl disable --now ecs-snapshot.timer 2>/dev/null || true
  rm -f /etc/systemd/system/ecs-snapshot.{service,timer}
  rm -f "$INSTALL_PATH/ecs-snapshot-once.sh"
  systemctl daemon-reload
  echo "==> Done"
}

case "$ACTION" in
  install)   install ;;
  status)    status ;;
  uninstall) uninstall ;;
  *)
    echo "Usage: $0 {install|status|uninstall}" >&2
    exit 1
    ;;
esac
