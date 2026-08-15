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
# Region: prefer ECS_REGION env, else detect from IMDS, else cn-beijing
REGION="${ECS_REGION:-$(curl -s http://100.100.100.200/latest/meta-data/region-id 2>/dev/null || echo cn-beijing)}"
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
# IMDS 100.100.100.200 isn't always reachable from systemd units on Aliyun ECS.
# Prefer ECS_INSTANCE_ID / ECS_REGION env (set in the systemd service unit);
# fall back to IMDS for ad-hoc runs.
INSTANCE_ID="${ECS_INSTANCE_ID:-$(curl -s --max-time 5 http://100.100.100.200/latest/meta-data/instance-id 2>/dev/null || true)}"
if [ -z "$INSTANCE_ID" ]; then
  echo "[$(date)] FATAL: INSTANCE_ID not set and IMDS unreachable. Set ECS_INSTANCE_ID env or run with --instance-id <id>" >&2
  exit 1
fi
REGION="${ECS_REGION:-$(curl -s --max-time 5 http://100.100.100.200/latest/meta-data/region-id 2>/dev/null || echo cn-beijing)}"
RETENTION_DAYS="${RETENTION_DAYS:-7}"
TS=$(date -u +%Y%m%dT%H%M%SZ)
# mTLS cert for broker (default: ci-runner client cert on this ECS).
# Override with BROKER_CLIENT_CERT / BROKER_CLIENT_KEY to use a different client.
BROKER_CLIENT_CERT="${BROKER_CLIENT_CERT:-/opt/secret-broker/pki/clients/client.ci-runner.crt}"
BROKER_CLIENT_KEY="${BROKER_CLIENT_KEY:-/opt/secret-broker/pki/clients/client.ci-runner.key}"
# Snapshot name prefix; only auto-* is eligible for cleanup
SNAP_PREFIX="${SNAP_PREFIX:-auto-snap}"

# 1. Create snapshot via broker (mTLS)
# CreateSnapshot requires DiskId, not InstanceId. Look up the system disk first.
echo "[$(date)] Looking up system disk for $INSTANCE_ID"
DISK_RESP=$(curl -sk --cert "$BROKER_CLIENT_CERT" --key "$BROKER_CLIENT_KEY" -X POST \
  -H "Content-Type: application/json" \
  -d "{\"method\":\"GET\",\"path\":\"/?Action=DescribeDisks&InstanceId=$INSTANCE_ID&RegionId=$REGION\"}" \
  "$BROKER_URL/api/v1/proxy/aliyun_ecs")
DISK_ID=$(echo "$DISK_RESP" | grep -oE '"DiskId":"[^"]+"' | head -1 | cut -d'"' -f4)
if [ -z "$DISK_ID" ]; then
  echo "[$(date)] ERROR: no disks found for instance: $DISK_RESP" >&2
  exit 1
fi
echo "[$(date)] Creating snapshot of disk $DISK_ID"
RESP=$(curl -sk --cert "$BROKER_CLIENT_CERT" --key "$BROKER_CLIENT_KEY" -X POST \
  -H "Content-Type: application/json" \
  -d "{\"method\":\"GET\",\"path\":\"/?Action=CreateSnapshot&DiskId=$DISK_ID&SnapshotName=${SNAP_PREFIX}-${TS}&RegionId=$REGION\"}" \
  "$BROKER_URL/api/v1/proxy/aliyun_ecs")
SNAP_ID=$(echo "$RESP" | grep -oE '"SnapshotId":"[^"]+"' | head -1 | cut -d'"' -f4)
if [ -z "$SNAP_ID" ]; then
  echo "[$(date)] ERROR: failed to create snapshot: $RESP" >&2
  exit 1
fi
echo "[$(date)] Created snapshot: $SNAP_ID"

# 2. Cleanup old snapshots (>RETENTION_DAYS, only auto-snap-* prefix)
CUTOFF=$(date -u -d "$RETENTION_DAYS days ago" +%Y-%m-%dT%H:%M:%SZ)
echo "[$(date)] Cleaning snapshots older than $CUTOFF (prefix: ${SNAP_PREFIX}-)"
LIST=$(curl -sk --cert "$BROKER_CLIENT_CERT" --key "$BROKER_CLIENT_KEY" -X POST \
  -H "Content-Type: application/json" \
  -d "{\"method\":\"GET\",\"path\":\"/?Action=DescribeSnapshots&InstanceId=$INSTANCE_ID&RegionId=$REGION\"}" \
  "$BROKER_URL/api/v1/proxy/aliyun_ecs")
echo "$LIST" | grep -oE '"SnapshotId":"[^"]+","CreationTime":"[^"]+"' | while read -r line; do
  SID=$(echo "$line" | grep -oE '"SnapshotId":"[^"]+"' | cut -d'"' -f4)
  CTIME=$(echo "$line" | grep -oE '"CreationTime":"[^"]+"' | cut -d'"' -f4)
  if [ -n "$CTIME" ] && [ "$CTIME" \< "$CUTOFF" ] && [[ "$SID" == ${SNAP_PREFIX}-* ]]; then
    echo "[$(date)] Deleting old snapshot: $SID (created $CTIME)"
    curl -sk --cert "$BROKER_CLIENT_CERT" --key "$BROKER_CLIENT_KEY" -X POST \
      -H "Content-Type: application/json" \
      -d "{\"method\":\"GET\",\"path\":\"/?Action=DeleteSnapshot&SnapshotId=$SID&RegionId=$REGION\"}" \
      "$BROKER_URL/api/v1/proxy/aliyun_ecs" > /dev/null
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
After=network-online.target secret-broker.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/secret-broker/scripts/ecs-snapshot-once.sh
# Hardcoded for this ECS instance (IMDS 100.100.100.200 not reachable from systemd unit context on some images).
# Override with `systemctl edit ecs-snapshot.service` if moving to a different instance.
Environment="RETENTION_DAYS=7"
Environment="ECS_INSTANCE_ID=i-2ze8f5ni6c3bod1lxl22"
Environment="ECS_REGION=cn-beijing"
Nice=10
TimeoutStartSec=300
TimeoutStopSec=30
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
