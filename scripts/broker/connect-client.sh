#!/bin/bash
# scripts/broker/connect-client.sh
# 在用户笔记本上启动 SSH 隧道到 broker ECS
# 用法:
#   BROKER_HOST=example.com BROKER_PORT=8443 LOCAL_PORT=18443 ./connect-client.sh
# 然后:
#   export BROKER_CONFIG=~/.broker/config.json
#   node cli/secret-broker.js health

set -e

BROKER_HOST="${BROKER_HOST:-example.com}"
BROKER_PORT="${BROKER_PORT:-8443}"
LOCAL_PORT="${LOCAL_PORT:-18443}"

echo "Starting SSH tunnel: localhost:$LOCAL_PORT -> $BROKER_HOST:$BROKER_PORT"
echo "Stop with Ctrl-C"
echo

# -N: no remote command
# -L: local port forward
# -o ExitOnForwardFailure=yes: fail if can't bind local port
# -o ServerAliveInterval=30: keep alive
exec ssh -N \
  -L "${LOCAL_PORT}:127.0.0.1:${BROKER_PORT}" \
  -o "ExitOnForwardFailure=yes" \
  -o "ServerAliveInterval=30" \
  -o "ServerAliveCountMax=4" \
  "$BROKER_HOST"
