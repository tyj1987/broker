#!/bin/bash
# scripts/broker/install-ecs.sh
# 在 ECS（aliyun / tencent / 自建）上从零部署 Secret Broker
# 用法: 在 ECS 上跑
#   curl -fsSL https://raw.githubusercontent.com/tyj1987/sops-age-template/main/scripts/broker/install-ecs.sh | bash
# 或者本地:
#   scp install-ecs.sh user@host:/tmp/ && ssh user@host 'bash /tmp/install-ecs.sh'
#
# 假设:
#   - almalinux 9 / centos 8+ / ubuntu 22+
#   - 有 root 权限
#   - docker 已装并运行
#   - 公网有 8443 端口 (或通过 SSH 隧道 / cloudflared tunnel)

set -e

echo "============================================"
echo "  Secret Broker ECS Bootstrap"
echo "============================================"

# ----- 1. 基础工具 -----
echo "[1/8] installing sops + age..."
if ! command -v sops >/dev/null 2>&1; then
  curl -fsSL -o /usr/local/bin/sops \
    "https://github.com/getsops/sops/releases/download/v3.7.3/sops-v3.7.3.linux.amd64"
  chmod +x /usr/local/bin/sops
fi
if ! command -v age >/dev/null 2>&1; then
  if command -v dnf >/dev/null 2>&1; then
    dnf install -y age
  elif command -v apt >/dev/null 2>&1; then
    apt install -y age
  else
    curl -fsSL -o /tmp/age.tar.gz \
      "https://github.com/FiloSottile/age/releases/download/v1.3.1/age-v1.3.1-linux-amd64.tar.gz"
    tar -xzf /tmp/age.tar.gz -C /tmp
    install -m 755 /tmp/age/age /tmp/age/age-keygen /usr/local/bin/
  fi
fi
sops --version && age --version

# ----- 2. 准备目录 -----
echo "[2/8] preparing /opt/secret-broker..."
mkdir -p /opt/secret-broker
cd /opt/secret-broker
# 把当前目录的 broker 仓库内容 clone / scp 过来 (假设在脚本同一目录)
# 调用方负责把代码传过来, 这里只做结构初始化
for d in secrets pki/ca pki/server pki/clients age audit; do
  mkdir -p "$d"
done
chmod 700 pki

# ----- 3. age keypair -----
echo "[3/8] generating age keypair..."
if [ ! -f age/key.txt ]; then
  age-keygen -o age/key.txt 2>/dev/null
fi
AGE_PUB=$(grep '^# public key:' age/key.txt | sed 's/.*: *//')
chmod 600 age/key.txt
echo "    age pub: $AGE_PUB"

# ----- 4. 写 .sops.yaml -----
cat > .sops.yaml <<EOF
creation_rules:
  - path_regex: .*\.yaml\$
    key_groups:
      - age:
          - "$AGE_PUB"
  - path_regex: .*\.env\$
    key_groups:
      - age:
          - "$AGE_PUB"
  - path_regex: .*\.json\$
    key_groups:
      - age:
          - "$AGE_PUB"
EOF

# ----- 5. PKI -----
echo "[4/8] generating PKI (CA + server + 3 client certs)..."
DOMAIN="${BROKER_DOMAIN:-broker.example.com}"
SERVER_IP=$(curl -s --max-time 5 https://api.ipify.org || echo "127.0.0.1")

# CA
openssl genrsa -out pki/ca/ca.key 4096 2>/dev/null
openssl req -new -x509 -days 3650 -key pki/ca/ca.key -out pki/ca/ca.crt \
  -subj "/CN=Secret Broker Root CA" 2>/dev/null
chmod 600 pki/ca/ca.key

# Server
openssl genrsa -out pki/server/server.key 2048 2>/dev/null
openssl req -new -key pki/server/server.key -out pki/server/server.csr \
  -subj "/CN=$DOMAIN" 2>/dev/null
cat > pki/server/server.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:$DOMAIN,DNS:localhost,IP:127.0.0.1,IP:$SERVER_IP
EOF
openssl x509 -req -in pki/server/server.csr \
  -CA pki/ca/ca.crt -CAkey pki/ca/ca.key -CAcreateserial \
  -out pki/server/server.crt -days 825 -sha256 \
  -extfile pki/server/server.ext 2>/dev/null
rm -f pki/server/server.csr pki/server/server.ext
chmod 600 pki/server/server.key

# Clients
issue_client() {
  local CN="$1"
  openssl genrsa -out "pki/clients/$CN.key" 2048 2>/dev/null
  openssl req -new -key "pki/clients/$CN.key" -out "pki/clients/$CN.csr" \
    -subj "/CN=$CN" 2>/dev/null
  cat > "pki/clients/$CN.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF
  openssl x509 -req -in "pki/clients/$CN.csr" \
    -CA pki/ca/ca.crt -CAkey pki/ca/ca.key -CAcreateserial \
    -out "pki/clients/$CN.crt" -days 365 -sha256 \
    -extfile "pki/clients/$CN.ext" 2>/dev/null
  rm -f "pki/clients/$CN.csr" "pki/clients/$CN.ext"
  chmod 600 "pki/clients/$CN.key"
  openssl x509 -in "pki/clients/$CN.crt" -noout -fingerprint -sha256 | sed 's/.*SHA256 Fingerprint=//'
}

CLIENT_LAPTOP_FP=$(issue_client "client.tyj-laptop")
CLIENT_CI_FP=$(issue_client "client.ci-runner")
CLIENT_ADMIN_FP=$(issue_client "client.dashboard-admin")
echo "    client.tyj-laptop:        $CLIENT_LAPTOP_FP"
echo "    client.ci-runner:        $CLIENT_CI_FP"
echo "    client.dashboard-admin:  $CLIENT_ADMIN_FP"

# ----- 6. 写 broker.yaml + common.env 模板 -----
echo "[5/8] writing broker.yaml + common.env templates..."
cat > secrets/broker.yaml <<EOF
# SOPS 加密前:  sops --age $AGE_PUB --encrypt --in-place secrets/broker.yaml
# 加密后:       sops --decrypt secrets/broker.yaml

services:
  github:
    type: github_token
    token_secret: GITHUB_PAT
    upstream: https://api.github.com
    inject_headers:
      Accept: application/vnd.github+json
      X-GitHub-Api-Version: "2022-11-28"

clients:
  client.tyj-laptop:
    cert_fingerprint_sha256: "$CLIENT_LAPTOP_FP"
    role: developer
    allowed_resolve: ["GITHUB_PAT"]
    allowed_proxy:
      - service: github
        paths: ["^/(user|repos|gists|orgs)/.*"]
    rate_limit: "200/hour"

  client.ci-runner:
    cert_fingerprint_sha256: "$CLIENT_CI_FP"
    role: ci
    allowed_resolve: []
    allowed_proxy:
      - service: github
        paths: ["^/repos/tyj1987/.*/deployments"]
        methods: [POST]
    rate_limit: "1000/hour"

  client.dashboard-admin:
    cert_fingerprint_sha256: "$CLIENT_ADMIN_FP"
    role: admin
    allowed_resolve: [".*"]
    allowed_proxy: [".*"]
    rate_limit: "unlimited"
EOF

cat > secrets/common.env <<EOF
# SOPS 加密前:  sops --age $AGE_PUB --encrypt --in-place secrets/common.env
# 加密后:       sops --decrypt secrets/common.env

GITHUB_PAT=ghp_REPLACE_WITH_REAL_PAT
EOF

# ----- 7. broker 依赖 + 加密 -----
echo "[6/8] installing broker deps + encrypting secrets..."
cd broker
npm install --omit=dev --no-audit --no-fund 2>&1 | tail -3
cd ..

export SOPS_AGE_KEY_FILE="/opt/secret-broker/age/key.txt"
sops --encrypt --in-place secrets/broker.yaml
sops --encrypt --in-place secrets/common.env

# ----- 8. systemd -----
echo "[7/8] writing systemd unit..."
cat > /opt/secret-broker/broker.env <<EOF
PORT=8443
HOST=0.0.0.0
CONFIG_PATH=/opt/secret-broker/secrets/broker.yaml
SECRETS_PATH=/opt/secret-broker/secrets/common.env
PKI_DIR=/opt/secret-broker/pki
AGE_KEY_FILE=/opt/secret-broker/age/key.txt
AUDIT_DIR=/opt/secret-broker/audit
TLS_CERT=/opt/secret-broker/pki/server/server.crt
TLS_KEY=/opt/secret-broker/pki/server/server.key
TLS_CA=/opt/secret-broker/pki/ca/ca.crt
NODE_ENV=production
EOF
chmod 600 /opt/secret-broker/broker.env

cat > /etc/systemd/system/secret-broker.service <<'EOF'
[Unit]
Description=Secret Broker (mTLS credential proxy for AI)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/secret-broker/broker
EnvironmentFile=/opt/secret-broker/broker.env
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable secret-broker
systemctl start secret-broker
sleep 2
systemctl status secret-broker --no-pager | head -5
echo
ss -tlnp 2>/dev/null | grep 8443 || echo "WARN: 8443 not listening"

# ----- 9. 客户端 cert 给用户带走 -----
echo "[8/8] bundle client certs for download..."
BUNDLE="/tmp/secret-broker-client-bundle-$(date +%Y%m%d-%H%M%S).tar.gz"
tar czf "$BUNDLE" -C /opt/secret-broker pki/ca/ca.crt pki/clients
echo
echo "============================================"
echo "  DONE"
echo "============================================"
echo "  broker listening: 0.0.0.0:8443 (mTLS)"
echo "  server cert SAN:  $DOMAIN, localhost, 127.0.0.1, $SERVER_IP"
echo "  client certs:     client.tyj-laptop, client.ci-runner, client.dashboard-admin"
echo "  age pub key:      $AGE_PUB"
echo ""
echo "  client cert bundle:"
echo "    $BUNDLE"
echo "  scp this to your laptop, then:"
echo "    tar xzf secret-broker-client-bundle-*.tar.gz"
echo "    mv pki ~/.broker/"
echo "    write ~/.broker/config.json:"
echo "      {"
echo "        \"endpoint\": \"https://$DOMAIN:8443\","
echo "        \"client_cert\": \"$HOME/.broker/pki/clients/client.tyj-laptop.crt\","
echo "        \"client_key\":  \"$HOME/.broker/pki/clients/client.tyj-laptop.key\","
echo "        \"ca_cert\":     \"$HOME/.broker/pki/ca/ca.crt\""
echo "      }"
echo ""
echo "  test from laptop:"
echo "    node cli/secret-broker.js health"
echo ""
echo "  if 8443 is not publicly reachable, use SSH tunnel:"
echo "    ssh -L 8443:127.0.0.1:8443 $DOMAIN"
echo "    node cli/secret-broker.js health"
echo "============================================"
