# cloud-init.sh - 阿里云 ECS 首次启动
# 安装 Docker + clone 仓库 + 准备 broker 数据目录
#!/bin/bash
set -e

# 设置控制台
echo 'export LANG=en_US.UTF-8' >> /root/.bashrc
echo 'export LC_ALL=en_US.UTF-8' >> /root/.bashrc

# 更新 + 安装基础工具
apt-get update -y
apt-get install -y --no-install-recommends \
    curl git jq ca-certificates gnupg openssl age \
    apt-transport-https software-properties-common

# 安装 Docker
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# 安装 SOPS
curl -fsSL https://github.com/getsops/sops/releases/download/v3.7.3/sops-v3.7.3.linux.amd64 \
  -o /usr/local/bin/sops
chmod +x /usr/local/bin/sops

# 准备目录
mkdir -p /opt/secret-broker/{secrets,pki/ca,pki/server,pki/clients,age,audit,scripts/broker}
chown -R root:root /opt/secret-broker

# clone 仓库（用户需要在 terraform 里通过 user_data 传 GitHub PAT，或者手动 clone）
# 这里假设用户已手动 clone
cat > /opt/secret-broker/README.txt <<EOF
Secret Broker Bootstrap Complete!

Next steps:
  1. cd /opt/secret-broker
  2. Clone your repo here:    git clone https://github.com/YOUR_USER/sops-age-template.git .
  3. Or copy your local:      scp -r ./* root@${eip}:/opt/secret-broker/
  4. Run PKI init:            ./scripts/broker/init-ca.sh
  5. Issue server cert:       ./scripts/broker/issue-server-cert.sh --domain ${domain}
  6. Issue client cert:       ./scripts/broker/issue-client-cert.sh --cn client.tyj-laptop
  7. Configure secrets:       cp secrets/broker.yaml.example secrets/broker.yaml && sops --encrypt --in-place secrets/broker.yaml
  8. Start broker:            docker compose up -d broker
  9. Verify:                  curl -k https://localhost:8443/health

Domain (SAN): ${domain}
Public IP:    ${eip}
EOF

# 写一个状态文件
cat > /etc/motd <<EOF
================================
  Secret Broker
  Domain: ${domain}
  IP:     ${eip}
  Status: NOT YET CONFIGURED - run /opt/secret-broker/README.txt steps
================================
EOF

echo "Cloud-init done. See /opt/secret-broker/README.txt"
