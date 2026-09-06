#!/bin/bash
# cloud-init-user-data.sh
# Runs on first EC2 launch. Configures broker for AWS (S3 audit + CloudWatch + Let's Encrypt).
set -euxo pipefail

AUDIT_BUCKET="${1:-}"
CLOUDWATCH_GROUP="${2:-}"
DOMAIN="${3:-}"
LETSENCRYPT_EMAIL="${4:-}"

echo "[secret-broker-init] Starting first-launch configuration..."
echo "[secret-broker-init] AUDIT_BUCKET=$AUDIT_BUCKET"
echo "[secret-broker-init] CLOUDWATCH_GROUP=$CLOUDWATCH_GROUP"
echo "[secret-broker-init] DOMAIN=$DOMAIN"
echo "[secret-broker-init] LETSENCRYPT_EMAIL=$LETSENCRYPT_EMAIL"

# 1. Mount /var/log/secret-broker to S3 via s3fs (if AUDIT_BUCKET set)
if [ -n "$AUDIT_BUCKET" ]; then
  echo "[secret-broker-init] Setting up S3 audit log sync..."
  apt-get install -y s3fs
  echo "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY" > /etc/passwd-s3fs
  chmod 0400 /etc/passwd-s3fs
  mkdir -p /var/log/secret-broker
  s3fs "$AUDIT_BUCKET" /var/log/secret-broker -o passwd_file=/etc/passwd-s3fs -o allow_other -o umask=0022
  chown broker:broker /var/log/secret-broker
fi

# 2. Install + start CloudWatch agent (if CLOUDWATCH_GROUP set)
if [ -n "$CLOUDWATCH_GROUP" ]; then
  echo "[secret-broker-init] Setting up CloudWatch agent..."
  wget -q https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
  dpkg -i amazon-cloudwatch-agent.deb
  cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json <<EOF
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/secret-broker/audit.log",
            "log_group_name": "$CLOUDWATCH_GROUP",
            "log_stream_name": "{instance_id}"
          }
        ]
      }
    }
  }
}
EOF
  /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s
fi

# 3. Configure Let's Encrypt (if DOMAIN set)
if [ -n "$DOMAIN" ] && [ -n "$LETSENCRYPT_EMAIL" ]; then
  echo "[secret-broker-init] Setting up Let's Encrypt for $DOMAIN..."
  apt-get install -y certbot
  certbot certonly --standalone --non-interactive --agree-tos -m "$LETSENCRYPT_EMAIL" -d "$DOMAIN" --deploy-hook "systemctl restart secret-broker"
fi

# 4. Enable + start broker
echo "[secret-broker-init] Starting broker..."
systemctl enable secret-broker
systemctl start secret-broker
sleep 5
systemctl is-active secret-broker && echo "[secret-broker-init] broker is active" || (echo "[secret-broker-init] broker failed to start"; journalctl -u secret-broker -n 50; exit 1)

# 5. Verify /health endpoint
HEALTH=$(curl -k -s https://127.0.0.1:8443/health 2>/dev/null || echo "fail")
if echo "$HEALTH" | grep -q '"status":"ok"'; then
  echo "[secret-broker-init] /health OK: $HEALTH"
else
  echo "[secret-broker-init] /health FAILED: $HEALTH"
  exit 1
fi

echo "[secret-broker-init] Done. Broker is ready at https://<instance-public-dns>:8443"
echo "[secret-broker-init] IMPORTANT: rotate the default PKI before production use!"
