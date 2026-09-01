# DEPLOY-52TRZ.md — Secret Broker 部署到 broker.52trz.com

> Generated 2026-09-01 (V4.1.0 GA)
> 域名：`broker.52trz.com` (TLS 443 或 mTLS 8443)
> 部署根：`/opt/secret-broker` (Linux) — Windows dev 用 `E:\broker`

## 1. 三种部署场景

| 场景 | 何时用 | 脚本 |
|------|--------|------|
| **A. 首次部署** | server 上 broker 还没装 | `scripts/broker/install-ecs.sh` (一次性, 9 步) |
| **B. 从零 git 拉** | server 有空白 `/opt/secret-broker`, 但不是 git 仓库 | `git clone` + `update-from-github.sh` |
| **C. 更新到新版本** | server 已有 broker, 想升 v4.1.0 / 后续 v4.x | `update-from-github.sh` |

## 2. 场景 A — 首次部署 (Aliyun ECS / 任何 Linux 主机)

前提: Linux 主机 (Ubuntu 22+ / AlmaLinux 9+ / Debian 12+), 有 root, 公网 IP, **8443 端口可达** (mTLS) 或经 Cloudflare Tunnel。

```bash
# 1. SSH 上去
ssh root@broker.52trz.com   # 或 user@<server-ip>

# 2. 装前置
apt update && apt install -y curl git openssl   # Debian/Ubuntu
# 或 dnf install -y curl git openssl           # AlmaLinux

# 3. 拉代码 (scp 或 git clone)
cd /opt
git clone https://github.com/tyj1987/broker.git secret-broker
cd secret-broker
git checkout v4.1.0

# 4. 跑 install-ecs.sh (9 步, 一次性)
bash scripts/broker/install-ecs.sh
# 脚本会:
#   - 装 sops + age
#   - 建 /opt/secret-broker/{secrets,pki,age,audit}
#   - 生成 age keypair + .sops.yaml
#   - 生成 CA + server cert (SAN: broker.52trz.com + 公网 IP) + 3 client cert
#   - 写 secrets/broker.yaml 模板 + secrets/common.env 模板
#   - npm install --omit=dev
#   - SOPS encrypt broker.yaml + common.env
#   - 写 systemd unit: secret-broker.service
#   - bundle 3 client cert 到 /tmp/secret-broker-client-bundle-*.tar.gz

# 5. 拿 client cert bundle
scp root@broker.52trz.com:/tmp/secret-broker-client-bundle-*.tar.gz ~/
tar xzf ~/secret-broker-client-bundle-*.tar.gz -C ~/
mv ~/pki ~/.broker/

# 6. 本地 ~/.broker/config.json
cat > ~/.broker/config.json <<EOF
{
  "endpoint": "https://broker.52trz.com:8443",
  "client_cert": "$HOME/.broker/pki/clients/client.tyj-laptop.crt",
  "client_key":  "$HOME/.broker/pki/clients/client.tyj-laptop.key",
  "ca_cert":     "$HOME/.broker/pki/ca/ca.crt"
}
EOF

# 7. 本地验证 (需要 python + urllib, 因为 Windows curl Schannel 跟 PEM 不兼容)
node cli/secret-broker.js health
# 或:
python scripts/dev/run-curl.py me
```

## 3. 场景 C — 更新到 v4.1.0

```bash
# SSH 上去
ssh root@broker.52trz.com

# 跑一行
cd /opt/secret-broker
sudo bash scripts/broker/update-from-github.sh
# 默认拉 origin/master; 要锁版本:
#   sudo BROKER_REF=v4.1.0 bash scripts/broker/update-from-github.sh
```

脚本 4 步:
1. `git fetch --tags --prune origin` + `git reset --hard $REF`
2. `npm install --omit=dev` (新依赖)
3. `node --check broker/server.js` 语法验证
4. `systemctl restart secret-broker` + 验证 `/health`

## 4. DNS / TLS / 端口

- **域名**: `broker.52trz.com` 继续用 (Cloudflare 代理或直连)
- **端口**:
  - `8443` mTLS (生产端口, 客户端必须用 cert 验签)
  - `443` 若用 Cloudflare Tunnel 走 HTTPS (但仍是 mTLS, 不是 public)
  - 永远不要开放 80/8080 public — broker 是私有凭据服务
- **TLS cert**:
  - 自签 CA: `pki/ca/ca.crt` (deploy 时生成, 已入库的是 dev CA)
  - Server cert: `pki/server/server.crt` (CN=broker.52trz.com, SAN: DNS=broker.52trz.com, localhost + IP=公网IP)
  - 不要用 Cloudflare Origin CA 替代 — broker mTLS 需要 client cert verify, 跟 CF 终止 TLS 不冲突
- **Cloudflare Tunnel** (推荐):
  - `cloudflared` 装在 broker server, 配 `config.yml`:
    ```yaml
    tunnel: <tunnel-id>
    credentials-file: /etc/cloudflared/<tunnel-id>.json
    ingress:
      - hostname: broker.52trz.com
        service: https://127.0.0.1:8443
        originRequest:
          noTLSVerify: true
      - service: http_status:404
    ```
  - DNS: `cloudflared tunnel route dns <tunnel-id> broker.52trz.com`

## 5. SOPS / age / 凭据

- `/opt/secret-broker/age/key.txt` — **age 私钥, 600 权限, 绝不入 git**
- `/opt/secret-broker/.sops.yaml` — age pub key 列表
- `/opt/secret-broker/secrets/broker.yaml` — SOPS 加密
- `/opt/secret-broker/secrets/common.env` — SOPS 加密 (实际 PAT/token 都在这里)
- 加新 secret:
  ```bash
  cd /opt/secret-broker
  export SOPS_AGE_KEY_FILE=$PWD/age/key.txt
  sops secrets/common.env
  # vim 改 + 保存 (自动 encrypt)
  sudo systemctl restart secret-broker
  ```

## 6. systemd 状态

```bash
systemctl status secret-broker           # 运行状态
journalctl -u secret-broker -n 50       # 最近 50 行日志
systemctl restart secret-broker         # 重启
systemctl stop secret-broker            # 停
```

监听:
```bash
ss -tlnp | grep 8443
```

## 7. 审计 / 监控

- `/opt/secret-broker/audit/audit-YYYY-MM-DD.jsonl` — append-only 审计 (rotate by date)
- `/opt/secret-broker/audit/broker-stdout.log` + `broker-stderr.log` — runtime stdout/stderr
- Grafana dashboard: `deploy/grafana/dashboards/broker-overview.json` (导入到 Grafana)
- Prometheus scrape: `deploy/grafana/prometheus.yml` (用 systemd-exporter + node-exporter)

## 8. 备份 / 灾备

- **必须备份**: `age/key.txt` (丢了就解不了 SOPS 密文) + `pki/ca/ca.key` + `pki/server/server.key` + `pki/clients/*.key`
- 备份方式: `ecs-snapshot-policy.sh` (阿里云) / `tar czf` 到 NAS / Rclone 到 OSS
- 验证: `sops --decrypt secrets/broker.yaml` 能解密 = age key + sops.yaml 一致

## 9. 安全检查清单

- [ ] age/key.txt 权限 600, owner=root
- [ ] pki/**/*.key 权限 600
- [ ] secrets/*.yaml 是 SOPS 密文, 不是明文
- [ ] systemd unit 有 `NoNewPrivileges=true` + `PrivateTmp=true`
- [ ] firewall: 只开 8443/tcp (或 443/tcp 经 CF Tunnel), 其他端口 drop
- [ ] fail2ban 监控 secret-broker.service journal
- [ ] .broker/config.json 客户端配置 600 权限
- [ ] cloudflared service 配 noTLSVerify: true 因为是自签 CA
- [ ] `systemctl show secret-broker` 确认 Restart=always

## 10. 故障排查

| 症状 | 排查 |
|------|------|
| `systemctl status secret-broker` 显示 failed | `journalctl -u secret-broker -n 100 --no-pager` |
| `/health` 返回 502/503 | 端口冲突: `ss -tlnp \| grep 8443` ; 证书过期: `openssl x509 -in pki/server/server.crt -noout -dates` |
| 客户端 cert 报 "unknown cert" | 比对 `pki/clients/<CN>.crt` fingerprint 跟 `secrets/broker.yaml` 里的 `cert_fingerprint_sha256` |
| Cloudflare Tunnel 502 | `cloudflared tunnel info <id>` 看 connection status; `originRequest.noTLSVerify: true` 必须有 |
| `sops --decrypt` 报 "Failed to get the data key" | age key 不匹配, 重新从备份 cp `age/key.txt` |
| Windows curl 报 `0x80092002` | Schannel 不认 PEM, 用 `python scripts/dev/run-curl.py` 替代 |
