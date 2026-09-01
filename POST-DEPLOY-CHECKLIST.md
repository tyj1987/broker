# POST-DEPLOY-CHECKLIST.md — V4.1.0 升级后 11 步验证

> 在 52trz.com 跑完 `migrate-v3-to-v4.sh` 之后, 跑这 11 步确认 V4 真的起来了.
> 每步: 期望值 / 怎么测 / 失败怎么修.

---

## Step 1: /health 返回 V4.1.0

```bash
curl -sk https://broker.52trz.com:8443/health
```

期望:
```json
{"status":"ok","version":"4.1.0","sops_loaded":true,"services":[],"uptime_seconds":<low>}
```

- `version: "4.1.0"` ✓ (不是 3.8.0)
- `uptime_seconds` 应该 < 300 (刚 restart)
- `sops_loaded: true` ✓

**失败**: 看到 3.8.0 → migrate 失败, 检查 `journalctl -u secret-broker -n 100`.

---

## Step 2: V3 client cert 仍能 mTLS 验签

```bash
# 拿 V3 era 的 client cert + key
scp user@52trz.com:/opt/secret-broker-v3-backup-*/pki/clients/<name>.crt /tmp/v3.crt
scp user@52trz.com:/opt/secret-broker-v3-backup-*/pki/clients/<name>.key /tmp/v3.key
scp user@52trz.com:/opt/secret-broker-v3-backup-*/pki/ca/ca.crt /tmp/v3-ca.crt

curl -sk --cert /tmp/v3.crt --key /tmp/v3.key --cacert /tmp/v3-ca.crt \
  https://broker.52trz.com:8443/api/v1/me
```

期望: 200 + JSON 包含 `"name":"<client-name>"`

**失败**: 401 / cert_unknown → 备份的 PKI 跟新 broker.yaml 不匹配, 跑 rollback 然后排查.

---

## Step 3: V3 secrets 能 resolve

```bash
curl -sk --cert /tmp/v3.crt --key /tmp/v3.key --cacert /tmp/v3-ca.crt \
  -X POST -H "Content-Type: application/json" -d '{"name":"<V3-secret-name>"}' \
  https://broker.52trz.com:8443/api/v1/secrets/resolve
```

期望: 200 + JSON 包含明文 value (或 encrypt-at-rest pointer)

**失败**: 404 "Secret not loaded" → V3 common.env 没 migrate 成功, 检查 `secrets/secrets-detail.json` 是否存在 + `journalctl` 里 `Migrated N secrets`.

---

## Step 4: V3 services 仍列出

```bash
curl -sk --cert /tmp/v3.crt --key /tmp/v3.key --cacert /tmp/v3-ca.crt \
  https://broker.52trz.com:8443/api/v1/services
```

期望: 200 + array 含 V3 时配置的所有 service (e.g. github, openai 等)

**失败**: 空 array → broker.yaml 没解析 V3 services 段, 跑 `sops --decrypt secrets/broker.yaml | less` 验证.

---

## Step 5: dashboard 加载 (HTML 静态)

```bash
curl -sk -o /dev/null -w "GET / -> %{http_code} (%{content_type})\n" \
  https://broker.52trz.com:8443/
```

期望: 200 + `text/html`

**失败**: 404 → V4 broker 期望有 dashboard/ 目录, 检查 `broker/dashboard/` 是否在 git pull 后还在.

---

## Step 6: audit log 写入新格式

```bash
ssh user@52trz.com "tail -3 /opt/secret-broker/audit/audit-$(date +%Y-%m-%d).jsonl"
```

期望: 至少 1 行新 audit entry (来自 step 2/3/4 的请求), JSON 格式含 `timestamp`, `client_name`, `action`, `status`, `latency_ms`.

**失败**: 0 lines / 文件不存在 → audit dir permission 或 disk full, 查 `journalctl`.

---

## Step 7: /health 含 v4 新字段 (e.g. workload_identity 列表)

```bash
curl -sk https://broker.52trz.com:8443/health | python -m json.tool
```

期望: 字段含 `workload_identity_providers` (空 array OK, V3 没用) 或 V4.1 新加的 `build_info`.

**失败**: 仍是 V3 字段集 → 启动的是旧 server.js, journalctl 看是不是 systemd 还在跑 v3 binary.

---

## Step 8: smoke from your laptop (mTLS)

从 52trz.com 外的 client:

```bash
python sdk/python/examples/resolve.py  # 装好 wheel 之后
```

期望: 输出 GITHUB_PAT 明文 (或 SDK 装的 service)

**失败**: TLS handshake fail → 服务器 cert 是 V3 旧 cert 没换, 跑 `ls -la /opt/secret-broker/pki/server/`.

---

## Step 9: V4 新端点 (admin)

```bash
# V3 没这些端点, V4 加的
curl -sk --cert /tmp/v3.crt --key /tmp/v3.key --cacert /tmp/v3-ca.crt \
  https://broker.52trz.com:8443/api/v1/admin/types
# 期望: 200 + array of 59 type schemas
```

**失败**: 404 → V4 routes 没 register, 查 `journalctl -u secret-broker` 看 startup 有没有 `Registered route: /admin/types`.

---

## Step 10: auto-rotate cron (optional)

```bash
ssh user@52trz.com "crontab -l | grep -E 'secret-broker|auto-rotate'"
```

期望: 看到类似 `0 2 * * * /opt/secret-broker/broker/bin/auto-rotate-cron.sh` (V4 装时不自动加, manual setup).

**失败**: 空 → V4 不强制 auto-rotate cron, 但建议加. 详见 `DEPLOY-52TRZ.md` §5.

---

## Step 11: 监控 (optional but recommended)

```bash
# Grafana dashboard 导入 deploy/grafana/dashboard.json
# 14 panels 覆盖: request rate / latency / error rate / cert expire / audit / workload / etc.
```

期望: 9-10/14 panels 有数据 (audit / 流量), 3-4/14 是 0 (workload identity / sms provider 还没用)

**失败**: 0/14 → Prometheus scrape 失败, 查 `curl http://broker:9090/metrics`.

---

## 全通过后的清理

```bash
# 保留 backup 7-30 天 (万一有隐藏问题)
ssh user@52trz.com "rm -rf /opt/secret-broker-v3-backup-*  # 30 天后清"

# 把 v4.1.0 release 接进 CI / changelog workflow
# 见 ROADMAP-post-1.0.md P0 item 1 (CI runs on GitHub Actions)
```

## 任一失败 → rollback

```bash
ssh user@52trz.com "sudo bash /opt/secret-broker-v3-backup-*/rollback.sh"
# 5-10s 回到 V3.8.0, 全 V3 client cert 仍工作
```

rollback 不丢任何数据 (V3 backup 是 file-level cp). 修问题再重 migrate.
