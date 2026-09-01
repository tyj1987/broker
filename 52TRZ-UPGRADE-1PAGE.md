# 52trz.com V3 → V4.1.0 升级 1-Page Cheat Sheet

> 从 broker V3.8.0 升级到 V4.1.0, 全部命令从本地 Windows PowerShell 跑 (除了 ssh 部分).
> 假设 user 已有 SSH 到 broker.52trz.com 的能力.

---

## 0. 前置 (一次性, 5 min)

```powershell
# 本地 (Windows) 检查 repo 同步
cd E:\broker
git fetch origin --tags
git log -1 --oneline v4.1.0   # 期望看到 a626cb8 附近的 commit

# 验 52trz.com 当前版本
curl.exe -sk https://broker.52trz.com:8443/health
# 期望: {"version":"3.8.0",...,"uptime_seconds":<10.3 days>}
```

---

## 1. 准备: 把 4 个脚本 scp 到 server (30s)

```powershell
scp E:\broker\scripts\broker\preflight-v3-to-v4.sh `
    E:\broker\scripts\broker\migrate-v3-to-v4.sh `
    E:\broker\scripts\broker\upgrade-v3-to-v4.sh `
    user@broker.52trz.com:/tmp/

ssh user@broker.52trz.com "ls -la /tmp/*-v3-to-v4.sh"
# 期望: 3 个文件 600+ bytes each
```

---

## 2. Preflight (read-only, 10s, 不改任何文件)

```bash
ssh user@broker.52trz.com "sudo bash /tmp/preflight-v3-to-v4.sh"
```

期望最后一行:
```
[8/8] 51trz.com PKI complete
============================================
  preflight summary: 7 pass, 0 warn, 0 fail
============================================
  ✅ All checks passed. Ready to upgrade.
  Run: sudo bash /tmp/migrate-v3-to-v4.sh
```

**任何 FAIL 立即停, 不要跑 migrate.** 失败 fix → 重 preflight.

---

## 3. Migrate (改文件, 1-2 min, auto-backup + auto-rollback)

```bash
ssh user@broker.52trz.com "sudo bash /tmp/upgrade-v3-to-v4.sh --local"
```

期望最后一行:
```
============================================
  ✅ V3 -> V4 upgrade complete
============================================
  before: V3.x (commit <old>)
  after:  V4.x (commit a626cb8)
  backup: /opt/secret-broker-v3-backup-<timestamp>
  rollback (if anything broken): sudo bash <backup>/rollback.sh
```

**任何错误 (exit 2)** → 自动 rollback, 全 V3 状态恢复, 查 `journalctl -u secret-broker -n 100 --no-pager` 找 root cause.

---

## 4. 验证 (从本地 Windows, 30s)

```powershell
# 1. /health 返 V4.1.0
curl.exe -sk https://broker.52trz.com:8443/health
# 期望: {"version":"4.1.0",...,"uptime_seconds":<100}

# 2. (optional) mTLS smoke
# 拿 V3 backup 的 client cert, 跟 V4 broker 验
scp user@broker.52trz.com:/opt/secret-broker-v3-backup-*/pki/clients/<name>.crt /tmp/v3.crt
scp user@broker.52trz.com:/opt/secret-broker-v3-backup-*/pki/clients/<name>.key /tmp/v3.key
scp user@broker.52trz.com:/opt/secret-broker-v3-backup-*/pki/ca/ca.crt /tmp/v3-ca.crt

python E:\broker\sdk\python\examples\resolve.py
# 或手动:
curl.exe -sk --cert C:\tmp\v3.crt --key C:\tmp\v3.key --cacert C:\tmp\v3-ca.crt `
  https://broker.52trz.com:8443/api/v1/me
# 期望: 200 + JSON {"name":"<client>",...}
```

---

## 5. 11 步完整验证

跑 `POST-DEPLOY-CHECKLIST.md` 里 11 步 (5-10 min). 任何一步 FAIL 立即看 checklist 里 "失败怎么修" 段.

---

## 6. (optional) 清理 V3 backup

```bash
# 30 天后确认 V4 稳了, 再删 V3 backup (省 ~50MB)
ssh user@broker.52trz.com "sudo rm -rf /opt/secret-broker-v3-backup-*"
```

---

## 紧急 rollback (任何时候)

```bash
ssh user@broker.52trz.com "sudo bash /opt/secret-broker-v3-backup-*/rollback.sh"
# 5-10s 回到 V3.8.0, V3 client cert 仍工作
```

---

## 1 行 cheat (全 6 步压成 1 行, 拷贝就能跑)

```powershell
scp E:\broker\scripts\broker\{preflight,migrate,upgrade}-v3-to-v4.sh user@broker.52trz.com:/tmp/ ; `
ssh user@broker.52trz.com "sudo bash /tmp/preflight-v3-to-v4.sh && sudo bash /tmp/upgrade-v3-to-v4.sh --local" ; `
curl.exe -sk https://broker.52trz.com:8443/health
```

如果最后 curl 看到 `version 4.1.0` = 成功. 看到 `3.8.0` = rollback 自动, 查 journal.
