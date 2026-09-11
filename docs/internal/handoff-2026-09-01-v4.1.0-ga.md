# ⏸ Awaiting user — 2026-09-01

broker V4.1.0 GA 全自动发布已 ready, **等 user SSH 上 52trz.com 跑 upgrade**.

## Quick 1-line deploy
```powershell
scp E:\broker\scripts\broker\{preflight,migrate,upgrade}-v3-to-v4.sh user@broker.52trz.com:/tmp/ ; `
ssh user@broker.52trz.com "sudo bash /tmp/upgrade-v3-to-v4.sh --local" ; `
curl.exe -sk https://broker.52trz.com:8443/health
```
期望: `version: "4.1.0"` ✓

## Resources ready
- **GitHub Release**: https://github.com/tyj1987/broker/releases/tag/v4.1.0 (8/8 assets)
- **Full deploy guide**: `E:\broker\DEPLOY-52TRZ.md`
- **1-page cheat sheet**: `E:\broker\52TRZ-UPGRADE-1PAGE.md`
- **11-step verification**: `E:\broker\POST-DEPLOY-CHECKLIST.md`
- **Rollback if needed**: `sudo bash /opt/secret-broker-v3-backup-*/rollback.sh` (auto-created by migrate)

## 52trz.com current state
- Version: **3.8.0** (last verified 13:32 local)
- Uptime: **10.3 days** (no restart)
- Cloudflare terminates TLS (cert from Google Trust Services)
- Services: `[]` (empty, will remain empty after V4 upgrade)

## Local broker state
- Version: 4.1.0 (last running before test:verify-all freed port 8443)
- Tests: 647/0 (broker 619 + Python SDK 28)
- All dev config in `.gitignore` (broker.yaml / clients.json / secrets-detail.json)
