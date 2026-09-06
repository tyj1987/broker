# Project Status

> **V4.1.1 — Patch ready for GA** (target tag `v4.1.1`, 2026-09-06)
>
> V4.1.0 GA: ✅ shipped (tag `v4.1.0`, 2026-09-01).
> V4.1.1 patch: 🔄 22 PR in origin, 4-SDK parity done, awaiting user merge + tag + release.

## Current state

| Stage | Status |
|-------|--------|
| V4.1.0 GA | ✅ Shipped (tag `v4.1.0`, 2026-09-01) |
| V4.1.1 patch (broker) | 🔄 Branch `release/v4.1.1` PR ready — 1 critical fix (mTLS cert-as-session) + 1 startup clean (DEP0187) + version bump + audit clean |
| V4.1.1 SDK parity (all 4 SDKs) | ✅ **Code done** — single `BrokerError` + `parseBrokerError` + retry (5xx/429/connection) + auto-redact body. 4 PR ready: Python `9a0c5f7` (54 tests), Go `6052779` (33), CLI `ba6da09` (21), VSCode `f0a6dd1` (48). 166 SDK tests (was 54, +112). |
| V4.1.1 docs | ✅ `docs/SDK-REFERENCE.md` V4.1.1 parity section (`20c5e6d`) + `RELEASE-NOTES-v4.1.1.md` SDK parity section (`4222d76`) ready |
| V4.1 plan tasks (P1 10 + P2 6 + P3 6) | ✅ 22 / 22 |
| V4.1.0+ ROADMAP items (P0-P3) | 🔄 13 / 13推进 (2 done + 11 partial — see [AWAITING-USER.md V13](AWAITING-USER.md)) |
| **22 PR in origin** | 🔄 3 done-equivalent (V4.1.1 patch + 4 SDK V4.1.1 + release notes) + 19 partial — see [AWAITING-USER.md](AWAITING-USER.md) for merge order |
| v3.8 client compatibility | ✅ Maintained |
| `npm run test:verify-all` (V4.1.0) | ✅ 647 / 0 (broker 619 + Python SDK 28) |
| `npm run test:verify-all` (V4.1.1) | 🔄 **795 / 0** (broker 629 + SDK 166: Python 54 + Go 33 + Node CLI 21 + VSCode 48 + 1 SKIP) — ahead of tag |
| CI workflows (`.github/workflows/`) | ✅ 2 (ci-v4.yml + test-sdks.yml) — now covering `master` |
| `v4.1.0` tag | ✅ Annotated + pushed (ref `refs/tags/v4.1.0`, deref `673d8a1`) |
| `v4.1.1` tag | ⏳ Awaiting user merge (see [AWAITING-USER.md V13](AWAITING-USER.md)) |
| GitHub Release | ✅ V4.1.0 live (tyj1987/broker master + tag, 2026-09-01 12:48) — V4.1.1 pending user decision (8 assets ready: source tarball + zip, Python wheel + sdist, 4 Go SDK binaries) |
| Cloud marketplace images | ⏳ P1 in [ROADMAP-post-1.0.md](ROADMAP-post-1.0.md) — AWS Packer + CFN ready (`566d821`), 5-marketplace spec (AWS/Azure/GCP/Aliyun/Tencent) |
| SOC 2 Type 1 + ISO 27001 | ⏳ P1 in [ROADMAP-post-1.0.md](ROADMAP-post-1.0.md) — 93 + 65 controls mapped (`6347ae2`) |

## Where to start (if new)

1. [ARCHITECTURE.md](ARCHITECTURE.md) — one-page overview
2. [QUICKSTART.md](docs/QUICKSTART.md) — 5-minute walkthrough
3. [V4.1-COMPLETE.md](V4.1-COMPLETE.md) — what was built, per-task
4. [VERIFY.md](VERIFY.md) — 1-line verification
5. [ROADMAP-post-1.0.md](ROADMAP-post-1.0.md) — what's next

## Operational

- **Health check**: `curl -k --cert client.crt --key client.key --cacert ca.crt https://broker:8443/health`
- **Local dev**: `cd broker && npm install && npm run test:verify-all` (or `scripts/dev/start-broker.ps1` for one-command plaintext bypass)
- **Production deploy**: Helm chart `deploy/helm/broker/` or `docker compose up -d broker` or `DEPLOY-52TRZ.md` for git-pull + systemd
- **Cloud target (broker.52trz.com)**: see [DEPLOY-52TRZ.md](DEPLOY-52TRZ.md) — 3 场景 (首次 / 从零 git / 更新)
- **Incident response**: see [RUNBOOK.md](RUNBOOK.md)
- **Security issue**: see [SECURITY.md](SECURITY.md) — bug bounty up to $5000

## License

MIT — see [LICENSE](LICENSE).

---

This file is a sentinel — it documents the V4.1.0 GA state and points new
contributors to the right entry docs. Update it as the project evolves.
