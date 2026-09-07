# Project Status

> **V4.1.1 — security/UX patch** (public `/health` fingerprint removed; dashboard admin tabs no longer wait for a refresh). Built on V4.1.0 GA (`v4.1.0`, 2026-09-01).

## Current state

| Stage | Status |
|-------|--------|
| V4.1.0 GA | ✅ Shipped |
| V4.1 plan tasks (P1 10 + P2 6 + P3 6) | ✅ 22 / 22 |
| v3.8 client compatibility | ✅ Maintained |
| `npm run test:verify-all` | ✅ 647 / 0 (broker 619 + Python SDK 28) |
| CI workflows (`.github/workflows/`) | ✅ 2 (ci-v4.yml + test-sdks.yml) |
| `v4.1.0` tag | ✅ Annotated + pushed (ref `refs/tags/v4.1.0`, deref `673d8a1` — includes all post-GA fixes: Go SDK build fix + Python idn-email + dev tools + DEPLOY-52TRZ) |
| GitHub Release | ✅ Live (tyj1987/broker master + tag, 2026-09-01 12:48) |
| Cloud marketplace images | ⏳ P1 in [ROADMAP-post-1.0.md](ROADMAP-post-1.0.md) |
| SOC 2 Type 1 | ⏳ P1 in [ROADMAP-post-1.0.md](ROADMAP-post-1.0.md) |

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
