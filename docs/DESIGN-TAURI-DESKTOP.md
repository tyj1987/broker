# Tauri Desktop Client — Design Spec

> **Status**: P2 #6 partial (design + scaffold, awaiting Rust toolchain + user pick)
> **ROADMAP**: target 2026-12-15
> **Source**: [ROADMAP-post-1.0.md §6](../ROADMAP-post-1.0.md#6-tauri-desktop-client-w37-w42)

---

## 1. Goals

A native cross-platform desktop app (`broker-desktop`) for managing a local
Secret Broker instance + a remote broker (e.g. `broker.52trz.com`) without
going through the browser dashboard.

**Why not just the browser dashboard?**

- Browser requires mTLS cert import + per-tab config; not suitable for
  full-time ops
- Native notifications for alerts (WebSocket pushed)
- System tray icon with broker health (✓/✗/⏳)
- Auto-update via Tauri updater (no manual download)
- Built-in mTLS client cert management (one-click enroll/revoke)
- CLI escape hatch (run `secret-broker` from app menu → opens embedded terminal)

## 2. Non-goals

- **Not a replacement for the broker server** — Tauri is a client UI
- **Not a CLI replacement** — `secret-broker` CLI stays standalone; Tauri
  just wraps it
- **Not a SaaS dashboard** — broker is single-tenant per user; no shared state
- **Not a Kubernetes operator** — broker.52trz.com deploys via systemd / Docker,
  not Tauri

## 3. Stack

| Layer | Tech | Version | Rationale |
|-------|------|---------|-----------|
| App shell | Tauri | 2.x stable | Rust + webview hybrid, smaller than Electron |
| Frontend | Solid.js + TypeScript | 0.30+ | Lightweight (no VDOM diff tax), better than React for desktop |
| Styling | TailwindCSS | 3.x | Matches broker dashboard design tokens |
| Backend (Rust) | tokio | 1.40+ | Async runtime; mTLS via tokio-rustls |
| mTLS | rustls | 0.23+ | Pure-Rust TLS, no OpenSSL dep |
| PKI | rcgen | 0.13+ | Generate client certs locally (CSR for broker admin to sign) |
| WebSocket | tokio-tungstenite | 0.24+ | Matches broker WS protocol |
| HTTP | reqwest | 0.12+ | Built-in mTLS support |
| Tauri plugins | @tauri-apps/api | 2.x | system tray, notifications, updater, fs, dialog, shell, window-state |
| Build | cargo + tauri-cli | 2.x | Standard Tauri toolchain |
| Code signing | Apple's Developer ID + Microsoft EV cert + Linux GPG | (per platform) | For auto-update trust |

## 4. Architecture

```
┌──────────────────────────────────────────────────────────┐
│  Tauri 2.x app (broker-desktop)                           │
│  ┌────────────────────┐  ┌──────────────────────────────┐ │
│  │  Frontend (Solid)  │  │  Rust backend (src-tauri)     │ │
│  │  - Dashboard       │←→│  - mTLS client cert manager  │ │
│  │  - Service list    │  │  - WebSocket subscriber      │ │
│  │  - Health monitor  │  │  - System tray (status)      │ │
│  │  - Alert history   │  │  - Auto-updater (Tauri)      │ │
│  │  - mTLS enroll UI  │  │  - CLI proxy (open terminal) │ │
│  │  - TOTP setup      │  │  - Native notifications      │ │
│  └────────────────────┘  └──────────────────────────────┘ │
│              ↑                                            │
│              │ Tauri IPC (typed commands)                 │
│              ↓                                            │
│  ┌─────────────────────────────────────────────────────┐ │
│  │  Local state (encrypted sqlite via sqlx)            │ │
│  │  - Cached secrets (decrypted on demand, never logged)│ │
│  │  - mTLS cert fingerprints (not the keys themselves)  │ │
│  │  - WebSocket subscription list                       │ │
│  └─────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
              ↑                ↑                ↑
              │ mTLS           │ mTLS WS        │ mTLS REST
              │ cert-as-       │ (push events)  │
              │ session        │                │
              ↓                ↓                ↓
┌──────────────────────────────────────────────────────────┐
│  Broker server (broker.52trz.com or local)                │
│  - mTLS HTTPS :8443 (REST + cert-as-session login)        │
│  - WebSocket :8443 (audit, healthcheck, alerts, ...)      │
│  - 6 auth factors (mTLS / Pass / TOTP / WebAuthn / SMS / Recovery) │
└──────────────────────────────────────────────────────────┘
```

## 5. Key features (mapped to ROADMAP P2 #6)

### 5.1 Cross-platform (Linux / macOS / Windows)

| Platform | Webview | Bundle format | Auto-update |
|----------|---------|---------------|-------------|
| Linux x86_64 | WebKitGTK 4.1 | AppImage + deb + rpm | Tauri updater + zsync |
| Linux arm64 | WebKitGTK 4.1 | AppImage + deb + rpm | Tauri updater + zsync |
| macOS x86_64 | WKWebView | .app + .dmg | Sparkle + Tauri updater |
| macOS arm64 | WKWebView | .app + .dmg | Sparkle + Tauri updater |
| Windows x86_64 | WebView2 | .msi + .exe | Tauri updater + Squirrel.Windows |

Build matrix: GitHub Actions matrix workflow
- 4 OS × 2 arch (where applicable) × 3 package format
- For V4.1.0 → 9+ artifacts per release
- 1 release archive: `broker-desktop-v0.1.0-{linux-x64,macos-arm64,windows-x64,...}.{AppImage,dmg,msi}`

### 5.2 System tray icon

- Tray shows broker connection status:
  - 🟢 green check: connected + last healthcheck < 60s
  - 🟡 yellow hourglass: connecting or healthcheck in flight
  - 🔴 red X: disconnected or last healthcheck > 5 min
- Click menu:
  - Open dashboard (focus app)
  - Run `secret-broker health` (pop output)
  - Switch broker endpoint (multi-server support)
  - Quit
- Right-click context menu (Linux/macOS):
  - View audit log (last 100 events)
  - Trigger WebSocket re-subscribe
  - Open logs directory

### 5.3 Native notifications

Subscribe to broker WebSocket events:
- `audit` (severity ≥ medium) → desktop notification
- `alert` (any severity) → desktop notification + log
- `healthcheck` (status changed) → desktop notification (no sound)
- `mfa_enrolled` (new client) → desktop notification
- `secret_rotated` (your watched secrets only) → desktop notification

Notification action: click → open dashboard, focus the related panel.

### 5.4 Built-in mTLS client cert management

**Enroll flow** (one-click):
1. User clicks "Enroll this device" in dashboard
2. Tauri Rust backend generates a 2048-bit RSA keypair (rcgen, in memory)
3. Generates CSR with `CN = tyj1987-broker-laptop-{short-uuid}`,
   `O = tyj1987`, `OU = laptop`
4. CSR displayed as PEM + QR code
5. User shows QR to broker admin (via phone, Slack, email, etc.)
6. Admin signs CSR with broker CA → returns signed cert
7. User pastes signed cert into app
8. App verifies chain against broker CA cert (imported once)
9. App stores keypair + cert in OS keychain (Keychain / Credential Manager / libsecret)
10. From then on: cert auto-loaded, no manual path config

**Revoke flow**:
1. User clicks "Revoke this device" in dashboard
2. Tauri Rust backend calls `POST /api/v1/pki/revoke` with cert fingerprint
3. Deletes cert + key from keychain
4. Returns to "no device enrolled" state

### 5.5 Auto-update via Tauri updater

- Tauri 2.x `tauri-plugin-updater` with custom update server
- Update channel: `stable` (default) / `beta` (opt-in for testing)
- Update manifest: `https://broker.52trz.com/desktop/updates/{{target}}/{{arch}}/{{current_version}}`
- Native platform updaters layered:
  - macOS: Sparkle 2 (DSA/RSA signed deltas)
  - Windows: Squirrel.Windows (full + delta)
  - Linux: AppImage zsync + deb/rpm via apt PPA / yum repo
- Signature verification: ed25519 public key bundled in app, signed by maintainer
- Auto-download in background, prompt on completion
- Rollback: keep 2 previous versions, allow downgrade from settings

### 5.6 Embedded CLI escape hatch

- Menu item "Open secret-broker shell" → opens embedded terminal (xterm.js)
  backed by real `secret-broker` binary launched via `tauri-plugin-shell`
- Cwd: `~/.broker/`
- Env: `BROKER_CONFIG=auto` (uses app's loaded config)
- Working `secret-broker --help`, `health`, `list`, `proxy`, etc. all work
- No need to install `secret-broker` CLI separately

### 5.7 Multi-broker support

- Settings → Brokers → add new broker endpoint
- Each broker has its own: name, endpoint, mTLS cert, CA cert, TOTP secret (if any)
- Switch active broker from tray menu or dashboard
- WebSocket subscriptions scoped to active broker
- Audit log per broker (coloured by broker)

## 6. Phased rollout (ROADMAP target 2026-12-15)

### Phase 1: Spec + scaffold (this PR)
- [x] `docs/DESIGN-TAURI-DESKTOP.md` (this file)
- [x] `desktop/Cargo.toml` (Tauri 2.x workspace)
- [x] `desktop/tauri.conf.json` (cross-platform config)
- [x] `desktop/src/main.rs` (entry stub)
- [x] `desktop/README.md` (dev / build / dist)
- **Deliverable**: `cargo tauri dev` shows a "Hello broker" window on each platform

### Phase 2: mTLS client (4 weeks)
- `desktop/src-tauri/src/mtls.rs` — rustls + rcgen keypair generation
- `desktop/src-tauri/src/keychain.rs` — keyring-rs for OS keychain
- `desktop/src-tauri/src/commands.rs` — Tauri commands:
  - `enroll_device(name: String) -> CSR`
  - `import_signed_cert(cert_pem: String)`
  - `revoke_device(fingerprint: String)`
- `desktop/src/components/Enroll.tsx` — CSR display + QR code
- **Deliverable**: full enroll flow works end-to-end against local broker

### Phase 3: REST + WebSocket client (4 weeks)
- `desktop/src-tauri/src/broker_client.rs` — reqwest + tokio-tungstenite
- Connection pool: 1 mTLS connection per active broker
- Auto-reconnect with exponential backoff (1s, 2s, 4s, 8s, max 30s)
- WebSocket subscription manager (auto-resubscribe on reconnect)
- **Deliverable**: dashboard shows live services, secrets, audit log

### Phase 4: System tray + notifications (2 weeks)
- `tauri-plugin-system-tray` integration
- `tauri-plugin-notification` integration
- Tray icon state machine (green/yellow/red)
- Notification preferences (which event types to notify)
- **Deliverable**: tray + notifications work on Linux/macOS/Windows

### Phase 5: Auto-update + signing (4 weeks)
- `tauri-plugin-updater` integration
- `desktop/.tauri/updater.pub` (ed25519 public key, committed)
- Maintainer private key (`~/.tauri/updater.key`, gitignored)
- Sparkle setup (macOS): generate DSA keys, sign each build
- Squirrel.Windows setup (Windows): code signing cert (EV cert recommended)
- AppImage / deb / rpm: Tauri updater
- **Deliverable**: `cargo tauri build` produces signed, auto-updateable artifacts

### Phase 6: Polish + release (2 weeks)
- README + screenshots
- User docs: `docs/TAURI-DESKTOP.md`
- GitHub Actions matrix workflow: 4 OS × 2 arch
- 9+ artifacts per release
- `RELEASE-NOTES-tauri-0.1.0.md` for V0.1.0 alpha
- `RELEASE-NOTES-tauri-1.0.0.md` for V1.0.0 GA
- **Deliverable**: V0.1.0 alpha on GitHub Releases (target 2026-12-15)

## 7. Security considerations

| Concern | Mitigation |
|---------|------------|
| Private key leak | `keyring-rs` (OS keychain, encrypted at rest by OS) + never write to disk unencrypted |
| Code signing | EV cert (Windows) + Apple Developer ID (macOS) + GPG (Linux RPM) |
| Auto-update trust | ed25519 signature, public key in app, maintainer key offline |
| WebSocket injection | Same mTLS auth as REST; reject if cert mismatch |
| Tray spoofing | Tray icon = local healthcheck result, not from broker |
| IPC injection | Tauri 2.x typed commands + scope-limited capabilities |
| Local storage | sqlite with `sqlcipher` (encrypted at rest via OS keychain-derived key) |
| Log leakage | structlog + redaction filter (broker's `lib/redact.js` rules ported) |
| Clipboard leak | Don't auto-copy secrets to clipboard; if user does, auto-clear after 30s |

## 8. Open questions (for user 决断)

1. **Open source strategy**: Tauri scaffold under MIT (same as broker), or
   closed-source (commercial dual-license)? Recommendation: MIT to keep
   ecosystem consistent.
2. **Distribution channel**: Tauri updater (own server) vs Snapcraft /
   Microsoft Store / Mac App Store? Recommendation: Tauri updater first
   (control), then Snap Store + winget-pkgs (broader reach).
3. **Mobile**: Tauri 2.x supports iOS / Android (alpha). ROADMAP P3 #11 has
   separate Swift/Kotlin projects; should we re-evaluate Tauri mobile?
   Recommendation: keep separate (Tauri mobile too alpha).
4. **CLI escape hatch**: embed real `secret-broker` binary (Tauri sidecar)
   or wrap CLI in Rust? Recommendation: sidecar (preserves CLI stdlib-only
   purity, no Rust port of CLI logic).
5. **Multi-broker**: single-tenant (1 broker per user) or multi-tenant
   (broker-fleet management, e.g. dev + prod + staging)? Recommendation:
   single-tenant first (most users), multi-tenant post-V1.0.

## 9. Estimated effort

| Phase | Weeks | LOC (estimate) | Risk |
|-------|-------|----------------|------|
| 1: Spec + scaffold | 1 | ~200 (Cargo.toml + main.rs + config) | Low |
| 2: mTLS client | 4 | ~1,500 (keypair + CSR + keychain) | Medium |
| 3: REST + WebSocket | 4 | ~2,000 (client + reconnect + state) | Medium |
| 4: Tray + notifications | 2 | ~600 (state machine + filtering) | Low |
| 5: Auto-update + signing | 4 | ~400 + 1-day cert purchase (Windows EV) | High (cert) |
| 6: Polish + release | 2 | ~500 (CI matrix + docs) | Low |
| **Total** | **17 weeks** | **~5,200** | |

**Calendar**: 17 weeks from Phase 1 start (2026-09-06) → ~2027-01-10.
ROADMAP target 2026-12-15 is **8-week Phase 1-4 scope** (V0.1.0 alpha, no
auto-update). V1.0.0 GA with auto-update: 2027-Q1.

## 10. Success criteria

- [ ] `cargo tauri dev` runs on Linux / macOS / Windows
- [ ] Single-broker mTLS enrollment works end-to-end
- [ ] Dashboard shows live services, secrets, audit log
- [ ] WebSocket reconnect on broker restart (< 30s)
- [ ] Tray icon shows real-time broker health
- [ ] Native notifications for alerts
- [ ] Auto-update signed (V1.0.0 only)
- [ ] `cargo tauri build` produces signed artifacts
- [ ] All 9+ artifacts published to GitHub Release
- [ ] User docs + screenshots in `docs/TAURI-DESKTOP.md`

## 11. Refs

- [ROADMAP-post-1.0.md §6](../ROADMAP-post-1.0.md#6-tauri-desktop-client-w37-w42)
- [Tauri 2.x docs](https://tauri.app/v2/)
- [Solid.js docs](https://www.solidjs.com/)
- [rustls docs](https://docs.rs/rustls/)
- [keyring-rs](https://github.com/hwchen/keyring-rs)
- [broker dashboard V4.1.0](https://github.com/tyj1987/broker/tree/master/broker/dashboard) (frontend design ref)
- [ARCHITECTURE.md](../ARCHITECTURE.md) (broker 整体架构)
