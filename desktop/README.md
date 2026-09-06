# broker-desktop — Tauri native client

> **Status**: Phase 1 scaffold (2026-09-06)
> **Spec**: [docs/DESIGN-TAURI-DESKTOP.md](../docs/DESIGN-TAURI-DESKTOP.md)
> **ROADMAP**: P2 #6 (target 2026-12-15 V0.1.0 alpha, 2027-Q1 V1.0.0 GA)

---

## What

A native cross-platform desktop app for managing your local + remote
Secret Broker instances. Built on Tauri 2.x (Rust + WebView + Solid.js).

**Why not just the browser dashboard?**
- Browser requires mTLS cert import + per-tab config; not suitable for
  full-time ops
- Native notifications for alerts (WebSocket pushed)
- System tray icon with broker health
- Auto-update via Tauri updater
- One-click mTLS device enrollment (CSR + QR code)
- Embedded CLI escape hatch

## Stack

- **App shell**: Tauri 2.x
- **Frontend**: Solid.js + TypeScript + TailwindCSS
- **Backend**: Rust (tokio + rustls + reqwest + tokio-tungstenite)
- **mTLS**: rustls + rcgen + keyring-rs (OS keychain)
- **WebSocket**: tokio-tungstenite
- **Auto-update**: tauri-plugin-updater + ed25519 signature

## Layout

```
desktop/
├── Cargo.toml              # workspace root
├── package.json            # frontend deps
├── tsconfig.json
├── vite.config.ts
├── index.html
├── src/                    # Solid.js frontend
│   └── index.tsx
├── src-tauri/              # Rust backend
│   ├── Cargo.toml
│   ├── tauri.conf.json     # cross-platform config
│   ├── build.rs
│   └── src/
│       ├── main.rs         # binary entry
│       └── lib.rs          # shared lib (mobile-friendly)
└── README.md               # this file
```

## Prerequisites

- **Rust 1.74+** (`rustup install stable`)
- **Node.js 20+** (`nvm install 20`)
- **Platform deps**:
  - **Linux**: `sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev build-essential`
  - **macOS**: Xcode Command Line Tools (`xcode-select --install`)
  - **Windows**: Microsoft C++ Build Tools + WebView2 (Win 11 has it built-in)

## Dev

```bash
cd desktop
npm install
npx tauri dev
# First run takes 3-5 min to compile Rust deps
# After that: hot-reload for both Solid.js (Vite) + Rust (cargo watch)
```

## Build

```bash
cd desktop
npx tauri build
# Output:
#   src-tauri/target/release/bundle/
#     deb/secret-broker-desktop_0.1.0-alpha_amd64.deb
#     appimage/secret-broker-desktop_0.1.0-alpha_amd64.AppImage
#     rpm/secret-broker-desktop_0.1.0-alpha-1.x86_64.rpm
#     dmg/Secret Broker_0.1.0-alpha_aarch64.dmg
#     msi/Secret Broker_0.1.0-alpha_x64_en-US.msi
#     exe/secret-broker-desktop_0.1.0-alpha_x64-setup.exe
```

## Distribution (Phase 5)

- **Auto-update manifest**: `https://broker.52trz.com/desktop/updates/{{target}}/{{arch}}/{{current_version}}`
- **macOS**: Sparkle 2 (DSA/RSA signed deltas)
- **Windows**: Squirrel.Windows + EV code signing cert
- **Linux**: Tauri updater + zsync (AppImage) + apt PPA + yum repo

### Build-time config (`.env`)

`tauri.conf.json` uses `${VAR}` substitution for release-time secrets
(updater pubkey, Windows cert thumbprint, macOS signing identity, etc.).
Copy `.env.example` to `.env` and fill in the vars you need:

```bash
cp .env.example .env
# Edit .env — leave Phase 5 vars blank for dev / V0.1.0 alpha builds
npx tauri build
```

Phase 1-4 (dev / V0.1.0 alpha): leave auto-update + signing vars blank.
The build will succeed but unsigned, with no auto-update channel.
Phase 5 (V1.0.0 GA): fill in `TAURI_UPDATER_PUBKEY`,
`WINDOWS_CERTIFICATE_THUMBPRINT`, `MACOS_SIGNING_IDENTITY`,
`MACOS_TEAM_ID`, `LINUX_GPG_FINGERPRINT` for signed + auto-updateable
artifacts.

## Phase roadmap (see `docs/DESIGN-TAURI-DESKTOP.md` §6 for full)

| Phase | What | When | Status |
|-------|------|------|--------|
| 1 | Spec + scaffold | 2026-09-06 | ✅ This PR |
| 2 | mTLS client | +4 weeks | ⏳ |
| 3 | REST + WebSocket | +4 weeks | ⏳ |
| 4 | Tray + notifications | +2 weeks | ⏳ |
| 5 | Auto-update + signing | +4 weeks | ⏳ |
| 6 | Polish + release | +2 weeks | ⏳ |
| **V0.1.0 alpha** | Phases 1-4 | **2026-12-15** | ⏳ |
| **V1.0.0 GA** | Phases 1-6 | 2027-Q1 | ⏳ |

## Open questions (for user)

See `docs/DESIGN-TAURI-DESKTOP.md` §8:
1. Open source strategy (MIT vs closed-source)
2. Distribution channel (Tauri updater first, then Snap/winget?)
3. Mobile: keep separate (Swift/Kotlin) or re-evaluate Tauri mobile
4. CLI escape hatch: sidecar binary or Rust port
5. Multi-tenant vs single-tenant first

## Refs

- [Tauri 2.x docs](https://tauri.app/v2/)
- [Solid.js docs](https://www.solidjs.com/)
- [docs/DESIGN-TAURI-DESKTOP.md](../docs/DESIGN-TAURI-DESKTOP.md) (full spec)
- [ROADMAP-post-1.0.md §6](../ROADMAP-post-1.0.md#6-tauri-desktop-client-w37-w42)
