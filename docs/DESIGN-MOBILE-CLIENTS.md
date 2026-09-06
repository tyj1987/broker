# Mobile Clients Design Spec (iOS + Android) (2026-09-06)

> **Status**: P3 #11 partial — design spec, no code yet
> **ROADMAP**: target 2027-03-31
> **Source**: [ROADMAP-post-1.0.md §11](../ROADMAP-post-1.0.md#11-mobile-clients-q1-2027)
> **Baseline**: broker V4.1.x + 4 existing SDKs (Node / Python / Go / VSCode)

---

## 1. Goals

Native iOS + Android apps for AI agents running on mobile devices
(Mavis on iPhone, Claude on Android, etc.) to securely access broker
without going through browser dashboard.

**Why not just reuse the browser dashboard?**

- Mobile users want push notifications for broker alerts
- Background access (proxy mode) when phone is locked
- Native biometric (Face ID / Touch ID / fingerprint) instead of typing
  passwords
- iOS Keychain / Android Keystore for cert storage (encrypted at rest
  by OS)
- Cellular network handling (offline queue + retry)

## 2. Non-goals

- **Not a Tauri desktop replacement** — see [docs/DESIGN-TAURI-DESKTOP.md](DESIGN-TAURI-DESKTOP.md)
- **Not a CLI replacement** — broker has `cli/secret-broker.js` for server-side; mobile is consumer UI
- **Not a broker server** — mobile is **client only**

## 3. Stack

| Layer | iOS | Android | Rationale |
|-------|-----|---------|-----------|
| Language | Swift 5.9+ | Kotlin 1.9+ | Native, mature, official |
| Min version | iOS 16+ | Android 9+ (API 28) | 90%+ market share |
| UI | SwiftUI | Jetpack Compose | Modern declarative UI |
| Async | Swift Concurrency (async/await) | Kotlin Coroutines | First-class async |
| mTLS | Network.framework (built-in) | OkHttp 4.x + Conscrypt | Native / mature |
| Cert storage | Keychain (Secure Enclave on A7+) | Android Keystore (StrongBox on Pixel 3+) | OS-encrypted, hardware-backed |
| Biometric | LocalAuthentication.framework | androidx.biometric | Face ID / Touch ID / fingerprint |
| WebSocket | URLSessionWebSocketTask | OkHttp WebSocket | Built-in / mature |
| Push | APNs (UserNotifications.framework) | FCM (Firebase Cloud Messaging) | Native / standard |
| Background | BGTaskScheduler | WorkManager | OS scheduling |
| Networking | URLSession | OkHttp | Standard |
| JSON | Codable (built-in) | Moshi or kotlinx.serialization | Standard |
| Storage | SwiftData (Core Data successor) | Room (SQLite) | Modern / standard |
| Logging | os.Logger (unified logging) | Timber | Built-in / standard |
| Testing | XCTest | JUnit + Espresso | Standard |
| Build | Xcode 15 + SwiftPM | Gradle 8 + Android Studio Hedgehog | Standard |

**No new broker dependencies**: mobile apps consume existing REST + WebSocket
APIs. No new broker server features required (V4.1.x is sufficient).

## 4. Architecture

```
┌──────────────────────────────────────────────────────────┐
│  iOS / Android app                                        │
│  ┌────────────────────┐  ┌──────────────────────────────┐ │
│  │  UI (SwiftUI / Compose) │  │  Services (singleton)         │ │
│  │  - Dashboard         │←→│  - BrokerClient (mTLS REST)   │ │
│  │  - Service list      │  │  - WebSocketClient (events)   │ │
│  │  - Health monitor    │  │  - AuthService (biometric)    │ │
│  │  - Alert history     │  │  - CertManager (Keychain/KS)  │ │
│  │  - mTLS enroll UI    │  │  - PushService (APNs/FCM)     │ │
│  │  - Settings          │  │  - BackgroundTaskService      │ │
│  └────────────────────┘  └──────────────────────────────┘ │
│              ↑                                            │
│              │ Swift/Kotlin domain types                  │
│              ↓                                            │
│  ┌─────────────────────────────────────────────────────┐ │
│  │  Local storage (encrypted at rest by OS)              │ │
│  │  - Keychain / Keystore: mTLS cert + private key      │ │
│  │  - SwiftData / Room: cached services + alerts         │ │
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

## 5. Key features (mapped to ROADMAP P3 #11)

### 5.1 iOS / Android specific

#### 5.1.1 mTLS cert management with biometric gate

- **Cert enrollment**: user scans QR code (broker admin sends via iMessage / WhatsApp)
- **Biometric gate**: Face ID / Touch ID / fingerprint required to **use** the cert (decrypt + sign requests)
- **Keychain / Keystore**: cert + private key stored encrypted by OS (Secure Enclave / StrongBox)
- **App background lock**: after 5 min in background, biometric re-required to resume

```swift
// iOS: BrokerClient.swift
class BrokerClient {
    func request(path: String, body: Data?) async throws -> Data {
        // 1. Trigger biometric (Face ID / Touch ID)
        let context = LAContext()
        guard try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                                                localizedReason: "Access Secret Broker") else {
            throw BrokerError.biometricCancelled
        }

        // 2. Load cert from Keychain
        let identity = try CertManager.loadClientIdentity()

        // 3. URLSession with mTLS
        let session = URLSession(configuration: .ephemeral,
                                  delegate: MTLSPinningDelegate(identity: identity),
                                  delegateQueue: nil)
        var req = URLRequest(url: brokerURL.appendingPathComponent(path))
        req.httpBody = body
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let (data, response) = try await session.data(for: req)
        // ... handle response
    }
}
```

#### 5.1.2 Push notifications

- iOS: APNs (UserNotifications.framework)
- Android: FCM (Firebase Cloud Messaging)
- Subscribe to broker WebSocket events:
  - `audit` (severity ≥ medium) → push notification
  - `alert` (any severity) → push notification
- Tap notification → open relevant app page

#### 5.1.3 Background access (proxy mode)

- iOS: `BGAppRefreshTask` (15-min OS scheduling) + `BGProcessingTask` (longer ops)
- Android: `WorkManager` (OS-managed, battery-aware)
- Pattern: while in background, periodically poll broker health + cache services
- On foreground: sync with broker + show diff
- Cellular-aware: only sync on Wi-Fi (or unmetered cellular) for large data

#### 5.1.4 Offline queue

- iOS: SwiftData local store for pending requests
- Android: Room local store
- When offline, requests queue locally; sync when connection restored
- Conflict resolution: last-write-wins for read-only ops; 2-person approval for mutations (matches V4.1.x)

### 5.2 Cross-platform (shared with desktop / web)

#### 5.2.1 Dashboard

- List services (GitHub, OpenAI, AWS, ...) with health indicator
- Tap service → recent activity + quick actions
- Search + filter

#### 5.2.2 Alert history

- Chronological list of broker alerts (severity + description + time)
- Tap → detail view (audit chain)
- Filter by severity / service

#### 5.2.3 mTLS enrollment UI

- Scan QR code (camera) or paste cert PEM
- Biometric confirmation (Face ID / Touch ID)
- Verify cert chain against broker CA cert
- Save to Keychain / Keystore

#### 5.2.4 Multi-broker support

- Add / switch / remove broker endpoints
- Each broker has own: name, endpoint, mTLS cert, CA cert
- Switch active broker from settings

## 6. Phased rollout (P3 #11, target 2027-03-31)

| Phase | What | When | Status |
|-------|------|------|--------|
| 11.1 | iOS scaffold (Xcode project, SwiftUI, basic dashboard) | 2026-12-15 | ⏳ |
| 11.2 | iOS mTLS + Keychain + biometric | 2027-01-15 | ⏳ |
| 11.3 | iOS push notifications + WebSocket | 2027-02-01 | ⏳ |
| 11.4 | iOS background access + offline queue | 2027-02-15 | ⏳ |
| 11.5 | iOS TestFlight beta + App Store submission | 2027-03-15 | ⏳ |
| 11.6 | Android scaffold (Gradle, Compose, basic dashboard) | 2027-01-15 | ⏳ |
| 11.7 | Android mTLS + Keystore + biometric | 2027-02-15 | ⏳ |
| 11.8 | Android push (FCM) + WebSocket | 2027-03-01 | ⏳ |
| 11.9 | Android background + offline queue | 2027-03-15 | ⏳ |
| 11.10 | Android Play Store beta + production | 2027-03-31 | ⏳ |

**iOS + Android parallel**: 6 months calendar (Dec 2026 → Mar 2027),
3 months per platform full-time.

## 7. App Store / Play Store submission

### 7.1 iOS App Store

- **Bundle ID**: `com.tyj1987.broker.mobile`
- **Category**: Developer Tools / Productivity
- **Privacy**: NO PII collected (broker is non-PII by design; see
  [docs/SECURITY-CONTROLS-SOC2.md](SECURITY-CONTROLS-SOC2.md) §7)
- **Review notes**: explain mTLS + biometric; demo account; broker endpoint
- **Cost**: $99/year Apple Developer account
- **Lead time**: 1-2 weeks App Review

### 7.2 Google Play Store

- **Package**: `com.tyj1987.broker.mobile`
- **Category**: Developer Tools / Productivity
- **Data safety form**: declare no PII collection
- **Permissions**: `INTERNET` + `USE_BIOMETRIC` + `CAMERA` (QR scan) + `POST_NOTIFICATIONS` + `FOREGROUND_SERVICE` (background sync)
- **Cost**: $25 one-time Google Play Console
- **Lead time**: 1-2 weeks Play Console review

## 8. Cost estimate (P3 #11)

| Item | Cost |
|------|------|
| Apple Developer account (annual) | $99/year |
| Google Play Console (one-time) | $25 |
| iOS dev tooling (Xcode 15) | free (with Mac) |
| Android dev tooling (Android Studio Hedgehog) | free |
| Maintainer time (iOS + Android, 6 months full-time) | volunteer / tyj1987 |
| Push notification services (APNs free; FCM free) | $0 |
| **Total upfront** | **~$125** |
| **Total recurring** | **~$99/year** |

## 9. Security considerations

| Concern | Mitigation |
|---------|------------|
| Private key extraction | iOS Keychain (Secure Enclave, hardware-isolated); Android Keystore (StrongBox on supported devices); never write to disk unencrypted |
| Biometric bypass | LAContext / androidx.biometric with `setNegativeButtonText` for fallback to passcode; auto-lockout after 5 failures |
| App background hijack | 5-min background lock; biometric re-required to resume; on jailbreak / root detected, wipe keychain entry |
| Push notification spoofing | APNs token binding to app bundle ID; FCM token binding to package signature |
| WebSocket injection | Same mTLS auth as REST; reject if cert mismatch |
| Local storage tamper | iOS Data Protection (NSFileProtectionComplete); Android EncryptedSharedPreferences |
| Log leakage | os.Logger / Timber with redaction filter (port broker's `lib/redact.js` patterns) |
| Jailbreak / root | Detect via `JailbreakDetection` (iOS) + `RootBeer` (Android); refuse to run if detected |

## 10. Open questions (for user 决断)

1. **App Store publisher**: tyj1987 personal account, or new "tyj1987 LLC" entity? Apple requires D-U-N-S number for org accounts.
2. **Pricing model**: free (BYOL), or one-time $4.99 / $9.99 per platform?
3. **F-Droid**: distribute Android APK via F-Droid (open source app store)? F-Droid requires reproducible builds.
4. **Open source vs closed**: iOS + Android in same repo as broker? Or separate `broker-mobile` repo? Recommendation: separate (different release cadence, different CI, different review process).
5. **Multi-language**: en-US only first, or also zh-CN (since tyj1987 is Chinese)?

## 11. Estimated effort

| Phase | Weeks | LOC (estimate) | Risk |
|-------|-------|----------------|------|
| 11.1-11.5 iOS | 14 | ~3,500 (Swift) | Medium (Xcode 15 + SwiftUI + Keychain + APNs) |
| 11.6-11.10 Android | 12 | ~3,500 (Kotlin) | Medium (Gradle + Compose + Keystore + FCM) |
| **Total** | **26 weeks (parallel)** | **~7,000** | |

**Calendar**: 6 months from Phase 11.1 start (2026-12-01) → 2027-05-31.
ROADMAP target 2027-03-31 is **aggressive** (4 months). Realistic 2027-Q2
or Q3 launch.

## 12. Success criteria

- [ ] iOS app published on App Store (V1.0.0)
- [ ] Android app published on Play Store (V1.0.0)
- [ ] mTLS enrollment works (QR scan + biometric)
- [ ] Push notifications for alerts
- [ ] Background health check
- [ ] Offline queue + sync
- [ ] App Store review passed (privacy + security)
- [ ] Play Console review passed (data safety form)
- [ ] User docs + screenshots in `docs/MOBILE-CLIENTS.md`
- [ ] All tests pass (XCUITest + Espresso)

## 13. Refs

- [ROADMAP-post-1.0.md §11](../ROADMAP-post-1.0.md#11-mobile-clients-q1-2027)
- [docs/THREAT-MODEL.md](../docs/THREAT-MODEL.md)
- [docs/SECURITY-CONTROLS-ISO27001.md](SECURITY-CONTROLS-ISO27001.md)
- [docs/SECURITY-CONTROLS-SOC2.md](SECURITY-CONTROLS-SOC2.md)
- [docs/DESIGN-TAURI-DESKTOP.md](DESIGN-TAURI-DESKTOP.md) (sister design for desktop)
- [docs/DESIGN-V4.2.0.md](DESIGN-V4.2.0.md) (sister design for V4.2.0 features)
- [iOS Network.framework mTLS guide](https://developer.apple.com/documentation/network)
- [Android OkHttp mTLS guide](https://square.github.io/okhttp/features/https/)

## 14. License

This document is licensed under MIT — see [LICENSE](../LICENSE).
