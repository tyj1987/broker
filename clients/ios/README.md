# iOS client

The iOS client pairs a hardware-bound P-256 device identity with Secret Broker.
Its private key is generated in Secure Enclave and is marked this-device-only;
the Broker stores only its public key. Pairing uses a five-minute challenge
created by an already authenticated human session.

The first milestone implements secure pairing and protocol primitives. It does
not claim background SMS access, unattended OTP collection, production signing,
or physical-device acceptance. Those capabilities remain gated by Apple APIs,
explicit user permission, the approval state machine, App Store entitlements,
and real-device tests.

Open `Package.swift` in Xcode 16 or later, choose the `SecretBrokerIOSApp`
scheme, and use an iOS 17+ device. Secure Enclave key creation is expected to
fail on unsupported simulator configurations. Never weaken the signer to a
syncable software key in a release build.

Run protocol tests on macOS with:

```sh
swift test
```
