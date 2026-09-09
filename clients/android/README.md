# Secret Broker for Android

The current Android milestone is a device-bound OTP receiver. Approval UI is
not implemented yet. The app does not read message history, request SMS
sending, contacts, notification access, accessibility access, or store message
bodies.

Enrollment uses a hardware-backed Android Keystore P-256 signing key. The app
fails closed and does not pair when the generated key is not reported as
hardware-backed; this is a capability decision observed on the device, not an
assumption based on its model name.

`RECEIVE_SMS` is restricted by Android and might not be grantable to a self-signed APK. The app reports the observed capability. When it is unavailable, SMS User Consent requires a visible user confirmation, or the code must be entered manually. Neither fallback is unattended operation.

The first physical-device acceptance target is a dual-SIM Xiaomi 12S Ultra. A release is not considered device-tested until permission grant, both SIM bindings, delayed and duplicate messages, background restrictions, permission revocation, and the manual fallback have been exercised on that device.

The receiver does not guess a default SIM. After pairing, it records only the
subscription and slot metadata attached to a newly delivered SMS, never the
message or code. The operator then binds each observed SIM to the opaque value
shown by an active Broker task. Missing subscription metadata is rejected, and
a changed subscription in an observed slot invalidates the previous binding.
The app blocks screenshots and recent-task previews, masks the short-lived
pairing challenge, and accepts a SIM binding only while a matching task is
active.
