# Secret Broker Desktop

The Windows and Linux desktop client loads only bundled UI assets. Its native bridge is limited to health checks, typed operation creation, storing or deleting restricted API keys in the operating system credential store, and opening the fixed Broker `/approvals` URL in the system browser. The approval command accepts no URL or token from the webview. It exposes no arbitrary URL, file, shell, clipboard, cookie, or remote-content capability.

Approval decisions are intentionally absent from the native bridge. The system browser must establish its own short-lived WebAuthn session, and the Broker independently enforces request binding and separation of duties.

Windows is the first release target. Linux acceptance targets Ubuntu 24.04 LTS x64 after the Windows package passes signing and update verification.
