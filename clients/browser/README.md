# Secret Broker browser helper

This Manifest V3 extension performs a user-initiated fill on fixed Aliyun and Tencent login origins. It has no cookie, debugger, clipboard, history, downloads, broad host, or arbitrary-script permission. Each response from the native host must match the current origin, tab, document, frame, provider, and a two-minute maximum expiry.

The extension ID is fixed to `fcllkkhicfhknnbapgheklkaccjdbeln` by the public key in the manifest. The native host is the `secret-broker-browser-host` binary built with the desktop client; its manifest allows only that extension. Installers must replace the manifest `path` with the absolute installed binary path and register it using the operating-system browser policy. The bridge key is stored under `com.secretbroker.desktop/browser-bridge-api-key`, must carry only the `browser:otp:fill` scope, and must belong to the same subject that created the operation.

The native protocol claims a code for at most 30 seconds, binds it to the current provider, HTTPS origin, tab, top-level frame, and document, then records an explicit success or failure after the page write. A failed or expired claim cannot be reused. Codes inserted into a page are visible to that page and therefore this helper is not part of the strict isolated-browser security profile.

Register the host per user with `native-host/install-windows.ps1` or
`native-host/install-linux.sh`. Both installers require an explicit absolute
path to the separately built native-host binary; neither downloads or trusts a
binary. Production packages must verify the release signature before running
the installer.
