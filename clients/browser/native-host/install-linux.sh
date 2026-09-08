#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: install-linux.sh /absolute/path/to/secret-broker-browser-host chrome|edge" >&2
  exit 2
fi

binary=$1
browser=$2
case "$binary" in
  /*) ;;
  *) echo "binary path must be absolute" >&2; exit 2 ;;
esac
[ -f "$binary" ] && [ -x "$binary" ] || { echo "native host is not executable" >&2; exit 2; }

case "$browser" in
  chrome) directory="${XDG_CONFIG_HOME:-$HOME/.config}/google-chrome/NativeMessagingHosts" ;;
  edge) directory="${XDG_CONFIG_HOME:-$HOME/.config}/microsoft-edge/NativeMessagingHosts" ;;
  *) echo "browser must be chrome or edge" >&2; exit 2 ;;
esac

mkdir -p "$directory"
manifest="$directory/com.secretbroker.browser.json"
python3 - "$binary" "$manifest" <<'PY'
import json
import os
import sys

binary, manifest = sys.argv[1:]
payload = {
    "name": "com.secretbroker.browser",
    "description": "Secret Broker one-time fill bridge",
    "path": binary,
    "type": "stdio",
    "allowed_origins": ["chrome-extension://fcllkkhicfhknnbapgheklkaccjdbeln/"],
}
descriptor = os.open(manifest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as output:
    json.dump(payload, output, separators=(",", ":"))
    output.write("\n")
PY
echo "Registered com.secretbroker.browser for $browser."
