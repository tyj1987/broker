#!/bin/sh
# Install a verified SOPS release binary for Linux CI and container builds.
set -eu

SOPS_VERSION="${SOPS_VERSION:-3.13.3}"
SOPS_ARCH="${SOPS_ARCH:-$(uname -m)}"
DESTINATION="${1:-/usr/local/bin/sops}"

if ! printf '%s' "$SOPS_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "invalid SOPS_VERSION: $SOPS_VERSION" >&2
  exit 1
fi

case "$SOPS_ARCH" in
  amd64|x86_64)
    SOPS_ARCH=amd64
    ;;
  arm64|aarch64)
    SOPS_ARCH=arm64
    ;;
  *)
    echo "unsupported SOPS architecture: $SOPS_ARCH" >&2
    exit 1
    ;;
esac

# Pin the checksum manifest itself so downloading both the binary and manifest
# from the same endpoint cannot silently replace both. Update this value only
# after reviewing the official release assets.
case "$SOPS_VERSION" in
  3.13.3)
    DEFAULT_CHECKSUMS_SHA256='91710ede6a3218e5b62286412543768a92d0c3449434951bd148d21043aad538'
    ;;
  *)
    DEFAULT_CHECKSUMS_SHA256=''
    ;;
esac
CHECKSUMS_SHA256="${SOPS_CHECKSUMS_SHA256:-$DEFAULT_CHECKSUMS_SHA256}"
if [ -z "$CHECKSUMS_SHA256" ]; then
  echo "SOPS_CHECKSUMS_SHA256 must be supplied for SOPS $SOPS_VERSION" >&2
  exit 1
fi

ASSET="sops-v${SOPS_VERSION}.linux.${SOPS_ARCH}"
CHECKSUMS="sops-v${SOPS_VERSION}.checksums.txt"
BASE_URL="https://github.com/getsops/sops/releases/download/v${SOPS_VERSION}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

download() {
  url="$1"
  destination="$2"
  if command -v curl >/dev/null 2>&1; then
    curl --fail --silent --show-error --location --retry 3 --retry-all-errors \
      --output "$destination" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -T 30 -O "$destination" "$url"
  else
    echo 'curl or wget is required to install SOPS' >&2
    exit 1
  fi
}

download "$BASE_URL/$ASSET" "$TMP_DIR/$ASSET"
download "$BASE_URL/$CHECKSUMS" "$TMP_DIR/$CHECKSUMS"

printf '%s  %s\n' "$CHECKSUMS_SHA256" "$TMP_DIR/$CHECKSUMS" | sha256sum -c -
awk -v asset="$ASSET" '$2 == asset { print; found = 1 } END { if (!found) exit 1 }' \
  "$TMP_DIR/$CHECKSUMS" > "$TMP_DIR/selected-checksum.txt"
(
  cd "$TMP_DIR"
  sha256sum -c selected-checksum.txt
)

mkdir -p "$(dirname "$DESTINATION")"
install -m 0755 "$TMP_DIR/$ASSET" "$DESTINATION"
"$DESTINATION" --version
