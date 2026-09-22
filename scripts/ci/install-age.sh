#!/bin/sh
# Install a pinned, checksum-verified age release for Linux CI runners.
set -eu

AGE_VERSION="${AGE_VERSION:-1.3.2}"
AGE_ARCH="${AGE_ARCH:-$(uname -m)}"
DESTINATION_DIR="${1:-/usr/local/bin}"

if ! printf '%s' "$AGE_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "invalid AGE_VERSION: $AGE_VERSION" >&2
  exit 1
fi

case "$AGE_ARCH" in
  amd64|x86_64)
    AGE_ARCH=amd64
    ;;
  *)
    echo "unsupported age architecture: $AGE_ARCH" >&2
    exit 1
    ;;
esac

case "$AGE_VERSION-$AGE_ARCH" in
  1.3.2-amd64)
    DEFAULT_ARCHIVE_SHA256='cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10'
    ;;
  *)
    DEFAULT_ARCHIVE_SHA256=''
    ;;
esac
ARCHIVE_SHA256="${AGE_ARCHIVE_SHA256:-$DEFAULT_ARCHIVE_SHA256}"
if [ -z "$ARCHIVE_SHA256" ]; then
  echo "AGE_ARCHIVE_SHA256 must be supplied for age $AGE_VERSION/$AGE_ARCH" >&2
  exit 1
fi

ARCHIVE="age-v${AGE_VERSION}-linux-${AGE_ARCH}.tar.gz"
URL="https://github.com/FiloSottile/age/releases/download/v${AGE_VERSION}/${ARCHIVE}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

if command -v curl >/dev/null 2>&1; then
  curl --fail --silent --show-error --location --retry 3 --retry-all-errors \
    --output "$TMP_DIR/$ARCHIVE" "$URL"
elif command -v wget >/dev/null 2>&1; then
  wget -q -T 30 -O "$TMP_DIR/$ARCHIVE" "$URL"
else
  echo 'curl or wget is required to install age' >&2
  exit 1
fi

printf '%s  %s\n' "$ARCHIVE_SHA256" "$TMP_DIR/$ARCHIVE" | sha256sum -c -
tar -xzf "$TMP_DIR/$ARCHIVE" -C "$TMP_DIR"
test -x "$TMP_DIR/age/age"
test -x "$TMP_DIR/age/age-keygen"
mkdir -p "$DESTINATION_DIR"
install -m 0755 "$TMP_DIR/age/age" "$DESTINATION_DIR/age"
install -m 0755 "$TMP_DIR/age/age-keygen" "$DESTINATION_DIR/age-keygen"
"$DESTINATION_DIR/age" --version
"$DESTINATION_DIR/age-keygen" --version
