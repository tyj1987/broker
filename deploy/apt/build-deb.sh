#!/usr/bin/env bash
# build-deb.sh — Build secret-broker .deb package for Ubuntu/Debian
# Output: secret-broker_4.1.1-1_amd64.deb (and arm64/armhf)
#
# Usage:
#   bash deploy/apt/build-deb.sh                 # build for current arch
#   bash deploy/apt/build-deb.sh all             # build for amd64 + arm64 + armhf
#
# Requires: ruby + fpm (gem), wget, tar, nodejs >= 20
#   curl -L https://github.com/jordansissel/fpm/releases/download/v1.15.1/fpm-1.15.1.x86_64-linux.tar.gz | tar -xz -C /usr/local/bin
#   Or: gem install fpm  (if ruby available)

set -euo pipefail

VERSION="${VERSION:-4.1.1}"
REVISION="${REVISION:-1}"
ARCH="${ARCH:-$(dpkg --print-architecture 2>/dev/null || uname -m)}"
TARBALL_URL="https://github.com/tyj1987/broker/releases/download/v${VERSION}/broker-${VERSION}.tar.gz"
TARBALL_SHA256="$(curl -sL "$TARBALL_URL" | sha256sum | awk '{print $1}')"

if [ -z "$TARBALL_SHA256" ]; then
  echo "ERROR: failed to download / hash $TARBALL_URL"
  exit 1
fi

# Work in a temp dir
WORK=$(mktemp -d)
trap "rm -rf $WORK" EXIT

echo "==> Downloading $TARBALL_URL"
curl -sL "$TARBALL_URL" -o "$WORK/source.tar.gz"
echo "    SHA256: $TARBALL_SHA256"

echo "==> Extracting"
tar -xzf "$WORK/source.tar.gz" -C "$WORK"
SRC="$WORK/broker-${VERSION}"
[ ! -d "$SRC" ] && SRC=$(find "$WORK" -maxdepth 2 -type d -name "broker-*" | head -1)
echo "    Source: $SRC"

# Use fpm if available, else use dpkg-deb
if command -v fpm >/dev/null 2>&1; then
  echo "==> Building via fpm"
  cd "$SRC"
  # Pre-stage the libexec tree
  mkdir -p "$WORK/staging/opt/secret-broker/libexec"
  cp -r broker cli bin scripts package.json package-lock.json \
        ARCHITECTURE.md RUNBOOK.md CHANGELOG.md VERIFY.md STATUS.md README.md LICENSE \
        "$WORK/staging/opt/secret-broker/libexec/" 2>/dev/null || true
  install -m 0755 cli/secret-broker.js "$WORK/staging/opt/secret-broker/libexec/"
  mkdir -p "$WORK/staging/opt/secret-broker/bin"
  cat > "$WORK/staging/opt/secret-broker/bin/secret-broker" <<'WRAP'
#!/bin/bash
exec /usr/bin/node /opt/secret-broker/libexec/secret-broker.js "$@"
WRAP
  chmod 0755 "$WORK/staging/opt/secret-broker/bin/secret-broker"
  cat > "$WORK/staging/opt/secret-broker/bin/secret-broker-server" <<'WRAP'
#!/bin/bash
set -euo pipefail
exec /usr/bin/node /opt/secret-broker/libexec/broker/server.js "$@"
WRAP
  chmod 0755 "$WORK/staging/opt/secret-broker/bin/secret-broker-server"
  mkdir -p "$WORK/staging/usr/bin"
  ln -sf /opt/secret-broker/bin/secret-broker "$WORK/staging/usr/bin/secret-broker"
  ln -sf /opt/secret-broker/bin/secret-broker-server "$WORK/staging/usr/bin/secret-broker-server"

  fpm -s dir -t deb \
      -n secret-broker \
      -v "$VERSION" \
      --iteration "$REVISION" \
      -a "$ARCH" \
      --depends "nodejs (>= 20)" \
      --description "mTLS credential proxy for AI clients (CLI + server)" \
      --url "https://github.com/tyj1987/broker" \
      --maintainer "tyj1987 <broker@52trz.com>" \
      --license "MIT" \
      --after-install deploy/apt/debian/postinst \
      --before-remove deploy/apt/debian/prerm \
      --after-remove deploy/apt/debian/postrm \
      -C "$WORK/staging" \
      -p "secret-broker_${VERSION}-${REVISION}_${ARCH}.deb"

else
  echo "ERROR: fpm not found. Install via:"
  echo "  gem install fpm"
  echo "  # or download from https://github.com/jordansissel/fpm/releases"
  exit 1
fi

echo ""
echo "==> Done. Output:"
ls -la secret-broker_${VERSION}-${REVISION}_${ARCH}.deb
echo ""
echo "Install with: sudo dpkg -i secret-broker_${VERSION}-${REVISION}_${ARCH}.deb"
echo "Or publish to PPA: see deploy/apt/README.md §PPA publishing"
