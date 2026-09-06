#!/usr/bin/env bash
# deploy/homebrew/bump.sh
#
# Bump the Homebrew formula (deploy/homebrew/broker.rb) to a new broker version.
# Usage: ./deploy/homebrew/bump.sh <version> [sha256]
#   <version>   e.g. 4.1.2, 4.2.0, 5.0.0
#   [sha256]    optional — if omitted, downloads the release tarball and computes
#
# Examples:
#   ./deploy/homebrew/bump.sh 4.1.2
#   ./deploy/homebrew/bump.sh 4.2.0 a1b2c3d4e5f6...
#
# Workflow this replaces (from deploy/homebrew/README.md):
#   1. Download broker-4.x.y.tar.gz from GitHub Release
#   2. shasum -a 256 broker-4.x.y.tar.gz  (or sha256sum on Linux)
#   3. Edit deploy/homebrew/broker.rb — update `url` + `sha256`
#   4. git commit -m "chore(homebrew): bump formula to v4.x.y"
#
# After running: review the diff, commit, push to broker repo. Then sync to
# tyj1987/homebrew-broker tap repo per the README.

set -euo pipefail

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  echo "Usage: $0 <version> [sha256]" >&2
  echo "  <version>   broker version (e.g. 4.1.2, 4.2.0)" >&2
  echo "  [sha256]    optional — if omitted, downloads tarball and computes" >&2
  exit 1
fi

VERSION="$1"
SHA256="${2:-}"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FORMULA="$REPO_ROOT/deploy/homebrew/broker.rb"

if [ ! -f "$FORMULA" ]; then
  echo "ERROR: formula not found at $FORMULA" >&2
  exit 1
fi

# Compute SHA256 if not provided
if [ -z "$SHA256" ]; then
  TARBALL_URL="https://github.com/tyj1987/broker/archive/refs/tags/v${VERSION}.tar.gz"
  TARBALL_TMP="$(mktemp -t broker-XXXXXX).tar.gz"
  echo "Downloading $TARBALL_URL ..."
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$TARBALL_TMP" "$TARBALL_URL"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$TARBALL_TMP" "$TARBALL_URL"
  else
    echo "ERROR: neither curl nor wget found" >&2
    exit 1
  fi
  if command -v shasum >/dev/null 2>&1; then
    SHA256="$(shasum -a 256 "$TARBALL_TMP" | awk '{print $1}')"
  elif command -v sha256sum >/dev/null 2>&1; then
    SHA256="$(sha256sum "$TARBALL_TMP" | awk '{print $1}')"
  else
    echo "ERROR: neither shasum nor sha256sum found" >&2
    exit 1
  fi
  rm -f "$TARBALL_TMP"
  echo "Computed SHA256: $SHA256"
fi

# Validate SHA256 format (64 hex chars)
if ! echo "$SHA256" | grep -Eq "^[0-9a-f]{64}$"; then
  echo "ERROR: SHA256 must be 64 hex chars, got: $SHA256" >&2
  exit 1
fi

# Update formula — replace url and sha256 lines
# Match: url "https://github.com/tyj1987/broker/archive/refs/tags/vX.Y.Z.tar.gz"
# Match: sha256 "..."
if [[ "$OSTYPE" == "darwin"* ]]; then
  sed -i '' \
    -e "s|url \"https://github.com/tyj1987/broker/archive/refs/tags/v[0-9.]*\\.tar\\.gz\"|url \"https://github.com/tyj1987/broker/archive/refs/tags/v${VERSION}.tar.gz\"|" \
    -e "s|sha256 \"[0-9a-f]*\"|sha256 \"${SHA256}\"|" \
    "$FORMULA"
else
  sed -i \
    -e "s|url \"https://github.com/tyj1987/broker/archive/refs/tags/v[0-9.]*\\.tar\\.gz\"|url \"https://github.com/tyj1987/broker/archive/refs/tags/v${VERSION}.tar.gz\"|" \
    -e "s|sha256 \"[0-9a-f]*\"|sha256 \"${SHA256}\"|" \
    "$FORMULA"
fi

echo "Updated $FORMULA:"
grep -E "^\s*(url|sha256) " "$FORMULA" | sed 's/^/  /'

echo
echo "Next steps:"
echo "  1. Review the diff: cd $REPO_ROOT && git diff deploy/homebrew/broker.rb"
echo "  2. Commit:         git add deploy/homebrew/broker.rb && git commit -m \"chore(homebrew): bump formula to v${VERSION}\""
echo "  3. Push:           git push origin master"
echo "  4. Sync to tap:    cp deploy/homebrew/broker.rb <tyj1987/homebrew-broker>/Formula/broker.rb && (cd <tyj1987/homebrew-broker> && git commit -am \"chore: bump broker to v${VERSION}\" && git push origin master)"
echo "  5. Verify:         brew audit --strict tyj1987/broker/broker"
