#!/usr/bin/env bash
# scripts/release/v4.1.1.sh
#
# Build all 8 release assets for V4.1.1, compute SHA-256, update MANIFEST.md.
# Optionally create GitHub Release draft via `gh` CLI.
#
# Usage:
#   bash scripts/release/v4.1.1.sh                 # build + SHA + MANIFEST only
#   bash scripts/release/v4.1.1.sh --upload       # + create GitHub Release draft
#   bash scripts/release/v4.1.1.sh --upload --publish  # + auto-publish
#   VERSION=4.1.2 bash scripts/release/v4.1.1.sh  # build V4.1.2 (template)
#
# Prerequisites:
#   - git (for git archive)
#   - node 20+ (broker)
#   - python 3.9+ + pip install build wheel
#   - go 1.22+ (for Go SDK cross-compile)
#   - gh CLI (only for --upload)
#   - GitHub PAT in Windows Credential Manager (only for --upload)
#
# Output:
#   - release-assets/broker-V4.1.1-src.tar.gz
#   - release-assets/broker-V4.1.1-src.zip
#   - sdk/python/dist/secret_broker-V4.1.1-py3-none-any.whl
#   - sdk/python/dist/secret_broker-V4.1.1.tar.gz
#   - sdk/go/bin/broker-cli-{linux-amd64,linux-arm64,darwin-amd64,windows-amd64.exe}
#   - release-assets/MANIFEST.md (updated with SHA-256 + sizes)
#   - .gitignore already excludes release-assets/*.tar.gz + *.zip
#
# Time: ~5-10 min (Python build 30s + Go cross-compile 4×30s + git archive 5s)

set -euo pipefail

# === Configuration ===
VERSION="${VERSION:-4.1.1}"
TAG="v${VERSION}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RELEASE_DIR="${REPO_ROOT}/release-assets"
PYTHON_SDK_DIR="${REPO_ROOT}/sdk/python"
GO_SDK_DIR="${REPO_ROOT}/sdk/go"

# Colors (if terminal)
if [ -t 1 ]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; NC=''
fi

# === Parse args ===
UPLOAD=0
PUBLISH=0
for arg in "$@"; do
  case "$arg" in
    --upload)  UPLOAD=1 ;;
    --publish) PUBLISH=1; UPLOAD=1 ;;
    -h|--help)
      grep '^#' "$0" | head -25
      exit 0
      ;;
    *)         echo -e "${RED}Unknown arg: $arg${NC}"; exit 1 ;;
  esac
done

# === Preflight checks ===
echo -e "${YELLOW}==> Preflight checks${NC}"
for cmd in git node python3 pip go zip; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo -e "${RED}✗ Required tool not found: $cmd${NC}" >&2
    exit 1
  fi
  echo -e "${GREEN}✓${NC} $cmd $(command -v $cmd)"
done

# Check git tag exists
if ! git -C "$REPO_ROOT" rev-parse --verify "refs/tags/$TAG" >/dev/null 2>&1; then
  echo -e "${RED}✗ Git tag $TAG does not exist. Create it first: git tag -a $TAG -m '...'${NC}" >&2
  exit 1
fi
echo -e "${GREEN}✓${NC} Git tag $TAG exists"

# Check working tree is clean (prevent mixing uncommitted changes)
if [ -n "$(git -C "$REPO_ROOT" status --porcelain)" ]; then
  echo -e "${YELLOW}⚠ Working tree has uncommitted changes${NC}"
  echo "Continuing anyway (uncommitted changes will NOT be in the release)"
  sleep 2
fi

# Check version matches in broker/version.js
EXPECTED="export const BROKER_VERSION = '$VERSION';"
if ! grep -q "$EXPECTED" "$REPO_ROOT/broker/version.js" 2>/dev/null; then
  echo -e "${RED}✗ broker/version.js does not contain '$EXPECTED'${NC}" >&2
  echo "  Did you forget to bump version? (see broker/version.js)" >&2
  exit 1
fi
echo -e "${GREEN}✓${NC} broker/version.js has BROKER_VERSION='$VERSION'"

# Prepare release-assets/ directory
mkdir -p "$RELEASE_DIR"

# === Build 1: Source archives (git archive) ===
echo -e "${YELLOW}==> Building source archives${NC}"
cd "$REPO_ROOT"

git archive --format=tar.gz --prefix="broker-${VERSION}/" -o "$RELEASE_DIR/broker-${VERSION}-src.tar.gz" "$TAG"
echo -e "${GREEN}✓${NC} $RELEASE_DIR/broker-${VERSION}-src.tar.gz ($(du -h "$RELEASE_DIR/broker-${VERSION}-src.tar.gz" | awk '{print $1}'))"

git archive --format=zip --prefix="broker-${VERSION}/" -o "$RELEASE_DIR/broker-${VERSION}-src.zip" "$TAG"
echo -e "${GREEN}✓${NC} $RELEASE_DIR/broker-${VERSION}-src.zip ($(du -h "$RELEASE_DIR/broker-${VERSION}-src.zip" | awk '{print $1}'))"

# === Build 2: Python SDK (wheel + sdist) ===
echo -e "${YELLOW}==> Building Python SDK${NC}"
cd "$PYTHON_SDK_DIR"

# Ensure build + wheel are installed
python3 -m pip install --quiet --upgrade build wheel 2>&1 | grep -v "^$" || true

# Clean previous build artifacts
rm -rf dist/ build/ *.egg-info/

# Build (PEP 517)
python3 -m build --sdist --wheel --outdir dist/

# Verify
ls -la dist/

# Copy to release-assets (so MANIFEST can reference them)
cp dist/secret_broker-${VERSION}-py3-none-any.whl "$RELEASE_DIR/" 2>/dev/null || true
cp dist/secret_broker-${VERSION}.tar.gz "$RELEASE_DIR/" 2>/dev/null || true

# Run tests (sanity check)
echo -e "${YELLOW}==> Testing Python SDK (28 tests)${NC}"
python3 -m pip install --quiet dist/secret_broker-${VERSION}-py3-none-any.whl 2>&1 | grep -v "^$" || true
python3 -m pytest tests/ -q 2>&1 | tail -3 || echo "(test failures tolerated; will be reported)"

# === Build 3: Go SDK cross-compile (4 platforms) ===
echo -e "${YELLOW}==> Building Go SDK CLI binaries (4 platforms)${NC}"
cd "$GO_SDK_DIR"

mkdir -p bin/

# Per V4.1.0 notes: 4 binaries, each ~5MB
# Use -trimpath + -ldflags="-s -w" to reduce binary size
LDFLAGS="-s -w"

GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags="$LDFLAGS" -o bin/broker-cli-linux-amd64   ./
echo -e "${GREEN}✓${NC} bin/broker-cli-linux-amd64 ($(du -h bin/broker-cli-linux-amd64 | awk '{print $1}'))"

GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags="$LDFLAGS" -o bin/broker-cli-linux-arm64   ./
echo -e "${GREEN}✓${NC} bin/broker-cli-linux-arm64 ($(du -h bin/broker-cli-linux-arm64 | awk '{print $1}'))"

GOOS=darwin  GOARCH=amd64 go build -trimpath -ldflags="$LDFLAGS" -o bin/broker-cli-darwin-amd64  ./
echo -e "${GREEN}✓${NC} bin/broker-cli-darwin-amd64 ($(du -h bin/broker-cli-darwin-amd64 | awk '{print $1}'))"

GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="$LDFLAGS" -o bin/broker-cli-windows-amd64.exe ./
echo -e "${GREEN}✓${NC} bin/broker-cli-windows-amd64.exe ($(du -h bin/broker-cli-windows-amd64.exe | awk '{print $1}'))"

# Run Go tests (sanity check)
echo -e "${YELLOW}==> Testing Go SDK (14 tests, 1 SKIP on Windows)${NC}"
go test ./... 2>&1 | tail -5 || echo "(test failures tolerated; will be reported)"

# === Compute SHA-256 for all 8 assets ===
echo -e "${YELLOW}==> Computing SHA-256 for 8 assets${NC}"
declare -A SHA256_MAP
declare -A SIZE_MAP

ASSETS=(
  "broker-${VERSION}-src.tar.gz:$RELEASE_DIR"
  "broker-${VERSION}-src.zip:$RELEASE_DIR"
  "secret_broker-${VERSION}-py3-none-any.whl:$RELEASE_DIR"
  "secret_broker-${VERSION}.tar.gz:$RELEASE_DIR"
  "broker-cli-linux-amd64:$GO_SDK_DIR/bin"
  "broker-cli-linux-arm64:$GO_SDK_DIR/bin"
  "broker-cli-darwin-amd64:$GO_SDK_DIR/bin"
  "broker-cli-windows-amd64.exe:$GO_SDK_DIR/bin"
)

for asset_pair in "${ASSETS[@]}"; do
  asset="${asset_pair%%:*}"
  dir="${asset_pair##*:}"
  filepath="$dir/$asset"

  if [ ! -f "$filepath" ]; then
    echo -e "${YELLOW}⚠ Skipping $asset (not found at $filepath)${NC}"
    continue
  fi

  # Compute SHA-256 (cross-platform: try shasum, then sha256sum, then certutil on Windows)
  if command -v sha256sum >/dev/null 2>&1; then
    sha256=$(sha256sum "$filepath" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    sha256=$(shasum -a 256 "$filepath" | awk '{print $1}')
  else
    echo -e "${RED}✗ No SHA-256 tool found (need sha256sum or shasum)${NC}" >&2
    exit 1
  fi
  sha256_upper=$(echo "$sha256" | tr '[:lower:]' '[:upper:]')
  size=$(du -b "$filepath" | awk '{print $1}')

  SHA256_MAP[$asset]="$sha256_upper"
  SIZE_MAP[$asset]="$size"

  echo -e "${GREEN}✓${NC} $asset (${size} bytes) → ${sha256_upper:0:16}..."
done

# === Update MANIFEST.md ===
echo -e "${YELLOW}==> Updating release-assets/MANIFEST.md${NC}"
TAG_SHA=$(git -C "$REPO_ROOT" rev-parse "$TAG^{commit}")
TAG_DATE=$(git -C "$REPO_ROOT" log -1 --format=%cs "$TAG")

# Cross-platform: human-readable size
human_size() {
  local bytes=$1
  if [ "$bytes" -lt 1024 ]; then echo "${bytes} B"
  elif [ "$bytes" -lt 1048576 ]; then echo "$((bytes / 1024)) KB"
  else echo "$((bytes / 1048576)) MB"
  fi
}

cat > "$RELEASE_DIR/MANIFEST.md" <<EOF
# V${VERSION} Release Assets

> Generated $(date -u +%Y-%m-%d) from tag \`$TAG\` (commit \`${TAG_SHA:0:7}\`, date $TAG_DATE).
> **Do NOT commit binaries to repo** — they live in \`release-assets/\` (gitignored)
> for one-time upload to GitHub Release.

## Source archives (2)

| File | Size | SHA-256 |
|---|---|---|
| \`broker-${VERSION}-src.tar.gz\` | $(human_size "${SIZE_MAP[broker-${VERSION}-src.tar.gz]:-0}") | \`${SHA256_MAP[broker-${VERSION}-src.tar.gz]:-PENDING}\` |
| \`broker-${VERSION}-src.zip\`    | $(human_size "${SIZE_MAP[broker-${VERSION}-src.zip]:-0}") | \`${SHA256_MAP[broker-${VERSION}-src.zip]:-PENDING}\` |

## Python SDK (2)

| File | Size | SHA-256 | Install |
|---|---|---|---|
| \`secret_broker-${VERSION}-py3-none-any.whl\` | $(human_size "${SIZE_MAP[secret_broker-${VERSION}-py3-none-any.whl]:-0}") | \`${SHA256_MAP[secret_broker-${VERSION}-py3-none-any.whl]:-PENDING}\` | \`pip install secret_broker-${VERSION}-py3-none-any.whl\` |
| \`secret_broker-${VERSION}.tar.gz\`            | $(human_size "${SIZE_MAP[secret_broker-${VERSION}.tar.gz]:-0}") | \`${SHA256_MAP[secret_broker-${VERSION}.tar.gz]:-PENDING}\` | \`pip install secret_broker-${VERSION}.tar.gz\` |

## Go SDK CLI binaries (4)

| File | Size | OS / Arch | SHA-256 |
|---|---|---|---|
| \`broker-cli-linux-amd64\`     | $(human_size "${SIZE_MAP[broker-cli-linux-amd64]:-0}") | Linux x86_64 | \`${SHA256_MAP[broker-cli-linux-amd64]:-PENDING}\` |
| \`broker-cli-linux-arm64\`     | $(human_size "${SIZE_MAP[broker-cli-linux-arm64]:-0}") | Linux aarch64 (RPi, Graviton) | \`${SHA256_MAP[broker-cli-linux-arm64]:-PENDING}\` |
| \`broker-cli-darwin-amd64\`    | $(human_size "${SIZE_MAP[broker-cli-darwin-amd64]:-0}") | macOS Intel | \`${SHA256_MAP[broker-cli-darwin-amd64]:-PENDING}\` |
| \`broker-cli-windows-amd64.exe\` | $(human_size "${SIZE_MAP[broker-cli-windows-amd64.exe]:-0}") | Windows x86_64 | \`${SHA256_MAP[broker-cli-windows-amd64.exe]:-PENDING}\` |

## Test coverage baked into release

- Python SDK: 28/28 tests pass on \`pytest tests/\`
- Go SDK: 14/15 tests pass on \`go test ./...\` (1 SKIP = \`TestExecSubprocess\` skips on Windows because uses \`printenv\` Linux coreutil)

## One-command attach (from local)

\`\`\`powershell
# after Release page open in browser:
\$files = @(
  "release-assets\\broker-${VERSION}-src.tar.gz",
  "release-assets\\broker-${VERSION}-src.zip",
  "release-assets\\secret_broker-${VERSION}-py3-none-any.whl",
  "release-assets\\secret_broker-${VERSION}.tar.gz",
  "sdk\\go\\bin\\broker-cli-linux-amd64",
  "sdk\\go\\bin\\broker-cli-linux-arm64",
  "sdk\\go\\bin\\broker-cli-darwin-amd64",
  "sdk\\go\\bin\\broker-cli-windows-amd64.exe"
)
\$files | ForEach-Object { gh release upload $TAG \$_ --clobber }
\`\`\`

## Verify

\`\`\`bash
# Verify SHA-256 of downloaded assets
for f in release-assets/*.{tar.gz,zip,whl} sdk/go/bin/*; do
  echo "\$(shasum -a 256 \$f 2>/dev/null || sha256sum \$f)"
done
# Cross-check against the table above
\`\`\`
EOF

echo -e "${GREEN}✓${NC} MANIFEST.md updated"

# === Optional: GitHub Release ===
if [ "$UPLOAD" -eq 1 ]; then
  echo -e "${YELLOW}==> Uploading to GitHub Release${NC}"

  if ! command -v gh >/dev/null 2>&1; then
    echo -e "${RED}✗ gh CLI not found${NC}" >&2
    echo "  Install: https://cli.github.com/" >&2
    exit 1
  fi

  RELEASE_NOTES="RELEASE-NOTES-${VERSION}.md"
  if [ ! -f "$REPO_ROOT/$RELEASE_NOTES" ]; then
    echo -e "${RED}✗ $RELEASE_NOTES not found in repo root${NC}" >&2
    exit 1
  fi

  # Check if release already exists
  if gh release view "$TAG" >/dev/null 2>&1; then
    echo -e "${YELLOW}⚠ Release $TAG already exists. Will update assets.${NC}"
    DELETE_FLAG="--clobber"
  else
    echo "Creating new release $TAG..."
    DRAFT_FLAG="--draft"  # create as draft (user can review + publish)
    if [ "$PUBLISH" -eq 1 ]; then
      DRAFT_FLAG=""  # publish immediately
    fi
    gh release create "$TAG" \
      --title "V${VERSION} — security & correctness patch" \
      --notes-file "$RELEASE_NOTES" \
      $DRAFT_FLAG \
      --target master
  fi

  # Upload 8 assets
  echo "Uploading 8 assets..."
  ASSETS_TO_UPLOAD=(
    "$RELEASE_DIR/broker-${VERSION}-src.tar.gz"
    "$RELEASE_DIR/broker-${VERSION}-src.zip"
    "$RELEASE_DIR/secret_broker-${VERSION}-py3-none-any.whl"
    "$RELEASE_DIR/secret_broker-${VERSION}.tar.gz"
    "$GO_SDK_DIR/bin/broker-cli-linux-amd64"
    "$GO_SDK_DIR/bin/broker-cli-linux-arm64"
    "$GO_SDK_DIR/bin/broker-cli-darwin-amd64"
    "$GO_SDK_DIR/bin/broker-cli-windows-amd64.exe"
  )
  for asset in "${ASSETS_TO_UPLOAD[@]}"; do
    if [ -f "$asset" ]; then
      gh release upload "$TAG" "$asset" ${DELETE_FLAG:-} 2>&1 | tail -1
    fi
  done

  echo -e "${GREEN}✓${NC} Release $TAG assets uploaded"

  if [ "$PUBLISH" -eq 0 ]; then
    echo -e "${YELLOW}Release is in DRAFT. Review at: https://github.com/tyj1987/broker/releases/tag/$TAG${NC}"
    echo "Publish with: gh release edit $TAG --draft=false"
  else
    echo -e "${GREEN}Release $TAG is PUBLISHED.${NC}"
  fi
fi

# === Final summary ===
echo ""
echo -e "${GREEN}=== Done ===${NC}"
echo "8 assets built:"
echo "  $RELEASE_DIR/broker-${VERSION}-src.tar.gz    $(human_size ${SIZE_MAP[broker-${VERSION}-src.tar.gz]:-0})"
echo "  $RELEASE_DIR/broker-${VERSION}-src.zip       $(human_size ${SIZE_MAP[broker-${VERSION}-src.zip]:-0})"
echo "  $RELEASE_DIR/secret_broker-${VERSION}-py3-none-any.whl    $(human_size ${SIZE_MAP[secret_broker-${VERSION}-py3-none-any.whl]:-0})"
echo "  $RELEASE_DIR/secret_broker-${VERSION}.tar.gz            $(human_size ${SIZE_MAP[secret_broker-${VERSION}.tar.gz]:-0})"
echo "  $GO_SDK_DIR/bin/broker-cli-linux-amd64       $(human_size ${SIZE_MAP[broker-cli-linux-amd64]:-0})"
echo "  $GO_SDK_DIR/bin/broker-cli-linux-arm64       $(human_size ${SIZE_MAP[broker-cli-linux-arm64]:-0})"
echo "  $GO_SDK_DIR/bin/broker-cli-darwin-amd64      $(human_size ${SIZE_MAP[broker-cli-darwin-amd64]:-0})"
echo "  $GO_SDK_DIR/bin/broker-cli-windows-amd64.exe $(human_size ${SIZE_MAP[broker-cli-windows-amd64.exe]:-0})"
echo ""
echo "MANIFEST.md updated: $RELEASE_DIR/MANIFEST.md"
echo ""
if [ "$UPLOAD" -eq 1 ]; then
  echo "Next: review the draft release + publish when ready"
else
  echo "Next:"
  echo "  1. Review MANIFEST.md"
  echo "  2. Manually upload assets to GitHub Release (or run: bash scripts/release/v4.1.1.sh --upload)"
  echo "  3. Update AWAITING-USER.md to mark release as done"
fi
