# Release Scripts

Build + publish Secret Broker release assets.

## V4.1.1 release (current)

```bash
# 1. Verify tag exists
git tag -l "v4.1.1"  # should show v4.1.1

# 2. Run release script
bash scripts/release/v4.1.1.sh

# 3. Review MANIFEST.md
cat release-assets/MANIFEST.md

# 4. (Optional) Auto-upload to GitHub Release draft
gh auth status  # ensure logged in
bash scripts/release/v4.1.1.sh --upload

# 5. (Optional) Auto-publish (skip draft review)
bash scripts/release/v4.1.1.sh --upload --publish
```

## What the script does

1. **Preflight**: verifies git tag exists, version matches, working tree clean
2. **Source archives** (2): `git archive` from tag → tar.gz + zip
3. **Python SDK** (2): `python -m build` → wheel + sdist
4. **Go SDK CLI** (4): `go build` cross-compile for 4 platforms
5. **SHA-256** (8): compute for all assets (cross-platform via `sha256sum` / `shasum`)
6. **MANIFEST.md** (1): auto-generated table with sizes + SHA-256
7. **(Optional) Upload**: `gh release create` + upload 8 assets

## Total output

```
release-assets/
├── broker-V4.1.1-src.tar.gz          (~550 KB)
├── broker-V4.1.1-src.zip             (~690 KB)
├── secret_broker-V4.1.1-py3-none-any.whl  (~12 KB)
├── secret_broker-V4.1.1.tar.gz       (~16 KB)
└── MANIFEST.md                        (auto-generated)

sdk/go/bin/
├── broker-cli-linux-amd64             (~5.3 MB)
├── broker-cli-linux-arm64             (~5.1 MB)
├── broker-cli-darwin-amd64            (~5.4 MB)
└── broker-cli-windows-amd64.exe       (~5.4 MB)
```

## Prerequisites

```bash
# All standard tools
which git node python3 pip go zip

# GitHub CLI (for --upload)
gh --version  # https://cli.github.com/

# Python build deps
python3 -m pip install --upgrade build wheel

# Go (1.22+)
go version
```

## Why a script (not just docs)

- **Reproducibility**: 1 command = 8 assets + SHA-256 + MANIFEST
- **Cross-platform**: works on macOS, Linux, Windows (Git Bash / WSL)
- **Fail-fast**: preflight checks prevent bad releases (e.g. version mismatch, missing tag)
- **Audit trail**: 1 commit that adds the script = reproducible build forever

## V4.1.0 → V4.1.1 differences

V4.1.0 release was done manually (one-off PowerShell script). V4.1.1+
uses this bash script for:

- ✅ Cross-platform (was Windows-only PowerShell)
- ✅ Reusable for V4.1.2, V4.2.0, etc. (just `VERSION=4.2.0 bash scripts/release/v4.1.1.sh`)
- ✅ Pre-flight safety checks (prevent tag/version mismatch)
- ✅ Clean MANIFEST.md generation (was hand-edited)
- ✅ SHA-256 + size auto-computed (was manual)

## Refs

- [V4.1.0 release process](https://github.com/tyj1987/broker/releases/tag/v4.1.0) (manual)
- [V4.1.0 MANIFEST.md](../../release-assets/MANIFEST.md) (template for V4.1.1)
- [docs/RELEASE-NOTES-v4.1.1.md](../../docs/RELEASE-NOTES-v4.1.1.md) (release body, fed to `gh release create --notes-file`)
- [ROADMAP-post-1.0.md §9](../../ROADMAP-post-1.0.md#9-v41.1-patch-q4-2026) (V4.1.1 patch ROADMAP item)
