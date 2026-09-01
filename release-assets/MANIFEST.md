# V4.1.0 Release Assets

> Generated 2026-09-01. All binaries built from `v4.1.0` tag (commit `673d8a1`).
> **Do NOT commit binaries to repo** — they live in `release-assets/` (gitignored)
> for one-time upload to GitHub Release.

## Source archives (2)

| File | Size | SHA-256 |
|---|---|---|
| `broker-v4.1.0-src.tar.gz` | 547 KB | `3620261B1187C0AD7719996B8B2AFC113A5973F83933A73274369FCA9C42E3E8` |
| `broker-v4.1.0-src.zip`    | 687 KB | `C00980B8EB4B51498E192F6461345AE73DED2C11EC794F5EC1B7EFA0DCE64CAD` |

## Python SDK (2)

| File | Size | SHA-256 | Install |
|---|---|---|---|
| `secret_broker-4.1.0-py3-none-any.whl` | 11.5 KB | (see `E:\broker\sdk\python\dist\`) | `pip install secret_broker-4.1.0-py3-none-any.whl` |
| `secret_broker-4.1.0.tar.gz`            | 15.7 KB | (see `E:\broker\sdk\python\dist\`) | `pip install secret_broker-4.1.0.tar.gz` |

## Go SDK CLI binaries (4)

| File | Size | OS / Arch | SHA-256 |
|---|---|---|---|
| `broker-cli-linux-amd64`     | 5.3 MB | Linux x86_64 | `D1B314EF05E5BD22071FF23CB9D9D47A6D13A5A2A3D0271AB32B1A0D56866565` |
| `broker-cli-linux-arm64`     | 5.1 MB | Linux aarch64 (RPi, Graviton) | `57AF5D451BE6BDA1B8F8F614583E42A963EB0FA5711139AF1A15A2FB1B2A0F8C` |
| `broker-cli-darwin-amd64`    | 5.4 MB | macOS Intel | `B9767C5763CA8DA71DBC6632C65715CE08AD017793D77BA9C2582F5F355B8689` |
| `broker-cli-windows-amd64.exe` | 5.4 MB | Windows x86_64 | `6E9E3EFED9F98BD1433BE6246F05B9E4C1E03BC53A8D63306522956B9D1ED380` |

## Test coverage baked into release

- Python SDK: 28/28 tests pass on `pytest tests/`
- Go SDK: 14/15 tests pass on `go test ./...` (1 SKIP = `TestExecSubprocess` skips on Windows because uses `printenv` Linux coreutil)

## One-command attach (from local)

```powershell
# after Release page open in browser:
$files = @(
  "release-assets\broker-v4.1.0-src.tar.gz",
  "release-assets\broker-v4.1.0-src.zip",
  "sdk\python\dist\secret_broker-4.1.0-py3-none-any.whl",
  "sdk\python\dist\secret_broker-4.1.0.tar.gz",
  "sdk\go\bin\broker-cli-linux-amd64",
  "sdk\go\bin\broker-cli-linux-arm64",
  "sdk\go\bin\broker-cli-darwin-amd64",
  "sdk\go\bin\broker-cli-windows-amd64.exe"
)
$files | ForEach-Object { Write-Output "  -> $_" }
# drag these 8 into the GitHub Release "Attach binaries" area
```

## Verification (post-attach)

```bash
# Download + verify SHA-256
curl -L -O https://github.com/tyj1987/broker/releases/download/v4.1.0/broker-cli-linux-amd64
sha256sum broker-cli-linux-amd64
# expect: D1B314EF05E5BD22071FF23CB9D9D47A6D13A5A2A3D0271AB32B1A0D56866565

# smoke test
chmod +x broker-cli-linux-amd64
./broker-cli-linux-amd64 --help
```
