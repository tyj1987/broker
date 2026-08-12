# scripts/install-direnv-hook.ps1
# Adds the direnv PowerShell hook to the current user's $PROFILE.
# 给当前用户的 $PROFILE 加 direnv 的 PowerShell hook。
# Idempotent: safe to run multiple times.
# 幂等：可多次运行。
#
# Usage / 用法: pwsh -File scripts/install-direnv-hook.ps1

$ErrorActionPreference = 'Stop'

# UTF-8 console / UTF-8 控制台
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$profilePath = $PROFILE
if (-not (Test-Path $profilePath)) {
    Write-Host "Creating $profilePath / 创建中..." -ForegroundColor Cyan
    New-Item -Path $profilePath -ItemType File -Force | Out-Null
}

$utf8Bom = New-Object System.Text.UTF8Encoding($true)
$profileContent = if (Test-Path $profilePath) { Get-Content $profilePath -Raw -Encoding UTF8 } else { '' }

# Remove any existing direnv hook blocks (idempotent rewrite)
# 删掉已有的 direnv hook 块（幂等重写）
$pattern = '(?s)# >>> direnv hook >>>.*?# <<< direnv hook <<<\r?\n?'
$profileContent = [regex]::Replace($profileContent, $pattern, '')

$hookBlock = @"

# >>> direnv hook >>>
# Loads env vars from .envrc on cd. Install direnv first:
# 装 direnv：scoop install direnv
# Run this script to (re)install: pwsh -File scripts/install-direnv-hook.ps1
if (Get-Command direnv -ErrorAction SilentlyContinue) {
    Invoke-Expression "& `"`$((direnv export powershell)`)`" 2>`$null"
}
# <<< direnv hook <<<
"@

Add-Content -Path $profilePath -Value $hookBlock -Encoding UTF8
Write-Host "OK Added direnv hook to $profilePath / 已添加 direnv hook" -ForegroundColor Green
Write-Host "Restart PowerShell to activate / 重启 PowerShell 生效" -ForegroundColor Cyan
