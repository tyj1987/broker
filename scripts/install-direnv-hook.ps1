# scripts/install-direnv-hook.ps1
# Adds the direnv PowerShell hook to the current user's $PROFILE.
# Idempotent: safe to run multiple times.

$ErrorActionPreference = 'Stop'

$profilePath = $PROFILE
if (-not (Test-Path $profilePath)) {
    Write-Host "Creating $profilePath" -ForegroundColor Cyan
    New-Item -Path $profilePath -ItemType File -Force | Out-Null
}

$profileContent = if (Test-Path $profilePath) { Get-Content $profilePath -Raw } else { '' }
$marker = '# >>> direnv hook >>>'
$endMarker = '# <<< direnv hook <<<'

if ($profileContent -match [regex]::Escape($marker)) {
    Write-Host "direnv hook already installed in $profilePath" -ForegroundColor Yellow
    exit 0
}

$hookBlock = @"

$marker
# Loads env vars from .envrc on cd. Install direnv first:
#   scoop install direnv
if (Get-Command direnv -ErrorAction SilentlyContinue) {
    Invoke-Expression "& `"`$((direnv export powershell)`)`" 2>`$null"
}
$endMarker
"@

Add-Content -Path $profilePath -Value $hookBlock -Encoding UTF8
Write-Host "Added direnv hook to $profilePath" -ForegroundColor Green
Write-Host "Restart PowerShell to activate." -ForegroundColor Cyan
