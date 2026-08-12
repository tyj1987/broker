# scripts/check-tools.ps1
# Verify all required dev tools are installed.
# 验证所有必需的开发工具是否已装。
# Usage / 用法: pwsh -File scripts/check-tools.ps1

$ErrorActionPreference = 'Continue'

$required = @(
    @{ Name = "age";      MinVersion = "1.0.0";  Install = "scoop install age  |  winget install FiloSottile.age" }
    @{ Name = "sops";     MinVersion = "3.7.0";  Install = "scoop install sops  |  winget install Mozilla.SOPS" }
    @{ Name = "git";      MinVersion = "2.30.0"; Install = "scoop install git" }
    @{ Name = "task";     MinVersion = "3.0.0";  Install = "scoop install go-task" }
    @{ Name = "node";     MinVersion = "20.0.0"; Install = "scoop install nodejs  |  winget install OpenJS.NodeJS.LTS" }
    @{ Name = "direnv";   MinVersion = "2.30.0"; Install = "scoop install direnv" }
    @{ Name = "gitleaks"; MinVersion = "8.0.0";  Install = "scoop install gitleaks" }
)

$optional = @(
    @{ Name = "docker";    Install = "Docker Desktop  |  https://www.docker.com/products/docker-desktop" }
    @{ Name = "terraform"; Install = "scoop install terraform" }
    @{ Name = "pwsh";      Install = "scoop install pwsh" }
)

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Tool check / 工具检查" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$okCount = 0
$failCount = 0

foreach ($tool in $required) {
    $cmd = Get-Command $tool.Name -ErrorAction SilentlyContinue
    if ($cmd) {
        $version = & $tool.Name --version 2>$null | Select-Object -First 1
        Write-Host "  OK $($tool.Name) : $version" -ForegroundColor Green
        $okCount++
    } else {
        Write-Host "  MISSING $($tool.Name) / 缺失（必需）" -ForegroundColor Red
        Write-Host "     install: $($tool.Install)" -ForegroundColor Yellow
        $failCount++
    }
}

Write-Host ""
Write-Host "  --- Optional tools / 可选工具 ---" -ForegroundColor Gray

foreach ($tool in $optional) {
    $cmd = Get-Command $tool.Name -ErrorAction SilentlyContinue
    if ($cmd) {
        $version = & $tool.Name --version 2>$null | Select-Object -First 1
        Write-Host "  OK $($tool.Name) : $version" -ForegroundColor Green
    } else {
        Write-Host "  -- $($tool.Name) : not installed / 未装（可选）" -ForegroundColor Gray
        Write-Host "     install: $($tool.Install)" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Result / 结果: $okCount OK, $failCount missing / 缺失" -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Red" })
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($failCount -gt 0) {
    exit 1
}
