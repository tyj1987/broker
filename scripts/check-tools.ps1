# scripts/check-tools.ps1
# 验证开发环境所有必需工具
# 用法：pwsh -File scripts/check-tools.ps1

$ErrorActionPreference = 'Continue'

$required = @(
    @{ Name = "age";      MinVersion = "1.0.0";  Install = "scoop install age" }
    @{ Name = "sops";     MinVersion = "3.7.0";  Install = "scoop install sops" }
    @{ Name = "git";      MinVersion = "2.30.0"; Install = "scoop install git" }
    @{ Name = "task";     MinVersion = "3.0.0";  Install = "scoop install go-task" }
    @{ Name = "node";     MinVersion = "20.0.0"; Install = "scoop install nodejs" }
    @{ Name = "direnv";   MinVersion = "2.30.0"; Install = "scoop install direnv" }
    @{ Name = "gitleaks"; MinVersion = "8.0.0";  Install = "scoop install gitleaks" }
)

$optional = @(
    @{ Name = "docker";   Install = "Docker Desktop" }
    @{ Name = "terraform"; Install = "scoop install terraform" }
)

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  工具检查" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$okCount = 0
$failCount = 0

foreach ($tool in $required) {
    $cmd = Get-Command $tool.Name -ErrorAction SilentlyContinue
    if ($cmd) {
        $version = & $tool.Name --version 2>$null | Select-Object -First 1
        Write-Host "  ✅ $($tool.Name) : $version" -ForegroundColor Green
        $okCount++
    } else {
        Write-Host "  ❌ $($tool.Name) : 未安装（必需）" -ForegroundColor Red
        Write-Host "     安装命令: $($tool.Install)" -ForegroundColor Yellow
        $failCount++
    }
}

Write-Host ""
Write-Host "  --- 可选工具 ---" -ForegroundColor Gray

foreach ($tool in $optional) {
    $cmd = Get-Command $tool.Name -ErrorAction SilentlyContinue
    if ($cmd) {
        $version = & $tool.Name --version 2>$null | Select-Object -First 1
        Write-Host "  ✅ $($tool.Name) : $version" -ForegroundColor Green
    } else {
        Write-Host "  ⚪ $($tool.Name) : 未安装（可选）" -ForegroundColor Gray
        Write-Host "     需要时安装: $($tool.Install)" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  结果: $okCount 个必需工具 OK, $failCount 个缺失" -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Red" })
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($failCount -gt 0) {
    exit 1
}
