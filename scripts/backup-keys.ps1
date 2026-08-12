# scripts/backup-keys.ps1
# Backup age private keys to a chosen location (USB drive recommended).
# 备份 age 私钥到指定目录（推荐 U 盘）。
# Usage / 用法:
#   pwsh -File scripts/backup-keys.ps1
#   pwsh -File scripts/backup-keys.ps1 -Destination E:\keys-backup

param(
    [Parameter(Mandatory = $false)]
    [string]$Destination = "$env:USERPROFILE\Documents\age-keys-backup"
)

$ErrorActionPreference = 'Stop'

$ageDir = Join-Path $env:USERPROFILE ".config\sops\age"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Backup age private keys / 备份 age 私钥" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check source directory / 检查源目录
if (-not (Test-Path $ageDir)) {
    Write-Host "ERROR: key directory not found: $ageDir" -ForegroundColor Red
    Write-Host "       Run bootstrap.ps1 first. / 请先跑 bootstrap.ps1" -ForegroundColor Yellow
    exit 1
}

# Prepare destination / 准备目标目录
if (-not (Test-Path $Destination)) {
    New-Item -Path $Destination -ItemType Directory -Force | Out-Null
    Write-Host "OK Created backup dir / 创建备份目录: $Destination" -ForegroundColor Green
}

# Copy all key files / 复制所有钥匙
$keyFiles = Get-ChildItem $ageDir -Filter "*.txt" -File | Where-Object { $_.Name -ne 'README.txt' }
if ($keyFiles.Count -eq 0) {
    Write-Host "ERROR: no age key files found / 没找到任何 age 钥匙" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Found keys / 找到钥匙：" -ForegroundColor Cyan
foreach ($file in $keyFiles) {
    Write-Host "  - $($file.Name)" -ForegroundColor White
}
Write-Host ""

$confirm = Read-Host "Backup to [$Destination]? [Y/n] / 备份到 $Destination？"
if ($confirm -ne '' -and $confirm -notmatch '^[Yy]') {
    Write-Host "Cancelled / 已取消" -ForegroundColor Yellow
    exit 0
}

foreach ($file in $keyFiles) {
    $target = Join-Path $Destination $file.Name
    Copy-Item $file.FullName $target -Force
    Write-Host "  OK $($file.Name) -> $target" -ForegroundColor Green
}

# Write index / 生成索引
$indexFile = Join-Path $Destination "README.txt"
$index = @"
age 私钥备份清单 / age key backup manifest
Generated / 生成时间: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Backup dir / 备份目录: $Destination

!!! WARNINGS / 警告 !!!
1. Private key files = full control of all secrets. NEVER leak.
   私钥文件 = 全部密钥的控制权，绝对不能泄露。
2. This directory MUST be stored encrypted (BitLocker / VeraCrypt / strong-password zip).
   此目录必须加密存储（BitLocker / VeraCrypt / 强密码压缩包）。
3. Keep at least 2 independent physical backups (USB + safe deposit box).
   至少保留 2 份独立物理备份（U 盘 + 保险柜）。
4. Regenerate every 6-12 months.
   每 6-12 个月重新生成并更新备份。

Keys / 钥匙清单:
"@
foreach ($file in $keyFiles) {
    $content = Get-Content $file.FullName -Raw
    $pubMatch = [regex]::Match($content, '# public key: (age1[a-z0-9]+)')
    $pub = if ($pubMatch.Success) { $pubMatch.Groups[1].Value } else { "unknown / 未知" }
    $index += "`n- $($file.Name)`n  public key / 公钥: $pub`n  full path / 完整路径: $($file.FullName)`n"
}
[System.IO.File]::WriteAllText($indexFile, $index, (New-Object System.Text.UTF8Encoding $false))

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Backup complete / 备份完成" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Backup at / 备份位置: $Destination" -ForegroundColor White
Write-Host "  Index at / 索引: $indexFile" -ForegroundColor White
Write-Host ""
Write-Host "  NEXT STEPS / 下一步必做:" -ForegroundColor Yellow
Write-Host "    1. Copy the entire backup dir to a USB drive / 整个目录拷到 U 盘" -ForegroundColor Yellow
Write-Host "    2. Verify the USB key can decrypt this project / 验证 U 盘能解本项目" -ForegroundColor Yellow
Write-Host "       (copy key-xxx.txt to another machine's ~/.config/sops/age/, run sops --decrypt secrets/common.env)" -ForegroundColor Yellow
Write-Host "    3. Record public keys + backup location in your password manager / 公钥和备份位置记到密码管理器" -ForegroundColor Yellow
Write-Host ""
