# scripts/backup-keys.ps1
# 备份 age 私钥到指定目录（建议 U 盘 / 网盘 / 加密磁盘）
# 用法：pwsh -File scripts/backup-keys.ps1 -Destination E:\keys-backup

param(
    [Parameter(Mandatory = $false)]
    [string]$Destination = "$env:USERPROFILE\Documents\age-keys-backup"
)

$ErrorActionPreference = 'Stop'

$ageDir = Join-Path $env:USERPROFILE ".config\sops\age"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  备份 age 私钥" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 检查源目录
if (-not (Test-Path $ageDir)) {
    Write-Host "❌ 找不到钥匙目录: $ageDir" -ForegroundColor Red
    Write-Host "   请先运行 bootstrap.ps1" -ForegroundColor Yellow
    exit 1
}

# 准备目标目录
if (-not (Test-Path $Destination)) {
    New-Item -Path $Destination -ItemType Directory -Force | Out-Null
    Write-Host "✅ 创建备份目录: $Destination" -ForegroundColor Green
}

# 复制所有钥匙文件
$keyFiles = Get-ChildItem $ageDir -Filter "*.txt" -File
if ($keyFiles.Count -eq 0) {
    Write-Host "❌ 没有找到任何 age 钥匙文件" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "找到以下钥匙：" -ForegroundColor Cyan
foreach ($file in $keyFiles) {
    Write-Host "  - $($file.Name)" -ForegroundColor White
}
Write-Host ""

$confirm = Read-Host "确认备份到 [$Destination]？[Y/n]"
if ($confirm -ne '' -and $confirm -notmatch '^[Yy]') {
    Write-Host "已取消" -ForegroundColor Yellow
    exit 0
}

foreach ($file in $keyFiles) {
    $target = Join-Path $Destination $file.Name
    Copy-Item $file.FullName $target -Force
    Write-Host "  ✅ $($file.Name) → $target" -ForegroundColor Green
}

# 生成索引文件
$indexFile = Join-Path $Destination "README.txt"
$index = @"
age 私钥备份清单
生成时间: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
备份目录: $Destination

⚠️ 重要警告 ⚠️
1. 私钥文件 = 全部密钥的控制权，绝对不能泄露
2. 此目录必须加密存储（BitLocker / VeraCrypt / 强密码压缩包）
3. 至少保留 2 份独立物理备份（U 盘 + 云盘 / 保险柜）
4. 定期（每 6-12 个月）重新生成并更新备份

钥匙文件：
"@
foreach ($file in $keyFiles) {
    $content = Get-Content $file.FullName -Raw
    $pubMatch = [regex]::Match($content, '# public key: (age1[a-z0-9]+)')
    $pub = if ($pubMatch.Success) { $pubMatch.Groups[1].Value } else { "未知" }
    $index += "`n- $($file.Name)`n  公钥: $pub`n  完整路径: $($file.FullName)`n"
}
Set-Content -Path $indexFile -Value $index -Encoding UTF8

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  备份完成" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  📁 备份位置: $Destination" -ForegroundColor White
Write-Host "  📄 索引文件: $indexFile" -ForegroundColor White
Write-Host ""
Write-Host "  下一步必做：" -ForegroundColor Yellow
Write-Host "    1. 把整个备份目录拷贝到 U 盘 / 网盘" -ForegroundColor Yellow
Write-Host "    2. 验证 U 盘上的钥匙能解开本项目" -ForegroundColor Yellow
Write-Host "       (把 U 盘上的 key-xxx.txt 放到任意机器的 ~/.config/sops/age/ 目录，跑 sops --decrypt secrets/common.yaml)" -ForegroundColor Yellow
Write-Host "    3. 在 KeePassXC 里记录公钥和备份位置" -ForegroundColor Yellow
Write-Host ""
