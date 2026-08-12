# scripts/rotate-keys.ps1
# 轮转 age 钥匙：生成新钥匙 → 替换 .sops.yaml → 重加密所有 secrets
# 用法：pwsh -File scripts/rotate-keys.ps1

$ErrorActionPreference = 'Stop'

$ageDir = Join-Path $env:USERPROFILE ".config\sops\age"
$sopsConfig = ".sops.yaml"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  轮转 age 钥匙" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "⚠️  警告：这会重新加密所有 secrets 文件" -ForegroundColor Yellow
Write-Host ""

$confirm = Read-Host "继续？[y/N]"
if ($confirm -notmatch '^[Yy]') {
    Write-Host "已取消" -ForegroundColor Yellow
    exit 0
}

# 生成新主钥匙
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$newKeyA = Join-Path $ageDir "key-a-$timestamp.txt"
Write-Host ""
Write-Host "🔑 生成新主钥匙..." -ForegroundColor Cyan
age-keygen -o $newKeyA 2>&1 | ForEach-Object {
    Write-Host "   $_" -ForegroundColor Gray
}

$newPub = Select-String -Path $newKeyA -Pattern '# public key: (age1[a-z0-9]+)' | ForEach-Object { $matches[1] }
if (-not $newPub) {
    Write-Host "❌ 生成失败" -ForegroundColor Red
    exit 1
}
Write-Host "✅ 新公钥: $newPub" -ForegroundColor Green
Write-Host ""

# 备份旧钥匙
$oldKeyA = Join-Path $ageDir "key-a.txt"
if (Test-Path $oldKeyA) {
    $archiveDir = Join-Path $ageDir "archive-$timestamp"
    New-Item -Path $archiveDir -ItemType Directory -Force | Out-Null
    Move-Item $oldKeyA $archiveDir
    Write-Host "📦 旧钥匙已归档到: $archiveDir" -ForegroundColor Green
    Write-Host "   验证新流程跑通后再删除" -ForegroundColor Yellow
}

# 用新钥匙替换
Move-Item $newKeyA $oldKeyA

# 替换 .sops.yaml 里的 A 公钥
Write-Host ""
Write-Host "📝 更新 .sops.yaml..." -ForegroundColor Cyan
$content = Get-Content $sopsConfig -Raw

# 提取当前 A 公钥
$currentPub = Select-String -Path $sopsConfig -Pattern 'age1[a-z0-9]+' | Select-Object -First 1 | ForEach-Object { $_.Matches[0].Value }

if ($currentPub) {
    $content = $content -replace $currentPub, $newPub
    Set-Content -Path $sopsConfig -Value $content -Encoding UTF8 -NoNewline
    Write-Host "✅ 已替换 A 公钥" -ForegroundColor Green
}

# 重新加密所有 secrets
Write-Host ""
Write-Host "🔒 重加密所有 secrets 文件..." -ForegroundColor Cyan
$secretFiles = Get-ChildItem -Path "secrets" -Include "*.yaml", "*.yml", "*.env" -Recurse -File

foreach ($file in $secretFiles) {
    if ($file.Name -like "*.example" -or $file.Name -like ".gitkeep") { continue }
    Write-Host "   - $($file.FullName)" -ForegroundColor Gray
    sops updatekeys -y $file.FullName 2>&1 | Out-Null
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  轮转完成" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  下一步：" -ForegroundColor Cyan
Write-Host "    1. 验证: sops --decrypt secrets/common.yaml" -ForegroundColor White
Write-Host "    2. 测试应用能正常启动: task dev" -ForegroundColor White
Write-Host "    3. 跑一遍 git 流程: git add -A && git commit" -ForegroundColor White
Write-Host "    4. 备份新钥匙: task backup:keys" -ForegroundColor White
Write-Host "    5. 确认 OK 后删除旧钥匙归档" -ForegroundColor White
Write-Host ""
