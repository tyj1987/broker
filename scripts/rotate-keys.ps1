# scripts/rotate-keys.ps1
# Rotate age keys: generate new A -> re-encrypt all secrets -> archive old.
# 轮转 age 钥匙：生成新 A -> 重加密所有 secrets -> 归档旧钥匙。
# Usage / 用法: pwsh -File scripts/rotate-keys.ps1

$ErrorActionPreference = 'Stop'

# UTF-8 console / UTF-8 控制台
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$ageDir = Join-Path $env:USERPROFILE ".config\sops\age"
$sopsConfig = ".sops.yaml"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Rotate age keys / 轮转 age 钥匙" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "WARNING / 警告: this will re-encrypt all secrets files / 会重加密所有 secrets 文件" -ForegroundColor Yellow
Write-Host ""

$confirm = Read-Host "Continue? [y/N] / 继续？"
if ($confirm -notmatch '^[Yy]') {
    Write-Host "Cancelled / 已取消" -ForegroundColor Yellow
    exit 0
}

# Generate new main key / 生成新主钥匙
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$newKeyA = Join-Path $ageDir "key-a-$timestamp.txt"
Write-Host ""
Write-Host "Generating new main key... / 正在生成新主钥匙..." -ForegroundColor Cyan

# .NET Process wrapper to bypass PS 5.1 stderr trap / 用 .NET Process 包装，避开 PS 5.1 的 stderr 误判
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "age-keygen"
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
$psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
[void]$psi.ArgumentList.Add("-o")
[void]$psi.ArgumentList.Add($newKeyA)
$proc = [System.Diagnostics.Process]::Start($psi)
$so = $proc.StandardOutput.ReadToEnd()
$se = $proc.StandardError.ReadToEnd()
$proc.WaitForExit()
Write-Host "   $($so.Trim())" -ForegroundColor Gray

# Extract new public key / 提取新公钥
$keyContent = [System.IO.File]::ReadAllText($newKeyA, (New-Object System.Text.UTF8Encoding $false))
$newPub = if ($keyContent -match '# public key: (age1[a-z0-9]+)') { $matches[1] } else { $null }
if (-not $newPub) {
    Write-Host "ERROR: failed to extract public key / 提取公钥失败" -ForegroundColor Red
    exit 1
}
Write-Host "OK new public key / 新公钥: $newPub" -ForegroundColor Green

# Archive old key A / 归档旧 key A
$oldKeyA = Join-Path $ageDir "key-a.txt"
if (Test-Path $oldKeyA) {
    $archiveDir = Join-Path $ageDir "archive-$timestamp"
    New-Item -Path $archiveDir -ItemType Directory -Force | Out-Null
    Move-Item $oldKeyA $archiveDir
    Write-Host "OK old key archived to / 旧钥匙已归档: $archiveDir" -ForegroundColor Green
    Write-Host "   Verify the new flow works before deleting / 验证新流程跑通后再删" -ForegroundColor Yellow
}

# Promote new key to active / 提升新钥匙为当前钥匙
Move-Item $newKeyA $oldKeyA

# Replace public key in .sops.yaml / 替换 .sops.yaml 里的公钥
Write-Host ""
Write-Host "Updating .sops.yaml... / 正在更新 .sops.yaml..." -ForegroundColor Cyan
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$content = [System.IO.File]::ReadAllText((Resolve-Path $sopsConfig), $utf8NoBom)
$currentPub = Select-String -Path $sopsConfig -Pattern 'age1[a-z0-9]+' | Select-Object -First 1 | ForEach-Object { $_.Matches[0].Value }
if ($currentPub) {
    $content = $content -replace $currentPub, $newPub
    [System.IO.File]::WriteAllText((Resolve-Path $sopsConfig), $content, $utf8NoBom)
    Write-Host "OK public key replaced / 公钥已替换" -ForegroundColor Green
}

# Re-encrypt all secrets / 重加密所有 secrets
Write-Host ""
Write-Host "Re-encrypting all secrets... / 正在重加密所有 secrets..." -ForegroundColor Cyan
$secretFiles = Get-ChildItem -Path "secrets" -Include "*.env" -Recurse -File
foreach ($file in $secretFiles) {
    Write-Host "   - $($file.FullName)" -ForegroundColor Gray
    sops updatekeys -y $file.FullName 2>&1 | Out-Null
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Rotation complete / 轮转完成" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Next steps / 下一步：" -ForegroundColor Cyan
Write-Host "    1. Verify / 验证: sops --decrypt secrets/common.env" -ForegroundColor White
Write-Host "    2. Test app / 测试应用: task dev" -ForegroundColor White
Write-Host "    3. Commit / 提交: git add -A && git commit" -ForegroundColor White
Write-Host "    4. Backup new key / 备份新钥匙: task backup:keys" -ForegroundColor White
Write-Host "    5. Delete old key archive AFTER verifying / 验证 OK 后再删旧钥匙归档" -ForegroundColor White
Write-Host ""
