# bootstrap.ps1 / 一键引导脚本
# One-shot project initialization. / 项目一键引导。
# Usage / 用法:
#   pwsh -File bootstrap.ps1          # interactive / 交互模式
#   pwsh -File bootstrap.ps1 -Auto    # non-interactive (all yes) / 自动模式（全部 yes）

[CmdletBinding()]
param(
    [switch]$Auto = $false
)

$ErrorActionPreference = 'Stop'

# ============================
# Console UTF-8 (so Chinese / 中文 不会乱码)
# ============================
try {
    # 切控制台代码页到 UTF-8 (65001)，这样 Get-Content / Write-Host 都不会乱码
    # Switch console code page to UTF-8 (65001) so neither Get-Content nor
    # Write-Host shows mojibake. The chcp is the critical one for PS 5.1;
    # the [Console] settings help pwsh 7+ on Windows.
    cmd /c "chcp 65001 > nul" 2>&1 | Out-Null
    $OutputEncoding = [System.Text.Encoding]::UTF8
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
} catch { }

# ============================
# UTF-8 helpers (avoid PS 5.1 mojibake)
# ============================
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Write-FileUtf8 {
    param([string]$Path, [string]$Content)
    [System.IO.File]::WriteAllText($Path, $Content, $script:Utf8NoBom)
}

function Read-FileUtf8 {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    return [System.IO.File]::ReadAllText($Path, $script:Utf8NoBom)
}

# Run a native exe via .NET Process; never lets PS 5.1's stderr trap fire.
# 用 .NET Process 调外部命令，避开 PS 5.1 的 stderr 误判。
function Invoke-Exe {
    param(
        [Parameter(Mandatory)] [string]$FileName,
        [Parameter(Mandatory)] [string[]]$Arguments
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FileName
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    foreach ($a in $Arguments) { [void]$psi.ArgumentList.Add($a) }
    $proc = [System.Diagnostics.Process]::Start($psi)
    $so = $proc.StandardOutput.ReadToEnd()
    $se = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    return [PSCustomObject]@{
        ExitCode = $proc.ExitCode
        StdOut   = $so
        StdErr   = $se
    }
}

function Confirm-Prompt {
    param([string]$Message, [string]$Default = 'Y')
    if ($Auto) { return $true }
    $a = Read-Host $Message
    if ($a -eq '') { $a = $Default }
    return ($a -match '^[Yy]')
}

function Banner {
    param([string]$Text)
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Read-AgePub {
    param([string]$KeyFile)
    if (-not (Test-Path $KeyFile)) { return $null }
    $c = Read-FileUtf8 $KeyFile
    if ($c -match '# public key: (age1[a-z0-9]+)') { return $matches[1] }
    return $null
}

# ============================
# Step 1: Tool check / 工具检查
# ============================
Banner "Step 1/7 - Check required tools / 检查必需工具"

$toolsOk = $true
foreach ($pair in @(
    @{n='age';h='scoop install age OR winget install FiloSottile.age'},
    @{n='sops';h='scoop install sops OR winget install Mozilla.SOPS'},
    @{n='git';h='scoop install git'},
    @{n='task';h='scoop install go-task OR download from https://github.com/go-task/task/releases'}
)) {
    $cmd = Get-Command $pair.n -ErrorAction SilentlyContinue
    if ($cmd) {
        $v = & $pair.n --version 2>$null | Select-Object -First 1
        Write-Host "  OK $($pair.n): $v" -ForegroundColor Green
    } else {
        Write-Host "  MISSING $($pair.n) / 缺失" -ForegroundColor Red
        Write-Host "     install: $($pair.h)" -ForegroundColor Yellow
        $toolsOk = $false
    }
}

if (-not $toolsOk) {
    Write-Host ""
    Write-Host "Install missing tools and re-run bootstrap. / 装好缺失的工具再跑一次。" -ForegroundColor Red
    exit 1
}

# ============================
# Step 2: Prepare age key dir / 准备 age 钥匙目录
# ============================
Banner "Step 2/7 - Prepare age key directory / 准备 age 钥匙目录"

$ageDir = Join-Path $env:USERPROFILE ".config\sops\age"
if (-not (Test-Path $ageDir)) {
    New-Item -Path $ageDir -ItemType Directory -Force | Out-Null
    Write-Host "  Created $ageDir" -ForegroundColor Green
} else {
    Write-Host "  Exists: $ageDir" -ForegroundColor Gray
}

# Also seed SOPS' default key location to keep things working without SOPS_AGE_KEY_FILE.
# 顺便 seed SOPS 默认钥匙位置，免去设 SOPS_AGE_KEY_FILE。
$sopsDefaultKeyDir = Join-Path $env:APPDATA "sops\age"
if (-not (Test-Path $sopsDefaultKeyDir)) {
    New-Item -Path $sopsDefaultKeyDir -ItemType Directory -Force | Out-Null
}

# ============================
# Step 3: Main key A / 主钥匙 A
# ============================
Banner "Step 3/7 - Main key A (everyday use) / 主钥匙 A（日常用）"

$keyA = Join-Path $ageDir "key-a.txt"
$pubA = $null

if (Test-Path $keyA) {
    $pubA = Read-AgePub $keyA
    Write-Host "  Main key A exists: $keyA" -ForegroundColor Gray
    Write-Host "     public: $pubA" -ForegroundColor Gray
} else {
    Write-Host "  Generating main key A... / 正在生成主钥匙 A..." -ForegroundColor Cyan
    $r = Invoke-Exe -FileName "age-keygen" -Arguments @("-o", $keyA)
    Write-Host "     $($r.StdOut.Trim())" -ForegroundColor Gray
    $pubA = Read-AgePub $keyA
    if (-not $pubA) {
        Write-Host "  Failed to generate key A / 生成失败" -ForegroundColor Red
        exit 1
    }
    Write-Host "  Main key A generated / 主钥匙 A 已生成" -ForegroundColor Green
    Write-Host "     public: $pubA" -ForegroundColor Green
}

# Mirror key A to SOPS default location (avoids needing SOPS_AGE_KEY_FILE env var)
# 把 key A 同步到 SOPS 默认位置（不用设 SOPS_AGE_KEY_FILE 环境变量）
Copy-Item $keyA (Join-Path $sopsDefaultKeyDir "keys.txt") -Force

# ============================
# Step 4: Backup key B / 备份钥匙 B
# ============================
Banner "Step 4/7 - Backup key B (strongly recommended) / 备份钥匙 B（强烈建议）"

$keyB = Join-Path $ageDir "key-b-backup.txt"
$pubB = $null
$createBackup = $false

if (Test-Path $keyB) {
    $pubB = Read-AgePub $keyB
    Write-Host "  Backup key B exists: $keyB" -ForegroundColor Gray
    Write-Host "     public: $pubB" -ForegroundColor Gray
} else {
    Write-Host ""
    Write-Host "  Backup key unlocks all secrets if main key A is lost." -ForegroundColor Yellow
    Write-Host "  备份钥匙的作用：主钥匙 A 丢了也能解所有文件。" -ForegroundColor Yellow
    Write-Host "  Recommended: copy to USB drive, safety deposit box, etc." -ForegroundColor Yellow
    Write-Host "  建议：拷到 U 盘、保险柜等独立物理位置。" -ForegroundColor Yellow
    Write-Host ""
    $createBackup = Confirm-Prompt "  Generate backup key B now? [Y/n] / 现在生成备份钥匙 B 吗？"
}

if ($createBackup) {
    Write-Host "  Generating backup key B... / 正在生成备份钥匙 B..." -ForegroundColor Cyan
    $r = Invoke-Exe -FileName "age-keygen" -Arguments @("-o", $keyB)
    Write-Host "     $($r.StdOut.Trim())" -ForegroundColor Gray
    $pubB = Read-AgePub $keyB
    if ($pubB) {
        Write-Host "  Backup key B generated / 备份钥匙 B 已生成" -ForegroundColor Green
        Write-Host "     public: $pubB" -ForegroundColor Green
        Write-Host ""
        Write-Host "  IMMEDIATELY do these / 立刻做：" -ForegroundColor Yellow
        Write-Host "     1. Copy $keyB to a USB drive / 拷到 U 盘" -ForegroundColor Yellow
        Write-Host "     2. Record the public key in your password manager / 公钥记到密码管理器" -ForegroundColor Yellow
    }
}

# ============================
# Step 5: Configure .sops.yaml / 配置 .sops.yaml
# ============================
Banner "Step 5/7 - Configure .sops.yaml / 配置 .sops.yaml"

$sopsConfigPath = Join-Path (Get-Location) ".sops.yaml"
if (-not (Test-Path $sopsConfigPath)) {
    Write-Host "  Missing .sops.yaml" -ForegroundColor Red
    exit 1
}

# Always rewrite with the canonical pattern (idempotent).
# 永远用规范模式重写（幂等）。
$pubBLine = if ($pubB) { "          - `"$pubB`"" } else { "          # - `"<NO_BACKUP_KEY_YET>`"" }

$sopsContent = @"
# .sops.yaml
# SOPS encryption rules. Public keys are filled in by bootstrap.ps1.
# SOPS 加密规则。公钥由 bootstrap.ps1 自动填入。
# Docs / 文档: https://github.com/getsops/sops
#
# Note: sops 3.7.x on Windows matches path_regex against the FULL path with
# Go regexp. We use filename-only patterns for portability.
# 注意：sops 3.7.x 在 Windows 下用 Go 正则匹配完整路径，
# 这里用纯文件名模式方便 Windows / Linux 通用。

creation_rules:
  - path_regex: .*common\.env$
    key_groups:
      - age:
          - "$pubA"
$pubBLine

  - path_regex: .*dev\.env$
    key_groups:
      - age:
          - "$pubA"
$pubBLine

  - path_regex: .*prod\.env$
    key_groups:
      - age:
          - "$pubA"
      # For production-grade, replace local key above with cloud KMS:
      # 生产环境推荐改成只允许云 KMS 解密（把上面 A 那行删掉）：
      # - alibabakms:
      #     - xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
      # - tencentkms:
      #     - alias/your-key-alias
"@

Write-FileUtf8 -Path $sopsConfigPath -Content $sopsContent
Write-Host "  .sops.yaml updated / 已更新" -ForegroundColor Green
if ($pubB) { Write-Host "  Backup key B included / 已包含备份钥匙 B" -ForegroundColor Green } else { Write-Host "  Backup key B skipped (single-key risk) / 跳过备份（单钥匙风险）" -ForegroundColor Yellow }

# ============================
# Step 6: Encrypt first secret file / 加密第一个密钥文件
# ============================
Banner "Step 6/7 - Encrypt the first secret file / 加密第一个密钥文件"

$exampleFile = Join-Path (Get-Location) "secrets\common.env.example"
$secretFile = Join-Path (Get-Location) "secrets\common.env"

if (-not (Test-Path $exampleFile)) {
    Write-Host "  Missing $exampleFile" -ForegroundColor Red
    exit 1
}

if (Test-Path $secretFile) {
    Write-Host "  $secretFile already exists, skipping creation / 已存在，跳过" -ForegroundColor Gray
} else {
    Write-Host "  Copying example to $secretFile... / 复制 example..." -ForegroundColor Cyan
    $exampleContent = Read-FileUtf8 $exampleFile
    Write-FileUtf8 -Path $secretFile -Content $exampleContent
    Write-Host "  Encrypting... / 正在加密..." -ForegroundColor Cyan
    $r = Invoke-Exe -FileName "sops" -Arguments @("--encrypt", "--in-place", $secretFile)
    if ($r.ExitCode -ne 0) {
        Write-Host "  sops failed: $($r.StdErr) / 加密失败" -ForegroundColor Red
        exit 1
    }
    Write-Host "  Encrypted successfully / 加密完成" -ForegroundColor Green
}

# ============================
# Step 7: Init git / 初始化 git
# ============================
Banner "Step 7/7 - Initialize git / 初始化 git"

if (Confirm-Prompt "Initialize git repo and commit? [Y/n] / 初始化 git 仓库并提交？") {
    $userName = git config --global user.name 2>$null
    $userEmail = git config --global user.email 2>$null
    if (-not $userName) {
        $defaultName = if ($env:USERNAME) { $env:USERNAME } else { "Developer" }
        git config --global user.name $defaultName
        Write-Host "  set user.name = $defaultName" -ForegroundColor Gray
    }
    if (-not $userEmail) {
        $defaultEmail = "$($env:USERNAME)@localhost"
        git config --global user.email $defaultEmail
        Write-Host "  set user.email = $defaultEmail" -ForegroundColor Gray
    }

    if (-not (Test-Path ".git")) {
        git init | Out-Null
    }
    git add -A

    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $commitOut = git commit -m "feat: bootstrap project with SOPS secret management" 2>&1
    } finally {
        $ErrorActionPreference = $prevPref
    }
    $commitOut | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Committed / 已提交" -ForegroundColor Green
    } else {
        Write-Host "  git commit returned $LASTEXITCODE (manual check needed) / 返回非 0，需手动检查" -ForegroundColor Yellow
    }
}

# ============================
# Done / 完成
# ============================
Banner "Bootstrap complete / 引导完成"

Write-Host "  Next steps / 接下来：" -ForegroundColor Cyan
Write-Host ""
Write-Host "  1. Copy backup key B to a USB drive (if not already done) / 把备份钥匙 B 拷到 U 盘" -ForegroundColor White
Write-Host ""
Write-Host "  2. Start the dev environment / 启动开发环境：" -ForegroundColor White
Write-Host "     task dev" -ForegroundColor Gray
Write-Host ""
Write-Host "  3. Edit encrypted secrets anytime / 随时编辑加密密钥：" -ForegroundColor White
Write-Host "     sops secrets\common.env" -ForegroundColor Gray
Write-Host ""
Write-Host "  4. Push to GitHub / 推送到 GitHub：" -ForegroundColor White
Write-Host "     git remote add origin https://github.com/you/my-first-app.git" -ForegroundColor Gray
Write-Host "     git push -u origin main" -ForegroundColor Gray
Write-Host ""
Write-Host "  5. Restart PowerShell so new tools are in PATH / 重启 PowerShell 让新工具进 PATH" -ForegroundColor White
Write-Host ""
Write-Host "  System docs / 系统文档: C:\home\dev-system\README.md" -ForegroundColor Cyan
Write-Host ""
