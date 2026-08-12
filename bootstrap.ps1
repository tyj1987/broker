# bootstrap.ps1
# 一键初始化脚本：检查工具 → 生成 age 钥匙 → 加密第一个密钥文件 → git init
# 用法：
#   pwsh -File bootstrap.ps1                # 交互模式
#   pwsh -File bootstrap.ps1 -Auto          # 自动模式（全部 yes，不推荐生产用）

param(
    [switch]$Auto = $false
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

# 交互式确认辅助
function Confirm-Prompt {
    param([string]$Message, [string]$Default = 'Y')
    if ($Auto) { return $true }
    $answer = Read-Host $Message
    if ($answer -eq '') { $answer = $Default }
    return ($answer -match '^[Yy]')
}

# ============================
# 工具函数
# ============================

function Write-Banner {
    param([string]$Text)
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Test-Tool {
    param([string]$Name, [string]$InstallHint)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) {
        $version = & $Name --version 2>$null | Select-Object -First 1
        Write-Host "  ✅ $Name : $version" -ForegroundColor Green
        return $true
    } else {
        Write-Host "  ❌ $Name 未安装" -ForegroundColor Red
        Write-Host "     安装: $InstallHint" -ForegroundColor Yellow
        return $false
    }
}

function Read-AgePublicKey {
    param([string]$KeyFile)
    if (-not (Test-Path $KeyFile)) { return $null }
    $content = Get-Content $KeyFile -Raw
    if ($content -match '# public key: (age1[a-z0-9]+)') {
        return $matches[1]
    }
    return $null
}

# 用 .NET Process 直接调用外部命令，绕开 PowerShell stderr 错误处理
function Invoke-NativeCommand {
    param(
        [string]$FileName,
        [string[]]$Arguments
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FileName
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    foreach ($a in $Arguments) { $psi.ArgumentList.Add($a) }
    $proc = [System.Diagnostics.Process]::Start($psi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    $code = $proc.ExitCode
    $combined = @()
    if ($stdout) { $combined += ($stdout -split "`r?`n") }
    if ($stderr) { $combined += ($stderr -split "`r?`n") }
    return [PSCustomObject]@{
        ExitCode = $code
        Output   = $combined
    }
}

# ============================
# 步骤 1：检查工具
# ============================

Write-Banner "步骤 1/6 · 检查必需工具"

$toolsOk = $true
$toolsOk = (Test-Tool "age"     "scoop install age") -and $toolsOk
$toolsOk = (Test-Tool "sops"    "scoop install sops") -and $toolsOk
$toolsOk = (Test-Tool "git"     "scoop install git") -and $toolsOk
$toolsOk = (Test-Tool "task"    "scoop install go-task") -and $toolsOk

if (-not $toolsOk) {
    Write-Host ""
    Write-Host "❌ 部分工具未安装，请先安装后重试。" -ForegroundColor Red
    Write-Host "   推荐用 scoop 一键装齐：" -ForegroundColor Yellow
    Write-Host "   scoop install age sops git go-task" -ForegroundColor Yellow
    exit 1
}

# ============================
# 步骤 2：创建钥匙目录
# ============================

Write-Banner "步骤 2/6 · 准备 age 钥匙目录"

$ageDir = Join-Path $env:USERPROFILE ".config\sops\age"
if (-not (Test-Path $ageDir)) {
    New-Item -Path $ageDir -ItemType Directory -Force | Out-Null
    Write-Host "  ✅ 已创建 $ageDir" -ForegroundColor Green
} else {
    Write-Host "  ℹ️  目录已存在: $ageDir" -ForegroundColor Gray
}

# ============================
# 步骤 3：主钥匙 A
# ============================

Write-Banner "步骤 3/6 · 主钥匙 A（日常用）"

$keyA = Join-Path $ageDir "key-a.txt"
$pubA = $null

if (Test-Path $keyA) {
    $pubA = Read-AgePublicKey $keyA
    Write-Host "  ℹ️  主钥匙已存在: $keyA" -ForegroundColor Gray
    Write-Host "     公钥: $pubA" -ForegroundColor Gray
} else {
    Write-Host "  🔑 生成主钥匙 A..." -ForegroundColor Cyan
    $result = Invoke-NativeCommand -FileName "age-keygen" -Arguments @("-o", $keyA)
    $result.Output | ForEach-Object { Write-Host "     $_" -ForegroundColor Gray }
    $pubA = Read-AgePublicKey $keyA
    if (-not $pubA) {
        Write-Host "  ❌ 生成失败，请手动检查 age-keygen" -ForegroundColor Red
        exit 1
    }
    Write-Host "  ✅ 主钥匙 A 生成成功" -ForegroundColor Green
    Write-Host "     公钥: $pubA" -ForegroundColor Green
}

# ============================
# 步骤 4：备份钥匙 B
# ============================

Write-Banner "步骤 4/6 · 备份钥匙 B（强烈建议）"

$keyB = Join-Path $ageDir "key-b-backup.txt"
$pubB = $null
$createBackup = $false

if (Test-Path $keyB) {
    $pubB = Read-AgePublicKey $keyB
    Write-Host "  ℹ️  备份钥匙已存在: $keyB" -ForegroundColor Gray
    Write-Host "     公钥: $pubB" -ForegroundColor Gray
} else {
    Write-Host ""
    Write-Host "  ⚠️  备份钥匙的作用：主钥匙丢了，备份钥匙能解所有文件" -ForegroundColor Yellow
    Write-Host "  📍 建议把备份钥匙拷贝到 U 盘、保险柜等独立位置" -ForegroundColor Yellow
    Write-Host ""
    if (Confirm-Prompt "  现在生成备份钥匙 B 吗？[Y/n]") {
        $createBackup = $true
    } else {
        Write-Host "  ⏭️  跳过备份钥匙（不推荐）" -ForegroundColor Yellow
    }
}

if ($createBackup) {
    Write-Host "  🔑 生成备份钥匙 B..." -ForegroundColor Cyan
    $resultB = Invoke-NativeCommand -FileName "age-keygen" -Arguments @("-o", $keyB)
    $resultB.Output | ForEach-Object { Write-Host "     $_" -ForegroundColor Gray }
    $pubB = Read-AgePublicKey $keyB
    if ($pubB) {
        Write-Host "  ✅ 备份钥匙 B 生成成功" -ForegroundColor Green
        Write-Host "     公钥: $pubB" -ForegroundColor Green
        Write-Host ""
        Write-Host "  📋 立即执行以下操作：" -ForegroundColor Yellow
        Write-Host "     1. 把 $keyB 拷贝到 U 盘" -ForegroundColor Yellow
        Write-Host "     2. 把公钥和私钥内容都记到 KeePassXC" -ForegroundColor Yellow
        Write-Host "     3. 验证 U 盘上的钥匙能解开本项目" -ForegroundColor Yellow
    }
}

# ============================
# 步骤 5：替换 .sops.yaml 占位符
# ============================

Write-Banner "步骤 5/6 · 配置 .sops.yaml"

$sopsConfig = ".sops.yaml"
if (-not (Test-Path $sopsConfig)) {
    Write-Host "  ❌ 找不到 $sopsConfig" -ForegroundColor Red
    exit 1
}

# 用 .NET 读写文件，UTF-8 无 BOM（避免 PowerShell 5.1 默认编码损坏内容）
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$content = [System.IO.File]::ReadAllText((Resolve-Path $sopsConfig), $utf8NoBom)
$content = $content -replace '<AGE_PUBLIC_KEY_A>', $pubA

if ($pubB) {
    $content = $content -replace '<AGE_PUBLIC_KEY_B>', $pubB
} else {
    # No B: comment out that line
    $content = $content -replace '(\s*)- "<AGE_PUBLIC_KEY_B>"', '$1# - "<NO_BACKUP_KEY_YET>"'
}

[System.IO.File]::WriteAllText((Resolve-Path $sopsConfig), $content, $utf8NoBom)
Write-Host "  ✅ 已写入主钥匙 A 的公钥" -ForegroundColor Green
if ($pubB) {
    Write-Host "  ✅ 已写入备份钥匙 B 的公钥" -ForegroundColor Green
}

# ============================
# 步骤 6：加密第一个密钥文件
# ============================

Write-Banner "步骤 6/6 · 加密第一个密钥文件"

$exampleFile = "secrets\common.yaml.example"
$secretFile = "secrets\common.yaml"

if (-not (Test-Path $exampleFile)) {
    Write-Host "  ❌ 找不到 $exampleFile" -ForegroundColor Red
    exit 1
}

if (Test-Path $secretFile) {
    Write-Host "  ℹ️  $secretFile 已存在，跳过创建" -ForegroundColor Gray
} else {
    Write-Host "  📝 基于 example 创建 $secretFile..." -ForegroundColor Cyan
    Copy-Item $exampleFile $secretFile
    Write-Host "  🔒 用 SOPS 加密..." -ForegroundColor Cyan
    sops --encrypt --in-place $secretFile
    Write-Host "  ✅ 加密完成" -ForegroundColor Green
    Write-Host ""
    Write-Host "  💡 提示：以后编辑密钥用 'task secrets:edit' 或 'sops secrets\common.yaml'" -ForegroundColor Cyan
}

# ============================
# 收尾：git 初始化
# ============================

Write-Host ""
if (Confirm-Prompt "现在初始化 git 仓库并提交吗？[Y/n]") {
    Write-Host ""
    Write-Host "  📦 初始化 git..." -ForegroundColor Cyan

    # Auto-configure git user if missing (避免 Author identity unknown)
    $userName = git config --global user.name 2>$null
    $userEmail = git config --global user.email 2>$null
    if (-not $userName) {
        $defaultName = if ($env:USERNAME) { $env:USERNAME } else { "Developer" }
        git config --global user.name $defaultName
        Write-Host "     已设 user.name = $defaultName" -ForegroundColor Gray
    }
    if (-not $userEmail) {
        $defaultEmail = "$($env:USERNAME)@localhost"
        git config --global user.email $defaultEmail
        Write-Host "     已设 user.email = $defaultEmail" -ForegroundColor Gray
    }

    if (-not (Test-Path ".git")) {
        git init | Out-Null
    }
    git add -A
    # 临时关闭 PS 5.1 的 stderr 错误处理（git 输出 LF 警告到 stderr）
    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $commitOutput = git commit -m "feat: bootstrap project with SOPS secret management" 2>&1
    } finally {
        $ErrorActionPreference = $prevPref
    }
    $commitOutput | ForEach-Object { Write-Host "     $_" -ForegroundColor Gray }
    $lastCode = $LASTEXITCODE
    if ($lastCode -eq 0) {
        Write-Host "  ✅ 已提交" -ForegroundColor Green
    } else {
        Write-Host "  ⚠️  git commit 返回 $lastCode，请手动检查" -ForegroundColor Yellow
    }
}

# ============================
# 完成
# ============================

Write-Banner "🎉 初始化完成！"

Write-Host "  接下来可以做的：" -ForegroundColor Cyan
Write-Host ""
Write-Host "  1. 验证 direnv（首次进入项目会提示 direnv allow）" -ForegroundColor White
Write-Host "     cd $PWD" -ForegroundColor Gray
Write-Host "     direnv allow" -ForegroundColor Gray
Write-Host "     echo `$env:DATABASE_URL" -ForegroundColor Gray
Write-Host ""
Write-Host "  2. 启动应用看效果" -ForegroundColor White
Write-Host "     task dev" -ForegroundColor Gray
Write-Host ""
Write-Host "  3. 推送到 GitHub" -ForegroundColor White
Write-Host "     git remote add origin https://github.com/you/my-first-app.git" -ForegroundColor Gray
Write-Host "     git push -u origin main" -ForegroundColor Gray
Write-Host ""
Write-Host "  4. 重要：现在就把备份钥匙 B 拷贝到 U 盘" -ForegroundColor Yellow
Write-Host "     主钥匙丢失 + 没有备份 = 所有密钥永久丢失" -ForegroundColor Yellow
Write-Host ""
Write-Host "  详细文档： C:\home\dev-system\README.md" -ForegroundColor Cyan
Write-Host ""
