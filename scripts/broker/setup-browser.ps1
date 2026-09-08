# scripts/broker/setup-browser.ps1
# 让浏览器可以无警告直接访问 Secret Broker dashboard（免安装客户端证书）
#
# 做了什么:
#   1. hosts 添加 127.0.0.1 broker.example.com（解决 SNI/证书 CN 匹配, 需要管理员）
#   2. 导入 broker CA 到当前用户信任库（自签证书免警告）
#   3. 提示启动 SSH 隧道 + 打开 dashboard
#
# 用法:
#   powershell -ExecutionPolicy Bypass -File scripts/broker/setup-browser.ps1
#   若 hosts 写入失败: 用管理员 PowerShell 再运行一次

param(
  [string]$BrokerHostname = 'broker.example.com',
  [int]$LocalPort = 18443,
  [string]$BrokerRemotePort = '8443',
  [string]$SshHost = 'broker-host',
  [string]$CaCertPath = "$env:USERPROFILE\.broker\pki\ca\ca.crt",
  [switch]$SkipHosts,
  [switch]$SkipCa
)

$ErrorActionPreference = 'Stop'

Write-Host '=== Secret Broker 浏览器访问配置 ===' -ForegroundColor Cyan

# ---------- 1. hosts ----------
if (-not $SkipHosts) {
  $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
  $line = "127.0.0.1`t$BrokerHostname"
  try {
    $existing = Select-String -Path $hostsFile -Pattern ("127\.0\.0\.1\s+" + [regex]::Escape($BrokerHostname)) -Quiet
    if ($existing) {
      Write-Host "[1/3] hosts: 条目已存在 -> $line" -ForegroundColor Green
    } else {
      Add-Content -Path $hostsFile -Value "`r`n$line`t# secret-broker dashboard" -Encoding Ascii
      Write-Host "[1/3] hosts: 已添加 -> $line" -ForegroundColor Green
    }
  } catch {
    Write-Host "[1/3] hosts: 写入失败，需要管理员权限。请用管理员 PowerShell 重跑本脚本，或手动添加:" -ForegroundColor Yellow
    Write-Host "      $line" -ForegroundColor Yellow
  }
} else {
  Write-Host '[1/3] hosts: 跳过' -ForegroundColor DarkGray
}

# ---------- 2. CA 信任 ----------
if (-not $SkipCa) {
  if (-not (Test-Path $CaCertPath)) {
    Write-Host "[2/3] CA 证书不存在: $CaCertPath" -ForegroundColor Red
    Write-Host '      请先运行 scripts/broker/install-ecs.sh 或从 ECS 拉取 pki/ca/ca.crt 到本地' -ForegroundColor Yellow
  } else {
    $thumb = (Get-PfxCertificate $CaCertPath).Thumbprint
    $already = Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Thumbprint -eq $thumb }
    if ($already) {
      Write-Host '[2/3] CA: 已在当前用户信任库' -ForegroundColor Green
    } else {
      Import-Certificate -FilePath $CaCertPath -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
      Write-Host '[2/3] CA: 已导入当前用户信任库' -ForegroundColor Green
    }
  }
} else {
  Write-Host '[2/3] CA: 跳过' -ForegroundColor DarkGray
}

# ---------- 3. 隧道 + 打开 ----------
Write-Host '[3/3] 启动 SSH 隧道 (Ctrl-C 停止):' -ForegroundColor Cyan
Write-Host "      ssh -L ${LocalPort}:127.0.0.1:${BrokerRemotePort} $SshHost" -ForegroundColor DarkGray
Write-Host ''
Write-Host "浏览器打开: https://$BrokerHostname`:$LocalPort" -ForegroundColor Green
Write-Host '登录: 客户端名称 client.dashboard-admin + 密码(见 ~/.broker/dashboard-admin-password.txt)' -ForegroundColor DarkGray
Write-Host ''

# 如果隧道没在跑, 拉起来; 已在跑则直接开浏览器
$t = Test-NetConnection -ComputerName 127.0.0.1 -Port $LocalPort -WarningAction SilentlyContinue
if (-not $t.TcpTestSucceeded) {
  Start-Process ssh -ArgumentList '-f','-N','-L',"${LocalPort}:127.0.0.1:${BrokerRemotePort}",$SshHost -WindowStyle Hidden
  Start-Sleep -Seconds 2
  Write-Host 'SSH 隧道已启动' -ForegroundColor Green
} else {
  Write-Host 'SSH 隧道已在运行' -ForegroundColor Green
}

Start-Process "https://$BrokerHostname`:$LocalPort"
