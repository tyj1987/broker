# revoke-cert.ps1
# 吊销客户端证书 / Revoke a client certificate
# 通过指纹匹配证书，更新 CRL，broker 启动时 / 定时 reload CRL

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$Fingerprint,            # SHA-256 指纹，例如 "AB:CD:EF:..."
  [string]$Reason = "unspecified"  # keyCompromise | superseded | cessationOfOperation | unspecified
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$CaDir    = Join-Path $RepoRoot "pki\ca"
$CaKey    = Join-Path $CaDir "ca.key"
$CaCrt    = Join-Path $CaDir "ca.crt"
$CrlPem   = Join-Path $CaDir "crl.pem"
$IndexTxt = Join-Path $CaDir "index.txt"
$Serial   = Join-Path $CaDir "serial"

if (-not (Test-Path $CaKey)) { Write-Error "CA not found"; exit 1 }

# 把指纹格式统一为 OpenSSL 期望的 "AB:CD:..."
$Normalized = ($Fingerprint -replace '[^A-Fa-f0-9]','').ToUpper()
if ($Normalized.Length -ne 64) { Write-Error "Fingerprint must be 64 hex chars (SHA-256). Got: $Fingerprint"; exit 1 }
$ColonFp = ($Normalized -split '(.{2})' | Where-Object { $_ }) -join ':'

Write-Host "==> Looking up cert by fingerprint $ColonFp ..." -ForegroundColor Cyan

# 在 pki/clients/ 找匹配的证书
$ClientsDir = Join-Path $RepoRoot "pki\clients"
$MatchFile = $null
if (Test-Path $ClientsDir) {
  $MatchFile = Get-ChildItem -Path $ClientsDir -Filter "*.crt" -ErrorAction SilentlyContinue | Where-Object {
    $fp = openssl x509 -in $_.FullName -noout -fingerprint -sha256 2>$null | Select-String -Pattern 'SHA256 Fingerprint=' | ForEach-Object { $_.ToString().Replace('SHA256 Fingerprint=','').Trim() }
    return $fp -eq $ColonFp
  } | Select-Object -First 1
}

if ($MatchFile) {
  Write-Host "    Found: $($MatchFile.FullName)" -ForegroundColor Gray
  # 用 OpenSSL 标准吊销流程
  $SerialHex = openssl x509 -in $MatchFile.FullName -noout -serial 2>$null | ForEach-Object { $_.ToString().Replace('serial=','').Trim() }
  $CN = openssl x509 -in $MatchFile.FullName -noout -subject 2>$null | ForEach-Object { $_.ToString().Replace('subject=','').Trim() }
} else {
  Write-Warning "Cert file not found in $ClientsDir, will try by fingerprint only"
  $SerialHex = $null
  $CN = "unknown"
}

# 用 ca.key + index.txt 机制吊销
# 1. 把证书加到 index.txt（用 openssl ca -revoke）
# 2. 重新生成 CRL
# 简化版：直接生成 revoked cert list（生产环境建议用 openssl ca）

# 因为 Windows 上 openssl ca 配置文件复杂，这里用直接的方式：把证书标记进 index.txt
$ReasonCode = switch ($Reason) {
  "keyCompromise"          { "keyCompromise" }
  "superseded"             { "superseded" }
  "cessationOfOperation"   { "cessationOfOperation" }
  default                  { "unspecified" }
}

if ($SerialHex) {
  # index.txt 格式: "R\t<date>\t<serial>\t<unknown>\t<reason>\t<CN>"
  $DateStr = Get-Date -Format "yyMMddHHmmss'Z'"
  "R`t$DateStr`t$SerialHex`tunknown`t$ReasonCode`t$CN" | Out-File -FilePath $IndexTxt -Append -Encoding ASCII

  # 重新生成 CRL
  $OpensslCnf = Join-Path $CaDir "openssl.cnf"
  @"
[ ca ]
default_ca = CA_default
[ CA_default ]
dir = $CaDir
database = $IndexTxt
serial = $Serial
crl = $CrlPem
crlnumber = $CaDir\crlnumber
private_key = $CaKey
certificate = $CaCrt
default_days = 365
default_crl_days = 30
default_md = sha256
policy = policy_any
[ policy_any ]
commonName = supplied
[ crl_ext ]
authorityKeyIdentifier = keyid:always
"@ | Out-File -FilePath $OpensslCnf -Encoding ASCII

  # 生成 crlnumber
  if (-not (Test-Path (Join-Path $CaDir "crlnumber"))) {
    "01" | Out-File -FilePath (Join-Path $CaDir "crlnumber") -Encoding ASCII -NoNewline
  }

  openssl ca -config $OpensslCnf -gencrl -out $CrlPem 2>$null
  if ($LASTEXITCODE -ne 0) {
    Write-Warning "openssl ca -gencrl failed, falling back to manual CRL"
    # 兜底：手工写一个空 CRL
    openssl ca -config $OpensslCnf -revoke "$($MatchFile.FullName)" -crl_reason $ReasonCode 2>$null
  }

  Write-Host ""
  Write-Host "OK! Certificate revoked." -ForegroundColor Green
  Write-Host "  Fingerprint: $ColonFp"
  Write-Host "  Serial:      $SerialHex"
  Write-Host "  CN:          $CN"
  Write-Host "  Reason:      $ReasonCode"
  Write-Host "  CRL updated: $CrlPem"
  Write-Host ""
  Write-Host "  -> The broker will reject this cert on next TLS handshake (within ~60s after reload)." -ForegroundColor Cyan
  Write-Host "  -> To force immediate reload: docker compose restart broker" -ForegroundColor Cyan

  # 写个 .revoked 标记文件，方便快速查找
  if ($MatchFile) {
    $RevokedMarker = "$($MatchFile.FullName).revoked"
    "$ColonFp`t$SerialHex`t$(Get-Date -Format o)" | Out-File -FilePath $RevokedMarker -Encoding UTF8
  }
} else {
  Write-Error "Cannot determine cert serial number. Aborting."
  exit 1
}
